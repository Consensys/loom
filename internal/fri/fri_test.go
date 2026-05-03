// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fri_test

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/merkle"
)

func freshTS() *fiatshamir.Transcript {
	return fiatshamir.NewTranscript(sha256.New())
}

func randomPoly(n int) []koalabear.Element {
	elems := make([]koalabear.Element, n)
	for i := range elems {
		elems[i].SetRandom()
	}
	return elems
}

// buildRoot re-derives root0 by building the same paired Merkle tree as Prove does:
// nLeaves = N/2, leaf k = LeafHasher(encode(layer[k]) || encode(layer[k+N/2])).
func buildRoot(t *testing.T, layer []koalabear.Element) []byte {
	t.Helper()
	half := len(layer) / 2
	tree, err := merkle.New(half, commitment.LeafHash, commitment.NodeHash)
	if err != nil {
		t.Fatalf("merkle.New: %v", err)
	}
	leaves := make([][]byte, half)
	for k := 0; k < half; k++ {
		leaves[k] = append(layer[k].Marshal(), layer[k+half].Marshal()...)
	}
	if err := tree.Build(leaves); err != nil {
		t.Fatalf("tree.Build: %v", err)
	}
	return tree.Root()
}

func testParams(t *testing.T, N, D, queries int) fri.Params {
	t.Helper()
	p, err := fri.NewParams(N, D, queries, commitment.LeafHash, commitment.NodeHash)
	if err != nil {
		t.Fatalf("NewParams(%d,%d,%d): %v", N, D, queries, err)
	}
	return p
}

// TestProveVerify runs prove+verify for several (N, D, Q) parameter sets.
func TestProveVerify(t *testing.T) {
	cases := []struct{ N, D, Q int }{
		{16, 2, 1},
		{16, 4, 2},
		{64, 4, 4},
		{64, 8, 3},
		{256, 16, 5},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("N%d_D%d_Q%d", tc.N, tc.D, tc.Q), func(t *testing.T) {
			p := testParams(t, tc.N, tc.D, tc.Q)

			poly := randomPoly(tc.D)
			evals, err := p.Encode(poly)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			tsP := freshTS()
			prf, err := fri.Prove(p, evals, tsP)
			if err != nil {
				t.Fatalf("Prove: %v", err)
			}

			root0 := buildRoot(t, evals)

			tsV := freshTS()
			if err := fri.Verify(p, root0, prf, tsV); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestVerifyRejectsWrongRoot ensures Verify fails when root0 doesn't match the proof.
func TestVerifyRejectsWrongRoot(t *testing.T) {
	p := testParams(t, 64, 4, 4)
	evals, _ := p.Encode(randomPoly(p.D))

	tsP := freshTS()
	prf, _ := fri.Prove(p, evals, tsP)

	badRoot := make([]byte, 32)
	rand.Read(badRoot) //nolint:gosec

	tsV := freshTS()
	if err := fri.Verify(p, badRoot, prf, tsV); err == nil {
		t.Fatal("Verify accepted a proof with a wrong root0")
	}
}

// TestVerifyRejectsFlippedLeaf corrupts one leaf in a QueryLayer and expects rejection.
func TestVerifyRejectsFlippedLeaf(t *testing.T) {
	p := testParams(t, 64, 4, 4)
	evals, _ := p.Encode(randomPoly(p.D))
	root0 := buildRoot(t, evals)

	tsP := freshTS()
	prf, err := fri.Prove(p, evals, tsP)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Flip the first leaf of the first query, first layer.
	prf.Queries[0].Layers[0].LeafP.SetRandom()

	tsV := freshTS()
	if err := fri.Verify(p, root0, prf, tsV); err == nil {
		t.Fatal("Verify accepted a proof with a corrupted leaf")
	}
}
