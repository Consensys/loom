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
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
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

func randomExtPoly(n int) []ext.E4 {
	elems := make([]ext.E4, n)
	for i := range elems {
		elems[i].MustSetRandom()
	}
	return elems
}

// buildLevelTree builds the paired-leaf Merkle tree expected by FRI for a
// single-poly level (helper around p.BuildLevelTree).
func buildLevelTree(t *testing.T, p fri.Params, layer []koalabear.Element) *merkle.Tree {
	t.Helper()
	tree, err := p.BuildLevelTree(layer)
	if err != nil {
		t.Fatalf("BuildLevelTree: %v", err)
	}
	return tree
}

func buildLevelTreeExt(t *testing.T, p fri.Params, layer []ext.E4) *merkle.Tree {
	t.Helper()
	tree, err := p.BuildLevelTreeExt(layer)
	if err != nil {
		t.Fatalf("BuildLevelTreeExt: %v", err)
	}
	return tree
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

			tree := buildLevelTree(t, p, evals)
			tsP := freshTS()
			prf, _, err := fri.Prove(p, []fri.Level{{
				D:     p.D,
				Evals: fri.LevelEvals{Base: [][]koalabear.Element{evals}},
				Trees: []*merkle.Tree{tree},
			}}, tsP)
			if err != nil {
				t.Fatalf("Prove: %v", err)
			}

			tsV := freshTS()
			if err := fri.Verify(p, [][][]byte{{tree.Root()}}, []int{p.D}, prf, tsV); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestProveVerifyExtRail(t *testing.T) {
	p := testParams(t, 64, 4, 4)

	poly := randomExtPoly(p.D)
	evals, err := p.EncodeExt(poly)
	if err != nil {
		t.Fatalf("EncodeExt: %v", err)
	}

	tree := buildLevelTreeExt(t, p, evals)
	tsP := freshTS()
	prf, _, err := fri.Prove(p, []fri.Level{{
		D:     p.D,
		Evals: fri.LevelEvals{Ext: [][]ext.E4{evals}},
		Trees: []*merkle.Tree{tree},
	}}, tsP)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	tsV := freshTS()
	if err := fri.Verify(p, [][][]byte{{tree.Root()}}, []int{p.D}, prf, tsV); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifyRejectsWrongRoot ensures Verify fails when root0 doesn't match the proof.
func TestVerifyRejectsWrongRoot(t *testing.T) {
	p := testParams(t, 64, 4, 4)
	evals, _ := p.Encode(randomPoly(p.D))

	tree := buildLevelTree(t, p, evals)
	tsP := freshTS()
	prf, _, _ := fri.Prove(p, []fri.Level{{
		D:     p.D,
		Evals: fri.LevelEvals{Base: [][]koalabear.Element{evals}},
		Trees: []*merkle.Tree{tree},
	}}, tsP)

	badRoot := make([]byte, 32)
	rand.Read(badRoot) //nolint:gosec

	tsV := freshTS()
	if err := fri.Verify(p, [][][]byte{{badRoot}}, []int{p.D}, prf, tsV); err == nil {
		t.Fatal("Verify accepted a proof with a wrong root0")
	}
}

// TestVerifyRejectsFlippedLeaf corrupts one leaf in a QueryLayer and expects rejection.
func TestVerifyRejectsFlippedLeaf(t *testing.T) {
	p := testParams(t, 64, 4, 4)
	evals, _ := p.Encode(randomPoly(p.D))
	tree := buildLevelTree(t, p, evals)

	tsP := freshTS()
	prf, _, err := fri.Prove(p, []fri.Level{{
		D:     p.D,
		Evals: fri.LevelEvals{Base: [][]koalabear.Element{evals}},
		Trees: []*merkle.Tree{tree},
	}}, tsP)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Flip the first leaf of the first query, first layer.
	prf.FRIQueries[0].Layers[0].LeafPBase.SetRandom()

	tsV := freshTS()
	if err := fri.Verify(p, [][][]byte{{tree.Root()}}, []int{p.D}, prf, tsV); err == nil {
		t.Fatal("Verify accepted a proof with a corrupted leaf")
	}
}

func TestVerifyRejectsFlippedExtLeaf(t *testing.T) {
	p := testParams(t, 64, 4, 4)
	evals, _ := p.EncodeExt(randomExtPoly(p.D))
	tree := buildLevelTreeExt(t, p, evals)

	tsP := freshTS()
	prf, _, err := fri.Prove(p, []fri.Level{{
		D:     p.D,
		Evals: fri.LevelEvals{Ext: [][]ext.E4{evals}},
		Trees: []*merkle.Tree{tree},
	}}, tsP)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	prf.FRIQueries[0].Layers[0].LeafPExt.MustSetRandom()

	tsV := freshTS()
	if err := fri.Verify(p, [][][]byte{{tree.Root()}}, []int{p.D}, prf, tsV); err == nil {
		t.Fatal("Verify accepted a proof with a corrupted ext leaf")
	}
}
