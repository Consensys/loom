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

package merkle_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/hash"
	internalmerkle "github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/recursion/gadgets/merkle"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

// makeRandomDigests returns nLeaves deterministic-but-arbitrary digests.
func makeRandomDigests(nLeaves int) []hash.Digest {
	leaves := make([]hash.Digest, nLeaves)
	for i := range leaves {
		for j := 0; j < hash.DIGEST_NB_ELEMENTS; j++ {
			leaves[i][j].SetUint64(uint64(i*100 + j + 1))
		}
	}
	return leaves
}

// buildNativePath builds a native Merkle tree over the given leaves and
// returns the path proof for leafIdx.
func buildNativePath(t *testing.T, leaves []hash.Digest, leafIdx int) (hash.Digest, internalmerkle.Proof) {
	t.Helper()
	tree, err := internalmerkle.New(len(leaves), commitment.Poseidon2NodeHasher{})
	if err != nil {
		t.Fatalf("merkle.New: %v", err)
	}
	if err := tree.Build(leaves); err != nil {
		t.Fatalf("tree.Build: %v", err)
	}
	proof, err := tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatalf("tree.OpenProof: %v", err)
	}
	return tree.Root(), proof
}

func TestMerkleGadgetDepth8(t *testing.T) {
	const nLeaves = 256
	const leafIdx = 42
	leaves := makeRandomDigests(nLeaves)
	root, nativeProof := buildNativePath(t, leaves, leafIdx)
	_ = root // root binding is left for a follow-up milestone.

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		Leaf:     leaves[leafIdx],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}

	// Last-row parent equals the native root.
	for i := 0; i < merkle.DigestWidth; i++ {
		col := cols[cn.Parent[i]]
		got := col[len(col)-1]
		if !got.Equal(&root[i]) {
			t.Fatalf("parent[%d] at root row = %s, want %s", i, got.String(), root[i].String())
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestMerkleGadgetRejectsCorruptedBit confirms that flipping the direction
// bit on a step breaks the bit-selector constraints (left/right derivation).
func TestMerkleGadgetRejectsCorruptedBit(t *testing.T) {
	const nLeaves = 8
	const leafIdx = 3
	leaves := makeRandomDigests(nLeaves)
	_, nativeProof := buildNativePath(t, leaves, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		Leaf:     leaves[leafIdx],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

	// Flip the bit at row 0 (the leaf step).
	bit := cols[cn.Bit]
	if bit[0].IsZero() {
		bit[0].SetOne()
	} else {
		bit[0].SetZero()
	}

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestMerkleGadgetRejectsForgedParent flips parent[0] at row 0 while
// leaving the nodehash sub-columns honest. The new in-circuit hash-
// equality constraint should catch the inconsistency between the parent
// column and nodehash.Digest.
func TestMerkleGadgetRejectsForgedParent(t *testing.T) {
	const nLeaves = 8
	const leafIdx = 2
	leaves := makeRandomDigests(nLeaves)
	_, nativeProof := buildNativePath(t, leaves, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk_forge", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		Leaf:     leaves[leafIdx],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

	// Flip parent[0] at row 0. nodehash.Digest[0] still holds the true
	// hash output, so the parent == nodehash.Digest equality constraint
	// now fails. (Even if chaining might still be satisfied at row 1 if
	// we also corrupted current there — which we don't — the per-row
	// hash-equality constraint catches this immediately.)
	col := cols[cn.Parent[0]]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestMerkleGadgetRejectsBrokenChaining tampers with the current[*] column at
// row 1 (which is constrained to equal row 0's parent[*]).
func TestMerkleGadgetRejectsBrokenChaining(t *testing.T) {
	const nLeaves = 8
	const leafIdx = 0
	leaves := makeRandomDigests(nLeaves)
	_, nativeProof := buildNativePath(t, leaves, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		Leaf:     leaves[leafIdx],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

	// Corrupt current[0] at row 1.
	cur := cols[cn.Current[0]]
	var one koalabear.Element
	one.SetOne()
	cur[1].Add(&cur[1], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
