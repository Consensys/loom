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
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/hash"
	internalmerkle "github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/recursion/gadgets/merkle"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

// makeRandomLeafPairs returns nLeaves deterministic (LeafP, LeafQ) ext
// pairs and their HashLeaf digests.
func makeRandomLeafPairs(nLeaves int) (pairs [][2]ext.E6, digests []hash.Digest) {
	pairs = make([][2]ext.E6, nLeaves)
	digests = make([]hash.Digest, nLeaves)
	h := commitment.Poseidon2LeafHasher{}
	for i := range pairs {
		var P, Q ext.E6
		P.B0.A0.SetUint64(uint64(i*1000 + 1))
		P.B0.A1.SetUint64(uint64(i*1000 + 2))
		P.B1.A0.SetUint64(uint64(i*1000 + 3))
		P.B1.A1.SetUint64(uint64(i*1000 + 4))
		Q.B0.A0.SetUint64(uint64(i*1000 + 5))
		Q.B0.A1.SetUint64(uint64(i*1000 + 6))
		Q.B1.A0.SetUint64(uint64(i*1000 + 7))
		Q.B1.A1.SetUint64(uint64(i*1000 + 8))
		pairs[i] = [2]ext.E6{P, Q}
		digests[i] = h.HashLeaf(nil, []commitment.PairExt{{P, Q}})
	}
	return
}

// buildNativePath builds a native Merkle tree over the given leaf digests
// and returns the path proof for leafIdx.
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
	pairs, digests := makeRandomLeafPairs(nLeaves)
	root, nativeProof := buildNativePath(t, digests, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		LeafP:    pairs[leafIdx][0],
		LeafQ:    pairs[leafIdx][1],
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
	pairs, digests := makeRandomLeafPairs(nLeaves)
	_, nativeProof := buildNativePath(t, digests, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk_bit", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		LeafP:    pairs[leafIdx][0],
		LeafQ:    pairs[leafIdx][1],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

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
// leaving the nodehash sub-columns honest. The hash-equality constraint
// catches the mismatch.
func TestMerkleGadgetRejectsForgedParent(t *testing.T) {
	const nLeaves = 8
	const leafIdx = 2
	pairs, digests := makeRandomLeafPairs(nLeaves)
	_, nativeProof := buildNativePath(t, digests, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk_forge", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		LeafP:    pairs[leafIdx][0],
		LeafQ:    pairs[leafIdx][1],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

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
	pairs, digests := makeRandomLeafPairs(nLeaves)
	_, nativeProof := buildNativePath(t, digests, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk_chain", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		LeafP:    pairs[leafIdx][0],
		LeafQ:    pairs[leafIdx][1],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

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

// TestMerkleGadgetRejectsBadLeafP tampers with LeafP[0] at row 0. The
// leafhash sub-trace still computes a valid digest from the tampered
// LeafP, but that digest no longer matches the path's root (which was
// built from the honest leaf). The leafhash equality constraint at row 0
// catches the mismatch indirectly via the chain reaching the wrong root.
//
// To make the failure local and unambiguous, we tamper with LeafP at row
// 0 in the trace WITHOUT regenerating the sponge sub-columns: that breaks
// the leafhash gadget's own input-equality constraint (sponge.In[3..6] =
// LeafP limbs) — caught immediately.
func TestMerkleGadgetRejectsBadLeafP(t *testing.T) {
	const nLeaves = 8
	const leafIdx = 1
	pairs, digests := makeRandomLeafPairs(nLeaves)
	_, nativeProof := buildNativePath(t, digests, leafIdx)

	builder := board.NewBuilder()
	cn := merkle.BuildModule(&builder, "merk_leaf", len(nativeProof.Siblings))

	cols := merkle.GenerateTrace(cn, len(nativeProof.Siblings), merkle.Path{
		LeafP:    pairs[leafIdx][0],
		LeafQ:    pairs[leafIdx][1],
		LeafIdx:  leafIdx,
		Siblings: nativeProof.Siblings,
	})

	leafP0 := cols[cn.LeafP[0]]
	var one koalabear.Element
	one.SetOne()
	leafP0[0].Add(&leafP0[0], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
