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

package commitment

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
)

func TestRSCommitDualRailProof(t *testing.T) {
	basePolys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
		{baseElement(5), baseElement(6), baseElement(7), baseElement(8)},
	}
	extPolys := []poly.ExtPolynomial{
		{
			extElement(1, 2, 3, 4),
			extElement(5, 6, 7, 8),
			extElement(9, 10, 11, 12),
			extElement(13, 14, 15, 16),
		},
	}

	committer := NewRSCommit(4, 2, DefaultLeafHasher, DefaultNodeHasher)
	tree, err := committer.Commit(basePolys, extPolys)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree.NumLeaves(); got != 4 {
		t.Fatalf("NumLeaves = %d, want 4", got)
	}
	if got := tree.BaseWidth(); got != len(basePolys) {
		t.Fatalf("base rail width = %d, want %d", got, len(basePolys))
	}
	if got := tree.ExtWidth(); got != len(extPolys) {
		t.Fatalf("ext rail width = %d, want %d", got, len(extPolys))
	}

	const leafIdx = 1
	proof, err := tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatal(err)
	}
	baseLeaf, extLeaf := rawLeafFromPolys(committer, basePolys, extPolys, leafIdx)
	leaf := DefaultLeafHasher.HashLeaf(baseLeaf, extLeaf)
	if !merkle.Verify(tree.Root(), proof, leaf, DefaultNodeHasher) {
		t.Fatal("dual-rail Merkle proof did not verify")
	}
}

func TestWMerkleTreeOpenProof(t *testing.T) {
	basePolys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
		{baseElement(5), baseElement(6), baseElement(7), baseElement(8)},
	}
	extPolys := []poly.ExtPolynomial{
		{
			extElement(1, 2, 3, 4),
			extElement(5, 6, 7, 8),
			extElement(9, 10, 11, 12),
			extElement(13, 14, 15, 16),
		},
	}

	committer := NewRSCommit(4, 2, DefaultLeafHasher, DefaultNodeHasher)
	tree, err := committer.Commit(basePolys, extPolys)
	if err != nil {
		t.Fatal(err)
	}

	const leafIdx = 2
	proof, err := tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatal(err)
	}

	baseLeaf, extLeaf := rawLeafFromPolys(committer, basePolys, extPolys, leafIdx)
	leaf := DefaultLeafHasher.HashLeaf(baseLeaf, extLeaf)
	if !merkle.Verify(tree.Root(), proof, leaf, DefaultNodeHasher) {
		t.Fatal("opened Merkle proof did not verify")
	}
}

func TestRSCommitWithDomainCache(t *testing.T) {
	basePolys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
		{baseElement(5), baseElement(6), baseElement(7), baseElement(8)},
	}

	var cache poly.DomainCache
	committer := NewRSCommitWithDomainCache(4, 2, DefaultLeafHasher, DefaultNodeHasher, &cache)
	tree, err := committer.Commit(basePolys, nil, WithDomainCache(&cache))
	if err != nil {
		t.Fatal(err)
	}
	if got := tree.NumLeaves(); got != 4 {
		t.Fatalf("NumLeaves = %d, want 4", got)
	}
	if got := cache.Get(4); got != cache.Get(4) {
		t.Fatalf("DomainCache did not reuse input domain: %p vs %p", got, cache.Get(4))
	}
}

func TestRSCommitEmptyRails(t *testing.T) {
	basePolys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
	}
	committer := NewRSCommit(4, 2, DefaultLeafHasher, DefaultNodeHasher)
	baseTree, err := committer.Commit(basePolys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := baseTree.ExtWidth(); got != 0 {
		t.Fatalf("base-only tree ext rail width = %d, want 0", got)
	}

	extPolys := []poly.ExtPolynomial{
		{
			extElement(1, 2, 3, 4),
			extElement(5, 6, 7, 8),
			extElement(9, 10, 11, 12),
			extElement(13, 14, 15, 16),
		},
	}
	extTree, err := committer.Commit(nil, extPolys)
	if err != nil {
		t.Fatal(err)
	}
	if got := extTree.BaseWidth(); got != 0 {
		t.Fatalf("ext-only tree base rail width = %d, want 0", got)
	}
	if got := extTree.NumLeaves(); got != 4 {
		t.Fatalf("ext-only NumLeaves = %d, want 4", got)
	}
}

func baseElement(v uint64) koalabear.Element {
	var e koalabear.Element
	e.SetUint64(v)
	return e
}

func extElement(a0, a1, b0, b1 uint64) ext.E4 {
	var e ext.E4
	e.B0.A0.SetUint64(a0)
	e.B0.A1.SetUint64(a1)
	e.B1.A0.SetUint64(b0)
	e.B1.A1.SetUint64(b1)
	return e
}

func rawLeafFromPolys(committer RSCommit, basePolys []poly.Polynomial, extPolys []poly.ExtPolynomial, leafIdx int) ([]PairBase, []PairExt) {
	var cache poly.DomainCache
	halfN := int(committer.Encoder.Domain.Cardinality >> 1)

	baseLeaf := make([]PairBase, len(basePolys))
	for j, p := range basePolys {
		encoded := committer.Encoder.Encode(p, cache.Get(uint64(len(p))))
		baseLeaf[j][0].Set(&encoded[leafIdx])
		baseLeaf[j][1].Set(&encoded[leafIdx+halfN])
	}

	extLeaf := make([]PairExt, len(extPolys))
	for j, p := range extPolys {
		encoded := committer.Encoder.EncodeExt(p, cache.Get(uint64(len(p))))
		extLeaf[j][0].Set(&encoded[leafIdx])
		extLeaf[j][1].Set(&encoded[leafIdx+halfN])
	}

	return baseLeaf, extLeaf
}
