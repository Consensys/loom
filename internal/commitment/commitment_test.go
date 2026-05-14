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
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
)

func TestRSCommitDualRailProofSerialisation(t *testing.T) {
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

	committer := NewRSCommit(4, 2, LeafHash, NodeHash)
	tree, err := committer.Commit(basePolys, extPolys)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree.NumLeaves(); got != 4 {
		t.Fatalf("NumLeaves = %d, want 4", got)
	}
	if got := len(tree.UnhashedLeafsBase[0]); got != len(basePolys) {
		t.Fatalf("base rail width = %d, want %d", got, len(basePolys))
	}
	if got := len(tree.UnhashedLeafsExt[0]); got != len(extPolys) {
		t.Fatalf("ext rail width = %d, want %d", got, len(extPolys))
	}

	const leafIdx = 1
	proof, err := tree.Tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatal(err)
	}
	leafData := SerializeRawLeaf(tree.UnhashedLeafsBase[leafIdx], tree.UnhashedLeafsExt[leafIdx])
	if !merkle.Verify(tree.Root(), proof, leafData, LeafHash, NodeHash) {
		t.Fatal("dual-rail Merkle proof did not verify")
	}
}

func TestRSCommitEmptyRails(t *testing.T) {
	basePolys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
	}
	committer := NewRSCommit(4, 2, LeafHash, NodeHash)
	baseTree, err := committer.Commit(basePolys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseTree.UnhashedLeafsExt) != 0 {
		t.Fatalf("base-only tree ext rail length = %d, want 0", len(baseTree.UnhashedLeafsExt))
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
	if len(extTree.UnhashedLeafsBase) != 0 {
		t.Fatalf("ext-only tree base rail length = %d, want 0", len(extTree.UnhashedLeafsBase))
	}
	if got := extTree.NumLeaves(); got != 4 {
		t.Fatalf("ext-only NumLeaves = %d, want 4", got)
	}
}

func TestSerializeRawLeafExtCoordinateOrder(t *testing.T) {
	pair := PairExt{
		extElement(1, 2, 3, 4),
		extElement(5, 6, 7, 8),
	}

	got := SerializeRawLeaf(nil, []PairExt{pair})
	var want []byte
	want = appendExtElement(want, pair[0])
	want = appendExtElement(want, pair[1])
	if !bytes.Equal(got, want) {
		t.Fatalf("SerializeRawLeaf ext bytes mismatch\ngot  %x\nwant %x", got, want)
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

func appendExtElement(out []byte, e ext.E4) []byte {
	out = append(out, e.B0.A0.Marshal()...)
	out = append(out, e.B0.A1.Marshal()...)
	out = append(out, e.B1.A0.Marshal()...)
	out = append(out, e.B1.A1.Marshal()...)
	return out
}
