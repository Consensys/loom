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

package fri

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
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

	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	committed, err := pcs.Commit([]Group{{Base: basePolys, Ext: extPolys}})
	if err != nil {
		t.Fatal(err)
	}
	tree := committed.Tree
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
	baseLeaf, extLeaf := rawLeafFromPolys(2, basePolys, extPolys, leafIdx)
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

	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	committed, err := pcs.Commit([]Group{{Base: basePolys, Ext: extPolys}})
	if err != nil {
		t.Fatal(err)
	}
	tree := committed.Tree

	const leafIdx = 2
	proof, err := tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatal(err)
	}

	baseLeaf, extLeaf := rawLeafFromPolys(2, basePolys, extPolys, leafIdx)
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
	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	committed, err := pcs.Commit([]Group{{Base: basePolys}}, WithDomainCache(&cache))
	if err != nil {
		t.Fatal(err)
	}
	tree := committed.Tree
	if got := tree.NumLeaves(); got != 4 {
		t.Fatalf("NumLeaves = %d, want 4", got)
	}
	if got := cache.Get(4); got != cache.Get(4) {
		t.Fatalf("DomainCache did not reuse input domain: %p vs %p", got, cache.Get(4))
	}
}

func TestRSCommitBatchLeafHasherMatchesScalarRoot(t *testing.T) {
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

	tests := []struct {
		name string
		lh   LeafHasher
		nh   NodeHasher
	}{
		{
			name: "poseidon2",
			lh:   DefaultLeafHasher,
			nh:   DefaultNodeHasher,
		},
		{
			name: "sha256",
			lh:   SHA256LeafHasher{},
			nh:   SHA256NodeHasher{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batchPCS := NewPCS(2, tt.lh, tt.nh)
			batchCommitted, err := batchPCS.Commit([]Group{{Base: basePolys, Ext: extPolys}})
			if err != nil {
				t.Fatal(err)
			}

			scalarPCS := NewPCS(2, scalarOnlyLeafHasher{inner: tt.lh}, tt.nh)
			scalarCommitted, err := scalarPCS.Commit([]Group{{Base: basePolys, Ext: extPolys}})
			if err != nil {
				t.Fatal(err)
			}

			if batchCommitted.Tree.Root() != scalarCommitted.Tree.Root() {
				t.Fatalf("batched root differs from scalar root: got %v, want %v", batchCommitted.Tree.Root(), scalarCommitted.Tree.Root())
			}
		})
	}
}

func TestPoseidon2BatchLeafHasherMatchesScalarLeaves(t *testing.T) {
	tests := []struct {
		name    string
		leaves  int
		nbBase  int
		nbExt   int
		offset  int
		wantEnd int
	}{
		{name: "small mixed fallback", leaves: 8, nbBase: 2, nbExt: 1},
		{name: "exact base only", leaves: hash.Poseidon2SpongeBatchSize, nbBase: 3},
		{name: "tail ext only", leaves: hash.Poseidon2SpongeBatchSize + 1, nbExt: 2},
		{name: "multiple batches mixed", leaves: 2*hash.Poseidon2SpongeBatchSize + 1, nbBase: 4, nbExt: 2},
		{name: "subrange", leaves: 2 * hash.Poseidon2SpongeBatchSize, nbBase: 2, nbExt: 2, offset: 3, wantEnd: hash.Poseidon2SpongeBatchSize + 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := testLeafSource(tt.leaves, tt.nbBase, tt.nbExt)
			start := tt.offset
			end := tt.wantEnd
			if end == 0 {
				end = tt.leaves
			}
			got := make([]hash.Digest, end-start)
			DefaultLeafHasher.HashLeaves(got, src, start)

			for k := range got {
				i := start + k
				baseLeaf, extLeaf := leafFromSource(src, i)
				if want := DefaultLeafHasher.HashLeaf(baseLeaf, extLeaf); got[k] != want {
					t.Fatalf("leaf %d: batched digest differs from scalar digest", i)
				}
			}
		})
	}
}

func TestPoseidon2BatchNodeHasherMatchesScalarHash(t *testing.T) {
	const n = hash.Poseidon2SpongeBatchSize
	left := make([]hash.Digest, n)
	right := make([]hash.Digest, n)
	for i := 0; i < n; i++ {
		for j := 0; j < len(left[i]); j++ {
			left[i][j].SetUint64(uint64(0xabcd0000 + i*16 + j))
			right[i][j].SetUint64(uint64(0xdcba0000 + i*16 + j))
		}
	}

	got := make([]hash.Digest, n)
	DefaultNodeHasher.HashNodes(got, left, right)

	for i := 0; i < n; i++ {
		want := DefaultNodeHasher.HashNode(left[i], right[i])
		if got[i] != want {
			t.Fatalf("pair %d: batched node digest differs from scalar digest:\n got  %v\n want %v", i, got[i], want)
		}
	}
}

func TestRSCommitEmptyRails(t *testing.T) {
	basePolys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
	}
	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	baseCommitted, err := pcs.Commit([]Group{{Base: basePolys}})
	if err != nil {
		t.Fatal(err)
	}
	baseTree := baseCommitted.Tree
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
	extCommitted, err := pcs.Commit([]Group{{Ext: extPolys}})
	if err != nil {
		t.Fatal(err)
	}
	extTree := extCommitted.Tree
	if got := extTree.BaseWidth(); got != 0 {
		t.Fatalf("ext-only tree base rail width = %d, want 0", got)
	}
	if got := extTree.NumLeaves(); got != 4 {
		t.Fatalf("ext-only NumLeaves = %d, want 4", got)
	}
}

// TestRSCommitMultiGroupOpenProof exercises the multi-size single-tree path:
// two groups of different native sizes are committed in one Commit call, and
// proofs for both the leaf-level group and the injection-level group are
// verified through the merkle injection schedule.
func TestRSCommitMultiGroupOpenProof(t *testing.T) {
	// Top group: size 8 (the actual Merkle leaves).
	topBase := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4),
			baseElement(5), baseElement(6), baseElement(7), baseElement(8)},
	}
	topExt := []poly.ExtPolynomial{
		{
			extElement(11, 12, 13, 14),
			extElement(21, 22, 23, 24),
			extElement(31, 32, 33, 34),
			extElement(41, 42, 43, 44),
			extElement(51, 52, 53, 54),
			extElement(61, 62, 63, 64),
			extElement(71, 72, 73, 74),
			extElement(81, 82, 83, 84),
		},
	}

	// Smaller group: size 4 (introduced as a level injection).
	smallBase := []poly.Polynomial{
		{baseElement(100), baseElement(200), baseElement(300), baseElement(400)},
	}

	// rate=2 ⇒ encoded domains are 16 and 8, paired leaves at widths 8 and 4.
	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	committed, err := pcs.Commit([]Group{
		{Base: topBase, Ext: topExt},
		{Base: smallBase},
	})
	if err != nil {
		t.Fatal(err)
	}
	tree := committed.Tree
	sources := committed.Sources

	// Shape sanity.
	shapes := tree.Groups()
	if len(shapes) != 2 {
		t.Fatalf("Groups length = %d, want 2", len(shapes))
	}
	if shapes[0].PairedLeaves != 8 || shapes[0].BaseWidth != 1 || shapes[0].ExtWidth != 1 {
		t.Fatalf("top group shape = %+v", shapes[0])
	}
	if shapes[1].PairedLeaves != 4 || shapes[1].BaseWidth != 1 || shapes[1].ExtWidth != 0 {
		t.Fatalf("small group shape = %+v", shapes[1])
	}
	if got := tree.NumLeaves(); got != 8 {
		t.Fatalf("NumLeaves = %d, want 8", got)
	}
	if widths := tree.InjectionWidths(); len(widths) != 1 || widths[0] != 4 {
		t.Fatalf("InjectionWidths = %v, want [4]", widths)
	}

	// Commit's returned LeafSources must be in decreasing-size order — same
	// order as Groups() — and each source's width must match the
	// corresponding GroupShape.
	if len(sources) != 2 {
		t.Fatalf("len(sources) = %d, want 2", len(sources))
	}
	for k, src := range sources {
		if got, want := len(src.Base), shapes[k].BaseWidth; got != want {
			t.Fatalf("sources[%d].Base width = %d, want %d", k, got, want)
		}
		if got, want := len(src.Ext), shapes[k].ExtWidth; got != want {
			t.Fatalf("sources[%d].Ext width = %d, want %d", k, got, want)
		}
	}

	injectionWidths := tree.InjectionWidths()

	// Verify an opening for every leaf index: at each idx, the path crosses
	// the size-4 injection level at position idx>>1, and both the top-leaf
	// hash and the injection leaf must reconstruct the published root.
	for leafIdx := 0; leafIdx < 8; leafIdx++ {
		proof, err := tree.OpenProof(leafIdx)
		if err != nil {
			t.Fatalf("OpenProof(%d): %v", leafIdx, err)
		}
		if len(proof.InjectionLeaves) != 1 {
			t.Fatalf("leaf %d: InjectionLeaves length = %d, want 1", leafIdx, len(proof.InjectionLeaves))
		}

		// Compute the top-group leaf hash that the verifier consumes.
		baseLeaf, extLeaf := rawLeafFromPolys(2, topBase, topExt, leafIdx)
		leaf := DefaultLeafHasher.HashLeaf(baseLeaf, extLeaf)

		if !merkle.VerifyWithInjections(tree.Root(), proof, leaf, injectionWidths, DefaultNodeHasher) {
			t.Fatalf("leaf %d: VerifyWithInjections rejected a valid proof", leafIdx)
		}

		// Cross-check: the legacy Verify (no injection support) must reject,
		// since the proof carries InjectionLeaves the bare path can't fold in.
		if merkle.Verify(tree.Root(), proof, leaf, DefaultNodeHasher) {
			t.Fatalf("leaf %d: legacy Verify unexpectedly accepted an injection-bearing proof", leafIdx)
		}
	}
}

// TestRSCommitDuplicateGroupSize ensures that Commit rejects two groups of
// the same native size, since the merkle layer requires distinct LevelWidths
// for injections.
func TestRSCommitDuplicateGroupSize(t *testing.T) {
	polys := []poly.Polynomial{
		{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
	}
	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	if _, err := pcs.Commit([]Group{
		{Base: polys},
		{Base: polys},
	}); err == nil {
		t.Fatal("Commit should reject two groups with the same native size")
	}
}

type scalarOnlyLeafHasher struct {
	inner LeafHasher
}

func (h scalarOnlyLeafHasher) HashLeaf(base []koalabear.Element, ext []ext.E6) hash.Digest {
	return h.inner.HashLeaf(base, ext)
}

func testLeafSource(nLeaves, nbBase, nbExt int) LeafSource {
	src := LeafSource{
		Base: make([]poly.Polynomial, nbBase),
		Ext:  make([]poly.ExtPolynomial, nbExt),
	}
	for j := range src.Base {
		src.Base[j] = make(poly.Polynomial, nLeaves)
		for i := range src.Base[j] {
			src.Base[j][i] = baseElement(uint64(1000*(j+1) + i + 1))
		}
	}
	for j := range src.Ext {
		src.Ext[j] = make(poly.ExtPolynomial, nLeaves)
		for i := range src.Ext[j] {
			v := uint64(10000*(j+1) + 10*(i+1))
			src.Ext[j][i] = extElement(v+1, v+2, v+3, v+4)
		}
	}
	return src
}

func leafFromSource(src LeafSource, i int) ([]koalabear.Element, []ext.E6) {
	baseLeaf := make([]koalabear.Element, len(src.Base))
	for j := range src.Base {
		baseLeaf[j].Set(&src.Base[j][i])
	}

	extLeaf := make([]ext.E6, len(src.Ext))
	for j := range src.Ext {
		extLeaf[j].Set(&src.Ext[j][i])
	}

	return baseLeaf, extLeaf
}

func baseElement(v uint64) koalabear.Element {
	var e koalabear.Element
	e.SetUint64(v)
	return e
}

func extElement(a0, a1, b0, b1 uint64, b2 ...uint64) ext.E6 {
	var e ext.E6
	e.B0.A0.SetUint64(a0)
	e.B0.A1.SetUint64(a1)
	e.B1.A0.SetUint64(b0)
	e.B1.A1.SetUint64(b1)
	if len(b2) > 0 {
		e.B2.A0.SetUint64(b2[0])
	}
	if len(b2) > 1 {
		e.B2.A1.SetUint64(b2[1])
	}
	return e
}

// rawLeafFromPolys re-encodes basePolys/extPolys at the given rate (same
// blowup PCS uses) and reads the row evaluation at position leafIdx. It is a
// test-only mirror of what RSCommit / PCS.Commit does internally, used to
// check Merkle openings against the single-group leaf hash.
func rawLeafFromPolys(rate uint64, basePolys []poly.Polynomial, extPolys []poly.ExtPolynomial, leafIdx int) ([]koalabear.Element, []ext.E6) {
	var cache poly.DomainCache
	N := 0
	if len(basePolys) > 0 {
		N = len(basePolys[0])
	} else if len(extPolys) > 0 {
		N = len(extPolys[0])
	}
	encoder := reedsolomon.NewEncoder(rate*uint64(N), reedsolomon.WithCache(&cache))

	baseLeaf := make([]koalabear.Element, len(basePolys))
	for j, p := range basePolys {
		encoded := encoder.Encode(p, cache.Get(uint64(len(p))))
		baseLeaf[j].Set(&encoded[leafIdx])
	}

	extLeaf := make([]ext.E6, len(extPolys))
	for j, p := range extPolys {
		encoded := encoder.EncodeExt(p, cache.Get(uint64(len(p))))
		extLeaf[j].Set(&encoded[leafIdx])
	}

	return baseLeaf, extLeaf
}
