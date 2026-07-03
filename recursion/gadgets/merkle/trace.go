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

package merkle

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/leafhash"
	"github.com/consensys/loom/recursion/gadgets/nodehash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
)

// PathWithDigest is the input for BuildModuleNoLeafHash's trace
// generator. The caller supplies the leaf DIGEST directly (rather than
// the leaf P/Q pair), because the no-leafhash variant lets an external
// gadget — typically a multi-pair leafhash in airverify — compute the
// digest, with the merkle module's Current[0] cross-bound to it.
type PathWithDigest struct {
	LeafDigest hash.Digest
	LeafIdx    int
	Siblings   []hash.Digest
}

// GenerateTraceWithDigest fills the columns of a Merkle-step module
// built via BuildModuleNoLeafHash. It does NOT touch LeafP / LeafQ or
// the leafhash sub-columns (they don't exist in that module). The
// row-0 Current is filled directly from path.LeafDigest.
func GenerateTraceWithDigest(cn ColumnNames, capacity int, path PathWithDigest) map[string][]koalabear.Element {
	n := capacity
	if n <= 0 {
		panic("merkle.GenerateTraceWithDigest: capacity must be positive")
	}
	{
		r := 1
		for r < n {
			r <<= 1
		}
		n = r
	}
	if len(path.Siblings) > n {
		panic("merkle.GenerateTraceWithDigest: path longer than module rows")
	}

	cols := make(map[string][]koalabear.Element, 1+5*DigestWidth)
	alloc := func(name string) []koalabear.Element {
		c := make([]koalabear.Element, n)
		cols[name] = c
		return c
	}

	cur := [DigestWidth][]koalabear.Element{}
	sib := [DigestWidth][]koalabear.Element{}
	left := [DigestWidth][]koalabear.Element{}
	right := [DigestWidth][]koalabear.Element{}
	parent := [DigestWidth][]koalabear.Element{}
	for i := 0; i < DigestWidth; i++ {
		cur[i] = alloc(cn.Current[i])
		sib[i] = alloc(cn.Sibling[i])
		left[i] = alloc(cn.Left[i])
		right[i] = alloc(cn.Right[i])
		parent[i] = alloc(cn.Parent[i])
	}
	bitCol := alloc(cn.Bit)

	hasher := commitment.Poseidon2NodeHasher{}

	current := path.LeafDigest
	idx := path.LeafIdx

	nodes := make([]nodehash.Node, n)
	for row := 0; row < n; row++ {
		var sibling hash.Digest
		var bit uint64
		if row < len(path.Siblings) {
			sibling = path.Siblings[row]
			bit = uint64(idx & 1)
		} else {
			sibling = current
			bit = 0
		}
		var l, r hash.Digest
		if bit == 0 {
			l, r = current, sibling
		} else {
			l, r = sibling, current
		}
		nextParent := hasher.HashNode(l, r)

		for i := 0; i < DigestWidth; i++ {
			cur[i][row].Set(&current[i])
			sib[i][row].Set(&sibling[i])
			left[i][row].Set(&l[i])
			right[i][row].Set(&r[i])
			parent[i][row].Set(&nextParent[i])
		}
		bitCol[row].SetUint64(bit)

		var nh nodehash.Node
		for i := 0; i < DigestWidth; i++ {
			nh.Left[i].Set(&l[i])
			nh.Right[i].Set(&r[i])
		}
		nodes[row] = nh

		current = nextParent
		idx >>= 1
	}

	spongeInputs := nodehash.BuildSpongeInputs(nodes)
	spCols, _ := poseidon2sponge.GenerateTrace(cn.NodeHash.Sponge, n, spongeInputs)
	for k, v := range spCols {
		cols[k] = v
	}
	for i := 0; i < nodehash.DigestLen; i++ {
		col := alloc(cn.NodeHash.Digest[i])
		for row := 0; row < n; row++ {
			col[row].Set(&parent[i][row])
		}
	}

	return cols
}

// Path captures the inputs for one ext-rail Merkle-path verification.
//
// The leaf is supplied as an opening pair (LeafP, LeafQ); the gadget
// computes its digest in-circuit via leafhash and constrains the path's
// row-0 current to equal that digest. LeafIdx selects the path direction
// (its low bit per layer).
type Path struct {
	LeafP    ext.E6
	LeafQ    ext.E6
	LeafIdx  int
	Siblings []hash.Digest
}

// GenerateTrace fills every column referenced by cn with the witness values
// required to validate the given path. capacity is rounded up internally to
// the next power of two to match BuildModule's module size. Padding rows
// replay a self-consistent step with bit=0 and sibling=parent=current (so
// the chaining constraint stays satisfied).
//
// Uses the native Poseidon2 NodeHasher to compute each parent digest.
func GenerateTrace(cn ColumnNames, capacity int, path Path) map[string][]koalabear.Element {
	n := capacity
	if n <= 0 {
		panic("merkle.GenerateTrace: capacity must be positive")
	}
	// Match BuildModule: round n up to next power of two.
	{
		r := 1
		for r < n {
			r <<= 1
		}
		n = r
	}
	if len(path.Siblings) > n {
		panic("merkle.GenerateTrace: path longer than module rows")
	}

	cols := make(map[string][]koalabear.Element, 1+5*DigestWidth)
	alloc := func(name string) []koalabear.Element {
		c := make([]koalabear.Element, n)
		cols[name] = c
		return c
	}

	cur := [DigestWidth][]koalabear.Element{}
	sib := [DigestWidth][]koalabear.Element{}
	left := [DigestWidth][]koalabear.Element{}
	right := [DigestWidth][]koalabear.Element{}
	parent := [DigestWidth][]koalabear.Element{}
	for i := 0; i < DigestWidth; i++ {
		cur[i] = alloc(cn.Current[i])
		sib[i] = alloc(cn.Sibling[i])
		left[i] = alloc(cn.Left[i])
		right[i] = alloc(cn.Right[i])
		parent[i] = alloc(cn.Parent[i])
	}
	bitCol := alloc(cn.Bit)

	// Allocate leafP / leafQ columns (ext-rail opening pair, extfield limb
	// order). They are meaningful only at row 0; rows 1..n-1 are filled
	// with the same row-0 values so the per-row leafhash constraints
	// stay consistent.
	leafP := [extfield.Limbs][]koalabear.Element{}
	leafQ := [extfield.Limbs][]koalabear.Element{}
	for i := 0; i < extfield.Limbs; i++ {
		leafP[i] = alloc(cn.LeafP[i])
		leafQ[i] = alloc(cn.LeafQ[i])
	}

	hasher := commitment.Poseidon2NodeHasher{}
	leafHasher := commitment.Poseidon2LeafHasher{}

	// The path starts from the LEAF DIGEST = HashLeaf(LeafP, LeafQ).
	leafDigest := leafHasher.HashLeaf(nil, []commitment.PairExt{{path.LeafP, path.LeafQ}})
	current := leafDigest
	idx := path.LeafIdx

	// Collect per-row (left, right) digests for the in-module nodehash
	// trace generation.
	nodes := make([]nodehash.Node, n)

	for row := 0; row < n; row++ {
		var sibling hash.Digest
		var bit uint64
		if row < len(path.Siblings) {
			sibling = path.Siblings[row]
			bit = uint64(idx & 1)
		} else {
			// Pad row: sibling = current, bit = 0, parent computed as
			// HashNode(current, current) so chaining still holds.
			sibling = current
			bit = 0
		}

		var l, r hash.Digest
		if bit == 0 {
			l, r = current, sibling
		} else {
			l, r = sibling, current
		}
		nextParent := hasher.HashNode(l, r)

		for i := 0; i < DigestWidth; i++ {
			cur[i][row].Set(&current[i])
			sib[i][row].Set(&sibling[i])
			left[i][row].Set(&l[i])
			right[i][row].Set(&r[i])
			parent[i][row].Set(&nextParent[i])
		}
		bitCol[row].SetUint64(bit)

		// Stash the (left, right) for nodehash trace generation.
		var nh nodehash.Node
		for i := 0; i < DigestWidth; i++ {
			nh.Left[i].Set(&l[i])
			nh.Right[i].Set(&r[i])
		}
		nodes[row] = nh

		// Fill leafP / leafQ at every row with the row-0 leaf values, so
		// the per-row leafhash gadget is self-consistent across the
		// entire module domain. (Only row 0 is constrained to match
		// current; other rows just keep the leafhash AIR satisfied.)
		pLimbs := extfield.FromE6(path.LeafP)
		qLimbs := extfield.FromE6(path.LeafQ)
		for i := 0; i < extfield.Limbs; i++ {
			leafP[i][row].Set(&pLimbs[i])
			leafQ[i][row].Set(&qLimbs[i])
		}

		current = nextParent
		idx >>= 1
	}

	// Fill the nodehash sub-columns. Each row independently computes
	// HashNode(left, right) via one width-24 Poseidon2 sponge permutation.
	spongeInputs := nodehash.BuildSpongeInputs(nodes)
	spCols, _ := poseidon2sponge.GenerateTrace(cn.NodeHash.Sponge, n, spongeInputs)
	for k, v := range spCols {
		cols[k] = v
	}

	// Fill nodehash.Digest columns — must equal the parent columns so the
	// equality constraint added by BuildModule is satisfied.
	for i := 0; i < nodehash.DigestLen; i++ {
		col := alloc(cn.NodeHash.Digest[i])
		for row := 0; row < n; row++ {
			col[row].Set(&parent[i][row])
		}
	}

	// Fill the in-module leafhash sub-columns. Every row computes
	// HashLeaf(leafP, leafQ) on its own (leafP/leafQ are the same row-0
	// values across all rows in our trace, so every row's digest equals
	// the actual leaf digest — which matches current at row 0 thanks to
	// the AssertZeroAt constraint).
	rowLeaves := make([]leafhash.ExtLeaf, n)
	for row := 0; row < n; row++ {
		var leaf leafhash.ExtLeaf
		for i := 0; i < extfield.Limbs; i++ {
			leaf.P[i].Set(&leafP[i][row])
			leaf.Q[i].Set(&leafQ[i][row])
		}
		rowLeaves[row] = leaf
	}
	leafInputs := leafhash.BuildSpongeInputs(rowLeaves)
	leafCols, _ := poseidon2sponge.GenerateTrace(cn.LeafHash.Sponge, n, leafInputs)
	for k, v := range leafCols {
		cols[k] = v
	}
	// The leafhash digest columns are aliases of the sponge's last-round
	// post[0..7] cells (Register sets cn.LeafHash.Digest[i] =
	// sponge.Post[NbRounds-1][i]). poseidon2sponge.GenerateTrace already
	// fills those, so no separate writes are needed here.

	return cols
}
