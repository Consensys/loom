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
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/gadgets/nodehash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2"
)

// Path captures the inputs for a single Merkle-path verification.
type Path struct {
	Leaf     hash.Digest
	LeafIdx  int           // 0-based index of the leaf within its layer
	Siblings []hash.Digest // length = number of Merkle steps
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

	hasher := commitment.Poseidon2NodeHasher{}
	current := path.Leaf
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

		current = nextParent
		idx >>= 1
	}

	// Fill the nodehash sub-columns. Each row independently computes
	// HashNode(left, right) via two width-16 Poseidon2 permutations + MD
	// feedforward.
	c1Inputs, c2Inputs := nodehash.BuildCompressInputs(nodes)

	c1Cols, _ := poseidon2.GenerateTrace(cn.NodeHash.Compress, n, c1Inputs)
	for k, v := range c1Cols {
		cols[k] = v
	}
	c2Cols, _ := poseidon2.GenerateTrace(cn.NodeHash.Tail, n, c2Inputs)
	for k, v := range c2Cols {
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

	return cols
}
