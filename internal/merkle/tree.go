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
	"bytes"
	"fmt"
)

// LeafHasher hashes raw leaf data into a fixed-size digest.
type LeafHasher func(data []byte) []byte

// NodeHasher combines two child digests into a parent digest.
type NodeHasher func(left, right []byte) []byte

// Tree is a binary Merkle tree whose number of leaves is a power of two.
//
// Nodes are stored 1-indexed in a flat slice of length 2*nLeaves:
//   - nodes[1]              = root
//   - nodes[nLeaves..2*nLeaves-1] = leaves (leaf i at nodes[nLeaves+i])
//   - children of node k   = nodes[2k] (left) and nodes[2k+1] (right)
//   - parent of node k     = nodes[k/2]
type Tree struct {
	nodes      [][]byte
	nLeaves    int
	leafHasher LeafHasher
	nodeHasher NodeHasher
}

// Proof is an opening proof for a single leaf.
// Siblings[0] is the sibling at the leaf level; Siblings[depth-1] is the
// sibling one level below the root.
type Proof struct {
	LeafIdx  int      // 0-based index of the opened leaf
	Siblings [][]byte // sibling digests, leaf-level first
}

// New creates a Tree for nLeaves leaves. nLeaves must be a positive power of two.
func New(nLeaves int, lh LeafHasher, nh NodeHasher) (*Tree, error) {
	if nLeaves <= 0 || nLeaves&(nLeaves-1) != 0 {
		return nil, fmt.Errorf("merkle: nLeaves must be a positive power of two, got %d", nLeaves)
	}
	return &Tree{
		nodes:      make([][]byte, 2*nLeaves),
		nLeaves:    nLeaves,
		leafHasher: lh,
		nodeHasher: nh,
	}, nil
}

// BuildIthLeaf builds the i-th leaf
func (t *Tree) BuildIthLeaf(data []byte, i int) error {
	n := t.nLeaves
	t.nodes[n+i] = t.leafHasher(data)
	return nil
}

// BuildNodes call this function after all the BuildIthLeaf have been called
func (t *Tree) BuildNodes() error {
	n := t.nLeaves
	for i := n - 1; i >= 1; i-- {
		t.nodes[i] = t.nodeHasher(t.nodes[2*i], t.nodes[2*i+1])
	}
	return nil
}

// Build hashes each entry in data with the leaf hasher, then builds all
// internal nodes bottom-up. len(data) must equal nLeaves.
func (t *Tree) Build(data [][]byte) error {
	if len(data) != t.nLeaves {
		return fmt.Errorf("merkle: got %d data entries, want %d", len(data), t.nLeaves)
	}
	n := t.nLeaves
	for i, d := range data {
		t.nodes[n+i] = t.leafHasher(d)
	}
	for i := n - 1; i >= 1; i-- {
		t.nodes[i] = t.nodeHasher(t.nodes[2*i], t.nodes[2*i+1])
	}
	return nil
}

// Root returns the Merkle root digest. Build must be called first.
func (t *Tree) Root() []byte {
	return t.nodes[1]
}

// OpenProof returns the Merkle opening proof for the leaf at 0-based index idx.
func (t *Tree) OpenProof(idx int) (Proof, error) {
	if idx < 0 || idx >= t.nLeaves {
		return Proof{}, fmt.Errorf("merkle: leaf index %d out of range [0, %d)", idx, t.nLeaves)
	}
	depth := log2(t.nLeaves)
	siblings := make([][]byte, depth)
	pos := t.nLeaves + idx
	for k := 0; k < depth; k++ {
		siblings[k] = t.nodes[pos^1] // pos^1 flips the last bit to select the sibling
		pos >>= 1
	}
	return Proof{LeafIdx: idx, Siblings: siblings}, nil
}

// Verify checks that proof is a valid Merkle opening proof for leafData under root.
// The same leaf and node hashers used to build the tree must be supplied.
func Verify(root []byte, proof Proof, leafData []byte, lh LeafHasher, nh NodeHasher) bool {
	h := lh(leafData)
	idx := proof.LeafIdx
	for _, sibling := range proof.Siblings {
		if idx&1 == 0 {
			h = nh(h, sibling) // current node is the left child
		} else {
			h = nh(sibling, h) // current node is the right child
		}
		idx >>= 1
	}
	return bytes.Equal(h, root)
}

func log2(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}
