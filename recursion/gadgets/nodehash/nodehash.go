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

// Package nodehash implements an in-circuit verifier for Loom's Merkle
// inner-node hash (commitment.Poseidon2NodeHasher.HashNode).
//
// HashNode absorbs (nodeTag, left[8], right[8]) — 17 base elements — into
// the width-16 Merkle-Damgard sponge, which requires TWO permutations:
//
//	state[0..15] = (nodeTag, left[0..7], right[0..6])    // 16 elements
//	-- compress1: state = perm(state); state[0..7] += saved_upper[0..7]
//	-- state[8] = right[7]                                // 17th element
//	-- state[9..15] = 0                                   // pad
//	-- compress2: state = perm(state); state[0..7] += saved_upper[0..7]
//	digest = state[0..7]
//
// where saved_upper at each compression is the pre-permutation state[8..15].
//
// In-circuit the same flow is encoded by two poseidon2.Register calls and a
// handful of equality constraints linking their I/O.
package nodehash

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	nativeposeidon2 "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2"
)

// NodeDomainTag is the prefix Loom prepends to every Merkle node hash.
// Mirrors the unexported commitment.nodeDomainTag.
const NodeDomainTag uint64 = 0x4e4f4445 // "NODE"

// DigestLen is the digest width in base-field limbs.
const DigestLen = hash.DIGEST_NB_ELEMENTS // 8

// DigestColName is the column holding the i-th limb of the computed
// HashNode digest.
func DigestColName(prefix string, i int) string {
	return fmt.Sprintf("%s.digest_%d", prefix, i)
}

// ColumnNames holds the columns produced by Register.
type ColumnNames struct {
	Prefix   string
	Compress poseidon2.ColumnNames // compress1 (absorbs the first 16 elements)
	Tail     poseidon2.ColumnNames // compress2 (absorbs the 17th + padding)
	Digest   [DigestLen]string
}

// Register appends HashNode constraints to mod under the given prefix.
// leftCols / rightCols supply the column names for the two 8-limb child
// digests. Returns ColumnNames with cn.Digest as the resulting parent.
func Register(mod *board.Module, prefix string, leftCols, rightCols [DigestLen]string) ColumnNames {
	cn1 := poseidon2.Register(mod, prefix+".p2a")
	cn2 := poseidon2.Register(mod, prefix+".p2b")

	var tagElem, zeroElem koalabear.Element
	tagElem.SetUint64(NodeDomainTag)
	tag := expr.Const(tagElem)
	zero := expr.Const(zeroElem)

	// compress1 input:
	//   [0]     = NodeTag
	//   [1..8]  = left[0..7]
	//   [9..15] = right[0..6]
	mod.AssertZero(expr.Col(cn1.In[0]).Sub(tag))
	for i := 0; i < DigestLen; i++ {
		mod.AssertZero(expr.Col(cn1.In[1+i]).Sub(expr.Col(leftCols[i])))
	}
	for i := 0; i < DigestLen-1; i++ {
		mod.AssertZero(expr.Col(cn1.In[1+DigestLen+i]).Sub(expr.Col(rightCols[i])))
	}

	// compress2 input:
	//   [0..7] = compress1.In[8..15] + compress1.Out[8..15]    (feedforward)
	//   [8]    = right[7]
	//   [9..15]= 0
	out1 := cn1.Post[poseidon2.NbRounds-1]
	for i := 0; i < DigestLen; i++ {
		ff := expr.Col(cn1.In[8+i]).Add(expr.Col(out1[8+i]))
		mod.AssertZero(expr.Col(cn2.In[i]).Sub(ff))
	}
	mod.AssertZero(expr.Col(cn2.In[8]).Sub(expr.Col(rightCols[DigestLen-1])))
	for i := 9; i < poseidon2.Width; i++ {
		mod.AssertZero(expr.Col(cn2.In[i]).Sub(zero))
	}

	// digest[i] = compress2.In[8+i] + compress2.Out[8+i]
	out2 := cn2.Post[poseidon2.NbRounds-1]
	cn := ColumnNames{Prefix: prefix, Compress: cn1, Tail: cn2}
	for i := 0; i < DigestLen; i++ {
		cn.Digest[i] = DigestColName(prefix, i)
		ff := expr.Col(cn2.In[8+i]).Add(expr.Col(out2[8+i]))
		mod.AssertZero(expr.Col(cn.Digest[i]).Sub(ff))
	}

	return cn
}

// Node packs one HashNode input.
type Node struct {
	Left  [DigestLen]koalabear.Element
	Right [DigestLen]koalabear.Element
}

// BuildCompressInputs returns the two Poseidon2-width-16 input states per
// row (one slice per compress stage), ready to pass to
// poseidon2.GenerateTrace.
func BuildCompressInputs(nodes []Node) (compress1, compress2 [][poseidon2.Width]koalabear.Element) {
	compress1 = make([][poseidon2.Width]koalabear.Element, len(nodes))
	compress2 = make([][poseidon2.Width]koalabear.Element, len(nodes))

	perm := nativeposeidon2.NewPermutation(poseidon2.Width, poseidon2.NbFullRounds, poseidon2.NbPartialRound)

	for row, n := range nodes {
		var s1 [poseidon2.Width]koalabear.Element
		s1[0].SetUint64(NodeDomainTag)
		for i := 0; i < DigestLen; i++ {
			s1[1+i].Set(&n.Left[i])
		}
		for i := 0; i < DigestLen-1; i++ {
			s1[1+DigestLen+i].Set(&n.Right[i])
		}
		// state[16] would be right[7] but that's outside the 16-slot first
		// compress — it lives in compress2 instead.
		compress1[row] = s1

		// compress2 input = MD feedforward of compress1's permutation.
		var permuted [poseidon2.Width]koalabear.Element
		permuted = s1
		if err := perm.Permutation(permuted[:]); err != nil {
			panic(err)
		}
		var s2 [poseidon2.Width]koalabear.Element
		for i := 0; i < DigestLen; i++ {
			s2[i].Add(&s1[8+i], &permuted[8+i])
		}
		s2[8].Set(&n.Right[DigestLen-1])
		// s2[9..15] stay zero.
		compress2[row] = s2
	}

	return compress1, compress2
}

// DigestOf is the native HashNode digest for a single node — useful when
// the trace generator needs the explicit parent value.
func DigestOf(n Node) [DigestLen]koalabear.Element {
	_, c2 := BuildCompressInputs([]Node{n})
	perm := nativeposeidon2.NewPermutation(poseidon2.Width, poseidon2.NbFullRounds, poseidon2.NbPartialRound)

	var permuted [poseidon2.Width]koalabear.Element
	permuted = c2[0]
	if err := perm.Permutation(permuted[:]); err != nil {
		panic(err)
	}

	var digest [DigestLen]koalabear.Element
	for i := 0; i < DigestLen; i++ {
		digest[i].Add(&c2[0][8+i], &permuted[8+i])
	}
	return digest
}
