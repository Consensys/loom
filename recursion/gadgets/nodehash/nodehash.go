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
// HashNode is one permutation of the width-24 Poseidon2 sponge over the
// 17-element input (nodeTag, left[0..7], right[0..7]) laid out as:
//
//	state[0]      = nodeTag                  (capacity)
//	state[1..7]   = 0                        (rest of capacity)
//	state[8..15]  = left[0..7]               (rate, low half)
//	state[16..23] = right[0..7]              (rate, high half)
//
// The digest is the first 8 lanes of the permuted state.
package nodehash

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	nativeposeidon2 "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
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
	Prefix string
	Sponge poseidon2sponge.ColumnNames
	Digest [DigestLen]string
}

// Register appends HashNode constraints to mod under the given prefix.
// leftCols / rightCols supply the column names for the two 8-limb child
// digests. Returns ColumnNames with cn.Digest as the resulting parent.
func Register(mod *board.Module, prefix string, leftCols, rightCols [DigestLen]string) ColumnNames {
	spongeCN := poseidon2sponge.Register(mod, prefix+".sp")

	var tagElem, zeroElem koalabear.Element
	tagElem.SetUint64(NodeDomainTag)
	tag := expr.Const(tagElem)
	zero := expr.Const(zeroElem)

	// state[0] = NodeTag, state[1..7] = 0 (capacity)
	mod.AssertZero(expr.Col(spongeCN.In[0]).Sub(tag))
	for i := 1; i < 8; i++ {
		mod.AssertZero(expr.Col(spongeCN.In[i]).Sub(zero))
	}
	// state[8..15] = left[0..7]
	for i := 0; i < DigestLen; i++ {
		mod.AssertZero(expr.Col(spongeCN.In[8+i]).Sub(expr.Col(leftCols[i])))
	}
	// state[16..23] = right[0..7]
	for i := 0; i < DigestLen; i++ {
		mod.AssertZero(expr.Col(spongeCN.In[16+i]).Sub(expr.Col(rightCols[i])))
	}

	// digest[i] = sponge.Post[NbRounds-1][i]
	out := spongeCN.Post[poseidon2sponge.NbRounds-1]
	cn := ColumnNames{Prefix: prefix, Sponge: spongeCN}
	for i := 0; i < DigestLen; i++ {
		cn.Digest[i] = DigestColName(prefix, i)
		mod.AssertZero(expr.Col(cn.Digest[i]).Sub(expr.Col(out[i])))
	}

	return cn
}

// Node packs one HashNode input.
type Node struct {
	Left  [DigestLen]koalabear.Element
	Right [DigestLen]koalabear.Element
}

// BuildSpongeInputs returns one width-24 input state per row, ready to pass
// to poseidon2sponge.GenerateTrace.
func BuildSpongeInputs(nodes []Node) [][poseidon2sponge.Width]koalabear.Element {
	out := make([][poseidon2sponge.Width]koalabear.Element, len(nodes))
	for row, n := range nodes {
		var s [poseidon2sponge.Width]koalabear.Element
		s[0].SetUint64(NodeDomainTag)
		for i := 0; i < DigestLen; i++ {
			s[8+i].Set(&n.Left[i])
			s[16+i].Set(&n.Right[i])
		}
		out[row] = s
	}
	return out
}

// DigestOf is the native HashNode digest for a single node — useful when
// the trace generator needs the explicit parent value.
func DigestOf(n Node) [DigestLen]koalabear.Element {
	inputs := BuildSpongeInputs([]Node{n})
	perm := nativeposeidon2.NewPermutation(poseidon2sponge.Width, poseidon2sponge.NbFullRounds, poseidon2sponge.NbPartialRound)

	state := inputs[0]
	if err := perm.Permutation(state[:]); err != nil {
		panic(err)
	}

	var digest [DigestLen]koalabear.Element
	for i := 0; i < DigestLen; i++ {
		digest[i].Set(&state[i])
	}
	return digest
}
