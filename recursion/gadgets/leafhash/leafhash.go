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

// Package leafhash implements an in-circuit verifier for Loom's Merkle
// leaf hash, used to bind FRI openings against per-layer commitments.
//
// Currently implemented: ext-rail FRI leaves (one PairExt per leaf, no
// base pairs). The hash input absorbed into the width-24 sponge is:
//
//	state[0]    = LEAF_TAG
//	state[1]    = 0     (nbBase)
//	state[2]    = 1     (nbExt)
//	state[3..6] = LeafP {B0.A0, B0.A1, B1.A0, B1.A1}
//	state[7..10]= LeafQ {B0.A0, B0.A1, B1.A0, B1.A1}
//	state[11..]= 0
//
// One permutation produces the 24-element output state; the 8-limb digest
// is the first 8 cells of that output.
//
// LEAF_TAG = 0x4c454146 ("LEAF") matches commitment.leafDomainTag.
//
// Sponge limb ordering: the native HashLeaf uses Poseidon2SpongeHasher's
// WriteExt, which writes E4 limbs in the order {B0.A0, B0.A1, B1.A0,
// B1.A1}. The extfield package's E4Expr uses limb order {B0.A0, B1.A0,
// B0.A1, B1.A1} (= {1, v, v^2, v^3} basis). The wiring below re-maps
// between these two orderings.
package leafhash

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
)

// LeafDomainTag is the domain separation prefix Loom prepends to every
// Merkle leaf. Mirrors the unexported commitment.leafDomainTag constant —
// if Loom ever changes that value, this constant must change too.
const LeafDomainTag uint64 = 0x4c454146 // "LEAF"

// DigestLen is the number of base-field limbs in a Merkle leaf digest.
const DigestLen = hash.DIGEST_NB_ELEMENTS // 8

// SpongeLimbOrder maps a sponge-byte position (k in 0..3 within a packed
// E4) to the extfield.E4Expr limb index that should be written there.
//
//	sponge slot | extfield limb
//	  0 (B0.A0) | 0 (B0.A0)
//	  1 (B0.A1) | 2 (B0.A1)
//	  2 (B1.A0) | 1 (B1.A0)
//	  3 (B1.A1) | 3 (B1.A1)
var SpongeLimbOrder = [extfield.Limbs]int{0, 2, 1, 3}

// ColumnNames identifies the columns produced by a RegisterExtLeafHash
// call. Sponge holds the underlying width-24 Poseidon2 columns; Digest
// is an alias view onto the first 8 lanes of Sponge.Post[NbRounds-1].
type ColumnNames struct {
	Prefix string
	Sponge poseidon2sponge.ColumnNames
	Digest [DigestLen]string
}

// RegisterExtLeafHash appends leaf-hash constraints to mod. It registers
// a width-24 Poseidon2 sponge inside the same module and forces the
// sponge input cells to encode (LEAF_TAG, 0, 1, LeafP limbs, LeafQ limbs,
// 0...). The Digest field of the returned ColumnNames points at the
// 8 lanes of output that constitute the leaf digest.
//
// leafPCols / leafQCols are the column names of the four E4 limbs of the
// ext-rail leaf values P and Q (in extfield order: B0.A0, B1.A0, B0.A1,
// B1.A1). They typically come from a friround.ColumnNames or any other
// gadget that exposes E4 columns.
func RegisterExtLeafHash(mod *board.Module, prefix string, leafPCols, leafQCols [extfield.Limbs]string) ColumnNames {
	spongeCN := poseidon2sponge.Register(mod, prefix+".sponge")

	var tagElem, zeroElem, oneElem koalabear.Element
	tagElem.SetUint64(LeafDomainTag)
	oneElem.SetOne()

	tag := expr.Const(tagElem)
	zero := expr.Const(zeroElem)
	one := expr.Const(oneElem)

	// Header: [tag, nbBase=0, nbExt=1]
	mod.AssertZero(expr.Col(spongeCN.In[0]).Sub(tag))
	mod.AssertZero(expr.Col(spongeCN.In[1]).Sub(zero))
	mod.AssertZero(expr.Col(spongeCN.In[2]).Sub(one))

	// LeafP at sponge positions 3..6; LeafQ at 7..10. Re-map between
	// sponge order and extfield order.
	for k := 0; k < extfield.Limbs; k++ {
		limbIdx := SpongeLimbOrder[k]
		mod.AssertZero(expr.Col(spongeCN.In[3+k]).Sub(expr.Col(leafPCols[limbIdx])))
		mod.AssertZero(expr.Col(spongeCN.In[7+k]).Sub(expr.Col(leafQCols[limbIdx])))
	}

	// Pad: state[11..23] = 0.
	for i := 11; i < poseidon2sponge.Width; i++ {
		mod.AssertZero(expr.Col(spongeCN.In[i]).Sub(zero))
	}

	cn := ColumnNames{Prefix: prefix, Sponge: spongeCN}
	for i := 0; i < DigestLen; i++ {
		cn.Digest[i] = spongeCN.Post[poseidon2sponge.NbRounds-1][i]
	}
	return cn
}

// ExtLeaf is one ext-rail leaf-hash input. Limb order matches extfield.
type ExtLeaf struct {
	P [extfield.Limbs]koalabear.Element
	Q [extfield.Limbs]koalabear.Element
}

// BuildSpongeInputs returns the 24-element input state that
// RegisterExtLeafHash expects for one row's leaf. Useful for assembling
// the slice passed to poseidon2sponge.GenerateTrace.
func BuildSpongeInputs(leaves []ExtLeaf) [][poseidon2sponge.Width]koalabear.Element {
	out := make([][poseidon2sponge.Width]koalabear.Element, len(leaves))
	for row, leaf := range leaves {
		var s [poseidon2sponge.Width]koalabear.Element
		s[0].SetUint64(LeafDomainTag)
		// s[1] = 0
		s[2].SetOne() // = 1 (nbExt)
		for k := 0; k < extfield.Limbs; k++ {
			limbIdx := SpongeLimbOrder[k]
			s[3+k].Set(&leaf.P[limbIdx])
			s[7+k].Set(&leaf.Q[limbIdx])
		}
		// s[11..23] stay zero
		out[row] = s
	}
	return out
}
