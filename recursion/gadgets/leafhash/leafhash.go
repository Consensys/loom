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
// WriteExt, which writes E6 limbs in the order {B0.A0, B0.A1, B1.A0,
// B1.A1, B2.A0, B2.A1}. The extfield package's E6Expr uses the same
// limb order so the wiring below uses an identity SpongeLimbOrder.
package leafhash

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
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

// SpongeLimbOrder maps a sponge slot position to the extfield.E6Expr limb
// index that should be written there. With E6 the two orderings agree
// (both lay out limbs as B0.A0, B0.A1, B1.A0, B1.A1, B2.A0, B2.A1), so the
// mapping is the identity.
var SpongeLimbOrder = [extfield.Limbs]int{0, 1, 2, 3, 4, 5}

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
// leafPCols / leafQCols are the column names of the six E6 limbs of the
// ext-rail leaf values P and Q (in extfield order: B0.A0, B0.A1, B1.A0,
// B1.A1, B2.A0, B2.A1). They typically come from a friround.ColumnNames
// or any other gadget that exposes E6 columns.
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

	// LeafP at sponge positions 3..3+Limbs-1; LeafQ at 3+Limbs..3+2*Limbs-1.
	// With E6, sponge and extfield limb orderings agree (identity SpongeLimbOrder).
	for k := 0; k < extfield.Limbs; k++ {
		limbIdx := SpongeLimbOrder[k]
		mod.AssertZero(expr.Col(spongeCN.In[3+k]).Sub(expr.Col(leafPCols[limbIdx])))
		mod.AssertZero(expr.Col(spongeCN.In[3+extfield.Limbs+k]).Sub(expr.Col(leafQCols[limbIdx])))
	}

	// Pad: state[3+2*Limbs..23] = 0.
	for i := 3 + 2*extfield.Limbs; i < poseidon2sponge.Width; i++ {
		mod.AssertZero(expr.Col(spongeCN.In[i]).Sub(zero))
	}

	cn := ColumnNames{Prefix: prefix, Sponge: spongeCN}
	for i := 0; i < DigestLen; i++ {
		cn.Digest[i] = spongeCN.Post[poseidon2sponge.NbRounds-1][i]
	}
	return cn
}

// SpongeRate is the rate of Loom's Poseidon2 width-24 sponge in
// overwrite mode — 16 base elements per absorption block. The capacity
// (state[16..23]) carries between blocks; only state[0..15] is
// overwritten with input data each block.
const SpongeRate = 16

// FlexibleColumnNames identifies the columns produced by a
// RegisterFlexibleLeafHash call. The leaf hash is chained across one
// or more Poseidon2 width-24 sponge sub-modules — one per block of
// absorbed input — and Digest aliases the first 8 lanes of the LAST
// block's final permutation output.
type FlexibleColumnNames struct {
	Prefix    string
	NumBlocks int
	Sponges   []poseidon2sponge.ColumnNames
	Digest    [DigestLen]string
}

// NumBlocksForFlexible returns the number of absorption blocks required
// for the given leaf layout. Single block when the input fits in one
// rate (3 + 2*nbBase + 2*extfield.Limbs*nbExt ≤ SpongeRate), more blocks
// otherwise. Always >= 1.
func NumBlocksForFlexible(nbBase, nbExt int) int {
	inLen := 3 + 2*nbBase + 2*extfield.Limbs*nbExt
	if inLen <= 0 {
		return 1
	}
	return (inLen + SpongeRate - 1) / SpongeRate
}

// RegisterFlexibleLeafHash registers one or more chained Poseidon2
// width-24 sponges that together hash a Merkle leaf containing
// nbBase base-rail pairs and nbExt ext-rail pairs. Matches
// commitment.Poseidon2LeafHasher.HashLeaf for arbitrary input lengths
// by chaining absorption blocks in overwrite mode:
//
//	state[0..15]  = input block i (with state[k..15] carried from the
//	                previous block's output for the partial-block case)
//	state[16..23] = previous block's output[16..23] (capacity carry)
//
// Per block, the sub-sponge's In array is constrained slot-by-slot:
//   - If the slot lies within this block's input range it equals the
//     corresponding input column.
//   - Block 0 / unused slots are zero.
//   - Block i>0 / unused slots equal block i-1's Post[NbRounds-1][slot]
//     (i.e. they carry through the capacity).
//
// The leaf digest is the LAST block's Post[NbRounds-1][0..7].
func RegisterFlexibleLeafHash(
	mod *board.Module,
	prefix string,
	basePCols, baseQCols []string,
	extPCols, extQCols [][extfield.Limbs]string,
) FlexibleColumnNames {
	if len(basePCols) != len(baseQCols) {
		panic("leafhash.RegisterFlexibleLeafHash: base P/Q length mismatch")
	}
	if len(extPCols) != len(extQCols) {
		panic("leafhash.RegisterFlexibleLeafHash: ext P/Q length mismatch")
	}
	nbBase := len(basePCols)
	nbExt := len(extPCols)
	inLen := 3 + 2*nbBase + 2*extfield.Limbs*nbExt
	numBlocks := NumBlocksForFlexible(nbBase, nbExt)

	var tagElem, nbBaseElem, nbExtElem koalabear.Element
	tagElem.SetUint64(LeafDomainTag)
	nbBaseElem.SetUint64(uint64(nbBase))
	nbExtElem.SetUint64(uint64(nbExt))

	// Build the flat input-expression list: header + base pairs + ext
	// pairs (ext limbs permuted to sponge order).
	inputs := make([]expr.Expr, inLen)
	inputs[0] = expr.Const(tagElem)
	inputs[1] = expr.Const(nbBaseElem)
	inputs[2] = expr.Const(nbExtElem)
	pos := 3
	for i := 0; i < nbBase; i++ {
		inputs[pos] = expr.Col(basePCols[i])
		inputs[pos+1] = expr.Col(baseQCols[i])
		pos += 2
	}
	for j := 0; j < nbExt; j++ {
		for k := 0; k < extfield.Limbs; k++ {
			limbIdx := SpongeLimbOrder[k]
			inputs[pos+k] = expr.Col(extPCols[j][limbIdx])
			inputs[pos+extfield.Limbs+k] = expr.Col(extQCols[j][limbIdx])
		}
		pos += 2 * extfield.Limbs
	}

	cn := FlexibleColumnNames{
		Prefix:    prefix,
		NumBlocks: numBlocks,
		Sponges:   make([]poseidon2sponge.ColumnNames, numBlocks),
	}

	zero := expr.Const(koalabear.Element{})
	for b := 0; b < numBlocks; b++ {
		sub := poseidon2sponge.Register(mod, fmt.Sprintf("%s.sp%d", prefix, b))
		cn.Sponges[b] = sub

		blockStart := b * SpongeRate
		blockEnd := blockStart + SpongeRate
		if blockEnd > inLen {
			blockEnd = inLen
		}

		// state[0..SpongeRate-1]: overwritten by input if available; else carry.
		for j := 0; j < SpongeRate; j++ {
			idx := blockStart + j
			if idx < blockEnd {
				mod.AssertZero(expr.Col(sub.In[j]).Sub(inputs[idx]))
			} else if b == 0 {
				mod.AssertZero(expr.Col(sub.In[j]).Sub(zero))
			} else {
				prev := cn.Sponges[b-1].Post[poseidon2sponge.NbRounds-1][j]
				mod.AssertZero(expr.Col(sub.In[j]).Sub(expr.Col(prev)))
			}
		}

		// state[rate..width-1]: capacity — carry from prev block (zero for block 0).
		for j := SpongeRate; j < poseidon2sponge.Width; j++ {
			if b == 0 {
				mod.AssertZero(expr.Col(sub.In[j]).Sub(zero))
			} else {
				prev := cn.Sponges[b-1].Post[poseidon2sponge.NbRounds-1][j]
				mod.AssertZero(expr.Col(sub.In[j]).Sub(expr.Col(prev)))
			}
		}
	}

	last := numBlocks - 1
	for i := 0; i < DigestLen; i++ {
		cn.Digest[i] = cn.Sponges[last].Post[poseidon2sponge.NbRounds-1][i]
	}

	return cn
}

// FlexibleLeaf is one mixed leaf-hash input matching
// RegisterFlexibleLeafHash. BasePairsP/Q are base elements; ExtPairsP/Q
// hold ext.E6 in extfield limb order.
type FlexibleLeaf struct {
	BasePairsP []koalabear.Element
	BasePairsQ []koalabear.Element
	ExtPairsP  [][extfield.Limbs]koalabear.Element
	ExtPairsQ  [][extfield.Limbs]koalabear.Element
}

// FlexibleLeafSpongeStates replays the native width-24 Poseidon2
// sponge in overwrite mode on one leaf and returns the per-block
// 24-element INPUT state (after overwrite, before permute). Use this
// when filling the trace for the chained sponges produced by
// RegisterFlexibleLeafHash.
//
// Output[b] is the IN state of block b. It matches the order in
// which RegisterFlexibleLeafHash allocates its sub-sponges, so
// `poseidon2sponge.GenerateTrace(cn.Sponges[b], n, [Output[b]] * n)`
// will produce a satisfying trace for block b across all n rows.
func FlexibleLeafSpongeStates(leaf FlexibleLeaf) [][poseidon2sponge.Width]koalabear.Element {
	nbBase := len(leaf.BasePairsP)
	nbExt := len(leaf.ExtPairsP)
	inLen := 3 + 2*nbBase + 2*extfield.Limbs*nbExt
	numBlocks := NumBlocksForFlexible(nbBase, nbExt)

	// Flatten leaf into one input slice in the same order the
	// gadget's constraints lay out the per-slot inputs.
	flat := make([]koalabear.Element, inLen)
	flat[0].SetUint64(LeafDomainTag)
	flat[1].SetUint64(uint64(nbBase))
	flat[2].SetUint64(uint64(nbExt))
	pos := 3
	for i := 0; i < nbBase; i++ {
		flat[pos].Set(&leaf.BasePairsP[i])
		flat[pos+1].Set(&leaf.BasePairsQ[i])
		pos += 2
	}
	for j := 0; j < nbExt; j++ {
		for k := 0; k < extfield.Limbs; k++ {
			limbIdx := SpongeLimbOrder[k]
			flat[pos+k].Set(&leaf.ExtPairsP[j][limbIdx])
			flat[pos+extfield.Limbs+k].Set(&leaf.ExtPairsQ[j][limbIdx])
		}
		pos += 2 * extfield.Limbs
	}

	states := make([][poseidon2sponge.Width]koalabear.Element, numBlocks)
	var state [poseidon2sponge.Width]koalabear.Element
	perm := poseidon2.NewPermutation(poseidon2sponge.Width, poseidon2sponge.NbFullRounds, poseidon2sponge.NbPartialRound)
	for b := 0; b < numBlocks; b++ {
		blockStart := b * SpongeRate
		blockEnd := blockStart + SpongeRate
		if blockEnd > inLen {
			blockEnd = inLen
		}
		// Overwrite state[0..blockSize-1]. Keep state[blockSize..15]
		// and state[16..23] from the prior permute (or zero for block 0).
		for j := 0; j < blockEnd-blockStart; j++ {
			state[j].Set(&flat[blockStart+j])
		}
		states[b] = state
		// Permute to set up the state for the NEXT block (or just to
		// finalise this block's output for the digest).
		if err := perm.Permutation(state[:]); err != nil {
			panic(err)
		}
	}

	return states
}

// BuildFlexibleSpongeInputs returns the 24-element input state per row.
func BuildFlexibleSpongeInputs(leaves []FlexibleLeaf) [][poseidon2sponge.Width]koalabear.Element {
	out := make([][poseidon2sponge.Width]koalabear.Element, len(leaves))
	for row, leaf := range leaves {
		nbBase := len(leaf.BasePairsP)
		nbExt := len(leaf.ExtPairsP)
		var s [poseidon2sponge.Width]koalabear.Element
		s[0].SetUint64(LeafDomainTag)
		s[1].SetUint64(uint64(nbBase))
		s[2].SetUint64(uint64(nbExt))
		pos := 3
		for i := 0; i < nbBase; i++ {
			s[pos].Set(&leaf.BasePairsP[i])
			s[pos+1].Set(&leaf.BasePairsQ[i])
			pos += 2
		}
		for j := 0; j < nbExt; j++ {
			for k := 0; k < extfield.Limbs; k++ {
				limbIdx := SpongeLimbOrder[k]
				s[pos+k].Set(&leaf.ExtPairsP[j][limbIdx])
				s[pos+extfield.Limbs+k].Set(&leaf.ExtPairsQ[j][limbIdx])
			}
			pos += 2 * extfield.Limbs
		}
		out[row] = s
	}
	return out
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
			s[3+extfield.Limbs+k].Set(&leaf.Q[limbIdx])
		}
		// s[3+2*Limbs..23] stay zero
		out[row] = s
	}
	return out
}
