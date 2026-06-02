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

// Package frichain wires consecutive friround column-groups together so
// that one module verifies an entire per-query FRI traversal.
//
// Given two friround.ColumnNames cnPrev (round j) and cnNext (round j+1)
// registered in the same module, Link emits two families of constraints
// applied row-wise (one row per query):
//
//  1. Chain (E6, per limb i in 0..5):
//
//     expected_j[i] = P_{j+1}[i] + top_bit_j * (Q_{j+1}[i] - P_{j+1}[i])
//
//     where top_bit_j is the highest bit of base_j (cnPrev.Bits.Bits[k_j-1]).
//
//  2. Bit-inheritance (binary, per bit i in 0..k_{j+1}-1):
//
//     bits_{j+1}[i] = bits_j[i]
//
//     This enforces base_{j+1} = base_j without its top bit — i.e. the
//     lower k_{j+1} bits of the original query position s carry through.
//
// Together these two constraint families say: "the next round's opened
// leaf at index base_{j+1} equals this round's folded value, with the
// branch (LeafP vs LeafQ) chosen by the bit base_j sheds at folding".
//
// k_{j+1} must equal k_j - 1; Link panics otherwise.
package frichain

import (
	"fmt"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/friround"
)

// LevelData holds the column names for one mid-FRI level introduction:
// gamma (the batching challenge for this level), and the (LeafP, LeafQ)
// pair opened from this level's evaluations at the running query index.
type LevelData struct {
	Prefix string
	Gamma  [extfield.Limbs]string
	LeafP  [extfield.Limbs]string
	LeafQ  [extfield.Limbs]string
}

// GammaColName / LeafPColName / LeafQColName follow the package convention
// for column naming.
func GammaColName(prefix string, i int) string { return fmt.Sprintf("%s.gamma_%d", prefix, i) }
func LeafPColName(prefix string, i int) string { return fmt.Sprintf("%s.leafP_%d", prefix, i) }
func LeafQColName(prefix string, i int) string { return fmt.Sprintf("%s.leafQ_%d", prefix, i) }

// RegisterLevel allocates the witness column names for one level
// introduction inside mod. No constraints are added here — the level data
// is supplied by the trace generator and consumed by LinkWithLevel. The
// surrounding context is expected to also bind these columns to the
// inner-proof's level opening (e.g. via a Merkle proof lookup, deferred).
func RegisterLevel(_ *board.Module, prefix string) LevelData {
	ld := LevelData{Prefix: prefix}
	for i := 0; i < extfield.Limbs; i++ {
		ld.Gamma[i] = GammaColName(prefix, i)
		ld.LeafP[i] = LeafPColName(prefix, i)
		ld.LeafQ[i] = LeafQColName(prefix, i)
	}
	return ld
}

// Link adds chain + bit-inheritance constraints linking cnPrev (round j)
// to cnNext (round j+1) inside mod. Use this when NO level enters at round
// j+1; for level introductions, use LinkWithLevel instead.
func Link(mod *board.Module, cnPrev, cnNext friround.ColumnNames) {
	checkRoundShapes(cnPrev, cnNext)
	registerBitInheritance(mod, cnPrev, cnNext)

	topBit := expr.Col(cnPrev.Bits.Bits[cnPrev.KBits-1])

	// Chain: expected_j[i] = P_{j+1}[i] + topBit*(Q_{j+1}[i] - P_{j+1}[i])
	for i := 0; i < extfield.Limbs; i++ {
		expected := expr.Col(cnPrev.Expected[i])
		pNext := expr.Col(cnNext.P[i])
		qNext := expr.Col(cnNext.Q[i])
		selected := pNext.Add(topBit.Mul(qNext.Sub(pNext)))
		mod.AssertZero(expected.Sub(selected))
	}
}

// LinkWithLevel adds chain + bit-inheritance constraints linking cnPrev
// (round j) to cnNext (round j+1) when a NEW level enters at round j+1.
//
// The chain target is shifted by gamma * leaf:
//
//	(expected_j + gamma_l * leaf_l) = selected(P_{j+1}, Q_{j+1}, top_bit_j)
//
// where leaf_l = selected(LeafP_l, LeafQ_l, top_bit_j) — i.e. the level
// opening is picked on the same branch as the running fold.
//
// gamma is E6, leaf is E6, so gamma*leaf is a full E6 multiplication; the
// resulting constraint is degree 2 in witness columns.
func LinkWithLevel(mod *board.Module, cnPrev, cnNext friround.ColumnNames, ld LevelData) {
	checkRoundShapes(cnPrev, cnNext)
	registerBitInheritance(mod, cnPrev, cnNext)

	topBit := expr.Col(cnPrev.Bits.Bits[cnPrev.KBits-1])

	expected := extfield.FromLimbs(
		expr.Col(cnPrev.Expected[0]), expr.Col(cnPrev.Expected[1]),
		expr.Col(cnPrev.Expected[2]), expr.Col(cnPrev.Expected[3]),
		expr.Col(cnPrev.Expected[4]), expr.Col(cnPrev.Expected[5]),
	)
	nextP := extfield.FromLimbs(
		expr.Col(cnNext.P[0]), expr.Col(cnNext.P[1]),
		expr.Col(cnNext.P[2]), expr.Col(cnNext.P[3]),
		expr.Col(cnNext.P[4]), expr.Col(cnNext.P[5]),
	)
	nextQ := extfield.FromLimbs(
		expr.Col(cnNext.Q[0]), expr.Col(cnNext.Q[1]),
		expr.Col(cnNext.Q[2]), expr.Col(cnNext.Q[3]),
		expr.Col(cnNext.Q[4]), expr.Col(cnNext.Q[5]),
	)
	gamma := extfield.FromLimbs(
		expr.Col(ld.Gamma[0]), expr.Col(ld.Gamma[1]),
		expr.Col(ld.Gamma[2]), expr.Col(ld.Gamma[3]),
		expr.Col(ld.Gamma[4]), expr.Col(ld.Gamma[5]),
	)
	leafP := extfield.FromLimbs(
		expr.Col(ld.LeafP[0]), expr.Col(ld.LeafP[1]),
		expr.Col(ld.LeafP[2]), expr.Col(ld.LeafP[3]),
		expr.Col(ld.LeafP[4]), expr.Col(ld.LeafP[5]),
	)
	leafQ := extfield.FromLimbs(
		expr.Col(ld.LeafQ[0]), expr.Col(ld.LeafQ[1]),
		expr.Col(ld.LeafQ[2]), expr.Col(ld.LeafQ[3]),
		expr.Col(ld.LeafQ[4]), expr.Col(ld.LeafQ[5]),
	)

	// leaf_l = leafP + top_bit*(leafQ - leafP)
	leaf := leafP.Add(leafQ.Sub(leafP).MulByBase(topBit))

	// expectedNext = expected + gamma * leaf
	expectedNext := expected.Add(gamma.Mul(leaf))

	// chainTarget = nextP + top_bit*(nextQ - nextP)
	chainTarget := nextP.Add(nextQ.Sub(nextP).MulByBase(topBit))

	for _, rel := range chainTarget.EqualityConstraints(expectedNext) {
		mod.AssertZero(rel)
	}

	// Pin gamma constant across all rows (one FS challenge per level,
	// shared by every query). Applied at every row except the last.
	if mod.N >= 2 {
		for i := 0; i < extfield.Limbs; i++ {
			rel := expr.Col(ld.Gamma[i]).Sub(expr.Rot(ld.Gamma[i], 1))
			mod.AssertZeroExceptAt(rel, mod.N-1)
		}
	}
}

func checkRoundShapes(cnPrev, cnNext friround.ColumnNames) {
	if cnNext.KBits != cnPrev.KBits-1 {
		panic(fmt.Sprintf("frichain: cnNext.KBits=%d must equal cnPrev.KBits-1=%d", cnNext.KBits, cnPrev.KBits-1))
	}
}

func registerBitInheritance(mod *board.Module, cnPrev, cnNext friround.ColumnNames) {
	for i := 0; i < cnNext.KBits; i++ {
		prevBit := expr.Col(cnPrev.Bits.Bits[i])
		nextBit := expr.Col(cnNext.Bits.Bits[i])
		mod.AssertZero(nextBit.Sub(prevBit))
	}
}
