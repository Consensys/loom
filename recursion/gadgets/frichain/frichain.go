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
//  1. Chain (E4, per limb i in 0..3):
//
//	   expected_j[i] = P_{j+1}[i] + top_bit_j * (Q_{j+1}[i] - P_{j+1}[i])
//
//     where top_bit_j is the highest bit of base_j (cnPrev.Bits.Bits[k_j-1]).
//
//  2. Bit-inheritance (binary, per bit i in 0..k_{j+1}-1):
//
//	   bits_{j+1}[i] = bits_j[i]
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

// Link adds chain + bit-inheritance constraints linking cnPrev (round j) to
// cnNext (round j+1) inside mod.
func Link(mod *board.Module, cnPrev, cnNext friround.ColumnNames) {
	kPrev := cnPrev.KBits
	kNext := cnNext.KBits
	if kNext != kPrev-1 {
		panic(fmt.Sprintf("frichain.Link: cnNext.KBits=%d must equal cnPrev.KBits-1=%d", kNext, kPrev-1))
	}

	topBit := expr.Col(cnPrev.Bits.Bits[kPrev-1])

	// (1) Chain constraint, limb-wise.
	for i := 0; i < extfield.Limbs; i++ {
		expected := expr.Col(cnPrev.Expected[i])
		pNext := expr.Col(cnNext.P[i])
		qNext := expr.Col(cnNext.Q[i])
		// selected = pNext + topBit * (qNext - pNext)
		selected := pNext.Add(topBit.Mul(qNext.Sub(pNext)))
		mod.AssertZero(expected.Sub(selected))
	}

	// (2) Bit-inheritance constraint.
	for i := 0; i < kNext; i++ {
		prevBit := expr.Col(cnPrev.Bits.Bits[i])
		nextBit := expr.Col(cnNext.Bits.Bits[i])
		mod.AssertZero(nextBit.Sub(prevBit))
	}
}
