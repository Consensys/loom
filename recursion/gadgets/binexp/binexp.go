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

// Package binexp implements an in-circuit binary exponentiation gadget.
//
// Given a base-field constant g and k binary witness columns b_0..b_{k-1}
// (typically produced by gadgets/bits), the gadget computes
//
//	result = g^(sum 2^i * b_i)
//	       = prod_{i=0}^{k-1} g^(2^i * b_i)
//	       = prod_{i=0}^{k-1} (1 + b_i * (g^(2^i) - 1))
//
// via a running product chain with one intermediate witness per bit
// (degree-2 constraints throughout).
//
// Use case: compute xInv = omega^{-base} in-circuit by passing
// base = omega^{-1} and the bit decomposition of `base` (the per-round
// FRI query position).
//
// The gadget composes with gadgets/bits in the same module — call
// bits.Register first to allocate bit columns, then binexp.Register to
// allocate the running-product columns.
package binexp

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/gadgets/bits"
)

// StepColName is the i-th intermediate result (i in 1..NumBits). The final
// result is StepColName(prefix, NumBits).
func StepColName(prefix string, i int) string {
	return fmt.Sprintf("%s.step_%d", prefix, i)
}

// ResultColName returns the column holding the final computed value.
func ResultColName(prefix string, numBits int) string {
	return StepColName(prefix, numBits)
}

// ColumnNames lists the running-product columns the trace generator must
// fill.
type ColumnNames struct {
	Prefix    string
	NumBits   int
	Steps     []string // length == NumBits
	BitsCN    bits.ColumnNames
	BaseConst koalabear.Element
}

// Result returns the column holding the final exponentiation result.
func (cn ColumnNames) Result() string {
	return cn.Steps[cn.NumBits-1]
}

// Register appends binary-exponentiation columns and constraints to an
// existing module. It assumes bits.Register was previously called on the
// same module with the bits.ColumnNames provided here.
//
// The constraint chain is:
//
//	step[0] - (1 + bits[0] * (g - 1))                     = 0   // = g^bits[0]
//	step[i] - step[i-1] * (1 + bits[i] * (g^(2^i) - 1))   = 0   for i in 1..k-1
//
// All constraints have degree 2 (step[i-1] * (linear in bits[i])).
func Register(mod *board.Module, prefix string, base koalabear.Element, bitsCN bits.ColumnNames) ColumnNames {
	k := bitsCN.NumBits
	if k <= 0 {
		panic("binexp.Register: bitsCN.NumBits must be positive")
	}

	cn := ColumnNames{
		Prefix:    prefix,
		NumBits:   k,
		BitsCN:    bitsCN,
		BaseConst: base,
		Steps:     make([]string, k),
	}
	for i := 0; i < k; i++ {
		cn.Steps[i] = StepColName(prefix, i+1) // 1-indexed step names; step_1 is the first
	}

	one := expr.Const(koalabear.One())
	// Precompute g^(2^i) as field elements.
	powers := make([]koalabear.Element, k)
	powers[0].Set(&base)
	for i := 1; i < k; i++ {
		powers[i].Square(&powers[i-1])
	}

	for i := 0; i < k; i++ {
		ci := expr.Const(powers[i])      // g^(2^i)
		bi := expr.Col(bitsCN.Bits[i])   // b_i
		multiplier := one.Add(bi.Mul(ci.Sub(one))) // 1 + b_i * (c_i - 1)

		step := expr.Col(cn.Steps[i])
		if i == 0 {
			// step_1 = multiplier  (= g^b_0)
			mod.AssertZero(step.Sub(multiplier))
		} else {
			prev := expr.Col(cn.Steps[i-1])
			mod.AssertZero(step.Sub(prev.Mul(multiplier)))
		}
	}

	return cn
}

// GenerateTraceFor returns the per-row running-product values consistent
// with bitValues. Caller writes these into mod's trace under the column
// names in cn.Steps. The length of bitValues must equal mod.N.
//
// Each entry of bitValues is a slice of bits (0/1) for that row, length k.
func GenerateTraceFor(cn ColumnNames, bitValues [][]uint64) map[string][]koalabear.Element {
	n := len(bitValues)
	k := cn.NumBits

	// Precompute g^(2^i).
	powers := make([]koalabear.Element, k)
	powers[0].Set(&cn.BaseConst)
	for i := 1; i < k; i++ {
		powers[i].Square(&powers[i-1])
	}

	cols := make(map[string][]koalabear.Element, k)
	for i := 0; i < k; i++ {
		cols[cn.Steps[i]] = make([]koalabear.Element, n)
	}

	for row := 0; row < n; row++ {
		bv := bitValues[row]
		if len(bv) != k {
			panic(fmt.Sprintf("binexp.GenerateTraceFor: row %d has %d bits, expected %d", row, len(bv), k))
		}
		var running koalabear.Element
		running.SetOne()
		for i := 0; i < k; i++ {
			// multiplier = 1 + b_i * (c_i - 1)
			//            = b_i==0 ? 1 : c_i
			if bv[i]&1 == 1 {
				running.Mul(&running, &powers[i])
			}
			cols[cn.Steps[i]][row].Set(&running)
		}
	}

	return cols
}
