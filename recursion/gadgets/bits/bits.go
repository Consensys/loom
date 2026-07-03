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

// Package bits implements a per-row bit-decomposition gadget.
//
// Given a base-field column v holding integer values in [0, 2^k), the
// gadget produces k binary witness columns b_0..b_{k-1} satisfying:
//
//   - b_i * (1 - b_i) = 0       for each i in 0..k-1
//   - v = sum_{i=0}^{k-1} 2^i * b_i
//
// Use this as a building block for query-position decoding (FRI base/bit
// extraction) and in-circuit exponentiation (see gadgets/binexp).
//
// Note: the gadget does NOT range-check v separately — that responsibility
// falls on the surrounding context. If v exceeds 2^k - 1 the decomposition
// constraint will fail because v cannot be expressed as a sum of k binary
// witnesses.
package bits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

// ValueColName is the column that holds the value being decomposed.
func ValueColName(name string) string { return fmt.Sprintf("%s.value", name) }

// BitColName is the i-th bit of the value (i = 0 is the least-significant
// bit).
func BitColName(name string, i int) string { return fmt.Sprintf("%s.bit_%d", name, i) }

// ColumnNames lists every witness column the trace generator must fill.
type ColumnNames struct {
	ModuleName string
	Value      string
	Bits       []string // length == NumBits
	NumBits    int
}

func makeColumnNames(name string, k int) ColumnNames {
	cn := ColumnNames{ModuleName: name, Value: ValueColName(name), NumBits: k}
	cn.Bits = make([]string, k)
	for i := 0; i < k; i++ {
		cn.Bits[i] = BitColName(name, i)
	}
	return cn
}

// BuildModule registers a standalone bit-decomposition module in the
// builder. k is the number of bits to extract; capacity is rounded up to
// the next power of two. Padding rows store v = 0 with all bits = 0,
// which satisfies both constraints.
//
// For composing with other gadgets in the same module (e.g. to feed bits
// into a downstream exponentiation), use Register instead.
func BuildModule(builder *board.Builder, name string, capacity, k int) ColumnNames {
	if capacity <= 0 {
		panic("bits.BuildModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := Register(&mod, name, k)
	builder.AddModule(mod)
	return cn
}

// Register appends bit-decomposition columns and constraints to an existing
// module under the given prefix. The caller is responsible for setting
// mod.N (must be a power of two) and for calling builder.AddModule(*mod)
// once all gadgets are registered.
//
// The returned ColumnNames lets downstream gadgets reference the bit
// columns by name (e.g. binexp.Register consumes them to compute base^v).
func Register(mod *board.Module, prefix string, k int) ColumnNames {
	if k <= 0 {
		panic("bits.Register: k must be positive")
	}
	cn := makeColumnNames(prefix, k)

	one := expr.Const(koalabear.One())

	for i := 0; i < k; i++ {
		b := expr.Col(cn.Bits[i])
		mod.AssertZero(b.Mul(one.Sub(b)))
	}

	var weighted expr.Expr
	for i := 0; i < k; i++ {
		var pow2 koalabear.Element
		pow2.SetUint64(uint64(1) << uint(i))
		term := expr.Col(cn.Bits[i]).Mul(expr.Const(pow2))
		if i == 0 {
			weighted = term
		} else {
			weighted = weighted.Add(term)
		}
	}
	mod.AssertZero(expr.Col(cn.Value).Sub(weighted))

	return cn
}

// RegisterAt is the row-gated variant of Register. Constraints are
// applied via AssertZeroAt at rowIdx, and the value being decomposed
// is supplied by the caller as an existing column name (e.g. a
// challenger24 sponge digest limb). The gadget does NOT allocate a
// separate value column.
//
// Off-row, bit columns are unconstrained — the trace generator should
// fill them with zeros at non-rowIdx positions.
//
// Soundness note: with k = 31 the constraint
//
//	value = sum_{i=0..30} 2^i * b_i
//
// almost uniquely determines the bits, except when value < 2^24 - 1,
// where value + p is also a 31-bit representation (p = 2^31 - 2^24 + 1
// is the Koalabear modulus). For uniformly sampled digest limbs the
// collision probability is ~2^-7 per query — acceptable for an
// initial FRI verifier; tighten with an explicit range check if
// stronger soundness is required.
func RegisterAt(mod *board.Module, prefix string, valueColName string, k, rowIdx int) ColumnNames {
	if k <= 0 {
		panic("bits.RegisterAt: k must be positive")
	}
	cn := ColumnNames{
		ModuleName: prefix,
		Value:      valueColName,
		NumBits:    k,
		Bits:       make([]string, k),
	}
	for i := 0; i < k; i++ {
		cn.Bits[i] = BitColName(prefix, i)
	}

	one := expr.Const(koalabear.One())
	for i := 0; i < k; i++ {
		b := expr.Col(cn.Bits[i])
		mod.AssertZeroAt(b.Mul(one.Sub(b)), rowIdx)
	}

	var weighted expr.Expr
	for i := 0; i < k; i++ {
		var pow2 koalabear.Element
		pow2.SetUint64(uint64(1) << uint(i))
		term := expr.Col(cn.Bits[i]).Mul(expr.Const(pow2))
		if i == 0 {
			weighted = term
		} else {
			weighted = weighted.Add(term)
		}
	}
	mod.AssertZeroAt(expr.Col(valueColName).Sub(weighted), rowIdx)

	return cn
}

// GenerateTrace fills witness columns. values[r] is the value to decompose
// at row r; rows beyond len(values) are padded with zeros. Each value is
// reduced modulo 2^k before decomposition — values >= 2^k cause a panic
// because they cannot be represented.
func GenerateTrace(cn ColumnNames, capacity int, values []uint64) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	if len(values) > n {
		panic("bits.GenerateTrace: more values than module rows")
	}
	if cn.NumBits <= 0 || cn.NumBits > 63 {
		panic("bits.GenerateTrace: NumBits must be in (0, 63]")
	}

	cols := make(map[string][]koalabear.Element, 1+cn.NumBits)
	alloc := func(name string) []koalabear.Element {
		c := make([]koalabear.Element, n)
		cols[name] = c
		return c
	}

	valueCol := alloc(cn.Value)
	bitCols := make([][]koalabear.Element, cn.NumBits)
	for i := 0; i < cn.NumBits; i++ {
		bitCols[i] = alloc(cn.Bits[i])
	}

	maxV := uint64(1) << uint(cn.NumBits)
	for row := 0; row < n; row++ {
		if row >= len(values) {
			continue
		}
		v := values[row]
		if v >= maxV {
			panic(fmt.Sprintf("bits.GenerateTrace: values[%d]=%d does not fit in %d bits", row, v, cn.NumBits))
		}
		valueCol[row].SetUint64(v)
		for i := 0; i < cn.NumBits; i++ {
			if (v>>uint(i))&1 == 1 {
				bitCols[i][row].SetOne()
			}
		}
	}

	return cols
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	r := 1
	for r < n {
		r <<= 1
	}
	return r
}
