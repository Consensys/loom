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

// Package idxselect implements an indexed-select multiplexer over a
// constant E4 table of size 2^k.
//
// Given k binary witness columns b_0..b_{k-1} (least-significant bit first)
// and a fixed table T[0..2^k-1] of E4 constants, the gadget computes
//
//	out = T[ sum 2^i * b_i ]
//
// via tree reduction:
//
//	level_0[i] = T[i]
//	level_l[i] = (1 - b_{l-1}) * level_{l-1}[2i] + b_{l-1} * level_{l-1}[2i+1]
//	out        = level_k[0]
//
// The table is folded entirely into the polynomial expression (no
// intermediate witnesses), giving constraint degree k. For the FRI
// finalPoly use case k is small (log2(N/D), typically 1..4), so this
// inline form stays well within Loom's degree budget.
//
// Used to close the FRI verifier's last-round chain: at round r-1 the
// running fold must equal finalPoly[s mod len(finalPoly)].
package idxselect

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/bits"
)


// OutColName returns the name of the i-th E4 limb of the selector's output.
func OutColName(prefix string, i int) string {
	return fmt.Sprintf("%s.out_%d", prefix, i)
}

// ColumnNames lists the output columns the trace generator must fill.
type ColumnNames struct {
	Prefix string
	Out    [extfield.Limbs]string
	BitsCN bits.ColumnNames
}

// Register appends idxselect constraints to mod under the given prefix.
// table must have length 2^bitsCN.NumBits.
func Register(mod *board.Module, prefix string, table []ext.E4, bitsCN bits.ColumnNames) ColumnNames {
	k := bitsCN.NumBits
	if len(table) != 1<<uint(k) {
		panic(fmt.Sprintf("idxselect.Register: table size %d != 2^%d", len(table), k))
	}

	cn := ColumnNames{Prefix: prefix, BitsCN: bitsCN}
	for i := 0; i < extfield.Limbs; i++ {
		cn.Out[i] = OutColName(prefix, i)
	}

	// Tree-reduce, building a slice of E4Expr-typed entries that shrinks by
	// half at each level.
	level := make([]extfield.E4Expr, len(table))
	for i, t := range table {
		level[i] = extfield.Const(t)
	}

	for l := 0; l < k; l++ {
		b := expr.Col(bitsCN.Bits[l]) // pick b_l at each level
		next := make([]extfield.E4Expr, len(level)/2)
		for i := 0; i < len(next); i++ {
			lo := level[2*i]
			hi := level[2*i+1]
			// next[i] = lo + b * (hi - lo)
			diff := hi.Sub(lo)
			next[i] = lo.Add(diff.MulByBase(b))
		}
		level = next
	}

	out := extfield.FromLimbs(
		expr.Col(cn.Out[0]),
		expr.Col(cn.Out[1]),
		expr.Col(cn.Out[2]),
		expr.Col(cn.Out[3]),
	)
	for _, rel := range out.EqualityConstraints(level[0]) {
		mod.AssertZero(rel)
	}

	return cn
}

// GenerateTrace fills the output limb columns from the table and index
// values per row. indices[r] is the row's index (must be in [0, len(table))).
// Pad rows beyond len(indices) store table[0].
//
// koalabear.Element is the element type used by Loom traces; we keep the
// import for the return-type alias and limb-by-limb writes.
func GenerateTrace(cn ColumnNames, capacity int, table []ext.E4, indices []uint64) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	cols := make(map[string][]koalabear.Element, extfield.Limbs)
	for i := 0; i < extfield.Limbs; i++ {
		cols[cn.Out[i]] = make([]koalabear.Element, n)
	}
	for row := 0; row < n; row++ {
		var idx uint64
		if row < len(indices) {
			idx = indices[row]
		}
		if idx >= uint64(len(table)) {
			panic(fmt.Sprintf("idxselect.GenerateTrace: indices[%d]=%d out of range [0, %d)", row, idx, len(table)))
		}
		limbs := extfield.FromE4(table[idx])
		for i := 0; i < extfield.Limbs; i++ {
			cols[cn.Out[i]][row].Set(&limbs[i])
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
