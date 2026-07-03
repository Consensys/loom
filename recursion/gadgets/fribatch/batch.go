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

// Package fribatch implements the FRI batching gadget — the gamma-mix step
// that incorporates a freshly-introduced level polynomial into the running
// fold result at the next round.
//
// When a level enters at round j+1, the native FRI verifier computes:
//
//	leafValue   = LeafP if (base < N_{j+1}/2) else LeafQ
//	expectedNext = expected + gamma * leafValue
//
// The gadget encodes this with a binary selector column (sel) chosen so that
// sel = 0 selects LeafP and sel = 1 selects LeafQ — i.e. sel = 1 iff
// base >= N_{j+1}/2. The selector is a witness; it must already match the
// per-query base index decision, which the verifier circuit derives via bit
// decomposition.
//
// Per row, this gadget exposes:
//
//   - expected_0..5 / gamma_0..5 / leafP_0..5 / leafQ_0..5 / next_0..5 (E6)
//   - sel  (base column, 0 or 1)
//
// Constraints (E6 element-wise):
//
//   - sel*(1-sel) = 0
//   - leaf[i]     = leafP[i] + sel * (leafQ[i] - leafP[i])
//   - next[i]     = expected[i] + (gamma * leaf)[i]
//
// Degrees: sel * leaf (limb-wise) is degree 2; gamma * leaf is also degree 2.
package fribatch

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
)

// Column-name helpers.
func ExpectedColName(name string, i int) string { return fmt.Sprintf("%s.expected_%d", name, i) }
func GammaColName(name string, i int) string    { return fmt.Sprintf("%s.gamma_%d", name, i) }
func LeafPColName(name string, i int) string    { return fmt.Sprintf("%s.leafP_%d", name, i) }
func LeafQColName(name string, i int) string    { return fmt.Sprintf("%s.leafQ_%d", name, i) }
func NextColName(name string, i int) string     { return fmt.Sprintf("%s.next_%d", name, i) }
func SelColName(name string) string             { return fmt.Sprintf("%s.sel", name) }

// ColumnNames lists every witness column the trace generator must fill.
type ColumnNames struct {
	ModuleName string
	Expected   [extfield.Limbs]string
	Gamma      [extfield.Limbs]string
	LeafP      [extfield.Limbs]string
	LeafQ      [extfield.Limbs]string
	Next       [extfield.Limbs]string
	Sel        string
}

func makeColumnNames(name string) ColumnNames {
	cn := ColumnNames{ModuleName: name, Sel: SelColName(name)}
	for i := 0; i < extfield.Limbs; i++ {
		cn.Expected[i] = ExpectedColName(name, i)
		cn.Gamma[i] = GammaColName(name, i)
		cn.LeafP[i] = LeafPColName(name, i)
		cn.LeafQ[i] = LeafQColName(name, i)
		cn.Next[i] = NextColName(name, i)
	}
	return cn
}

// BuildModule registers the E6-rail batching module in the builder. capacity
// is rounded up to the next power of two.
func BuildModule(builder *board.Builder, name string, capacity int) ColumnNames {
	if capacity <= 0 {
		panic("fribatch.BuildModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := makeColumnNames(name)

	sel := expr.Col(cn.Sel)
	one := expr.Const(koalabear.One())

	// sel * (1 - sel) = 0
	mod.AssertZero(sel.Mul(one.Sub(sel)))

	expected := extfield.FromLimbs(expr.Col(cn.Expected[0]), expr.Col(cn.Expected[1]), expr.Col(cn.Expected[2]), expr.Col(cn.Expected[3]), expr.Col(cn.Expected[4]), expr.Col(cn.Expected[5]))
	gamma := extfield.FromLimbs(expr.Col(cn.Gamma[0]), expr.Col(cn.Gamma[1]), expr.Col(cn.Gamma[2]), expr.Col(cn.Gamma[3]), expr.Col(cn.Gamma[4]), expr.Col(cn.Gamma[5]))
	leafP := extfield.FromLimbs(expr.Col(cn.LeafP[0]), expr.Col(cn.LeafP[1]), expr.Col(cn.LeafP[2]), expr.Col(cn.LeafP[3]), expr.Col(cn.LeafP[4]), expr.Col(cn.LeafP[5]))
	leafQ := extfield.FromLimbs(expr.Col(cn.LeafQ[0]), expr.Col(cn.LeafQ[1]), expr.Col(cn.LeafQ[2]), expr.Col(cn.LeafQ[3]), expr.Col(cn.LeafQ[4]), expr.Col(cn.LeafQ[5]))
	next := extfield.FromLimbs(expr.Col(cn.Next[0]), expr.Col(cn.Next[1]), expr.Col(cn.Next[2]), expr.Col(cn.Next[3]), expr.Col(cn.Next[4]), expr.Col(cn.Next[5]))

	// leaf[i] = leafP[i] + sel * (leafQ[i] - leafP[i])
	leaf := leafP.Add(leafQ.Sub(leafP).MulByBase(sel))

	// expectedNext = expected + gamma * leaf
	expectedNext := expected.Add(gamma.Mul(leaf))

	for _, rel := range next.EqualityConstraints(expectedNext) {
		mod.AssertZero(rel)
	}

	builder.AddModule(mod)
	return cn
}

// Batch is one batching-step input record.
type Batch struct {
	Expected ext.E6
	Gamma    ext.E6
	LeafP    ext.E6
	LeafQ    ext.E6
	Sel      uint64 // 0 or 1
}

// Next computes the expected output of this batching step natively.
func (b Batch) Next() ext.E6 {
	var leaf ext.E6
	if b.Sel == 0 {
		leaf.Set(&b.LeafP)
	} else {
		leaf.Set(&b.LeafQ)
	}
	var term, out ext.E6
	term.Mul(&b.Gamma, &leaf)
	out.Add(&b.Expected, &term)
	return out
}

// GenerateTrace fills witness columns. Padding rows store all zeros and
// sel = 0, which trivially satisfies the constraint (next = expected = 0).
func GenerateTrace(cn ColumnNames, capacity int, batches []Batch) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	if len(batches) > n {
		panic("fribatch.GenerateTrace: more batches than module rows")
	}

	cols := make(map[string][]koalabear.Element, 5*extfield.Limbs+1)
	alloc := func(name string) []koalabear.Element {
		c := make([]koalabear.Element, n)
		cols[name] = c
		return c
	}

	var eCols, gCols, lpCols, lqCols, nCols [extfield.Limbs][]koalabear.Element
	for i := 0; i < extfield.Limbs; i++ {
		eCols[i] = alloc(cn.Expected[i])
		gCols[i] = alloc(cn.Gamma[i])
		lpCols[i] = alloc(cn.LeafP[i])
		lqCols[i] = alloc(cn.LeafQ[i])
		nCols[i] = alloc(cn.Next[i])
	}
	selCol := alloc(cn.Sel)

	for row := 0; row < n; row++ {
		if row < len(batches) {
			b := batches[row]
			eLimbs := extfield.FromE6(b.Expected)
			gLimbs := extfield.FromE6(b.Gamma)
			lpLimbs := extfield.FromE6(b.LeafP)
			lqLimbs := extfield.FromE6(b.LeafQ)
			next := b.Next()
			nLimbs := extfield.FromE6(next)
			for i := 0; i < extfield.Limbs; i++ {
				eCols[i][row].Set(&eLimbs[i])
				gCols[i][row].Set(&gLimbs[i])
				lpCols[i][row].Set(&lpLimbs[i])
				lqCols[i][row].Set(&lqLimbs[i])
				nCols[i][row].Set(&nLimbs[i])
			}
			selCol[row].SetUint64(b.Sel)
		}
		// Padding rows: everything zero; constraints all hold (0 = 0 + 0*0).
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
