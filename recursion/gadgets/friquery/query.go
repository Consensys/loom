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

// Package friquery composes the per-round FRI fold check with the
// inter-round chaining constraint to form a complete per-query traversal.
//
// One row of the module corresponds to one fold round of one query. The
// gadget enforces two constraints per row:
//
//  1. Fold equation (degree 2 in witnesses):
//
//	   expected = (P + Q)/2 + alpha * (P - Q) * invTwo * xInv
//
//  2. Chain to the next row (excluded at the final row of the module): the
//     next row's P or Q (selected by next row's bit) equals this row's
//     expected. With bit in {0,1}:
//
//	   expected[k] = (1 - bit[k+1])*P[k+1] + bit[k+1]*Q[k+1]
//
// Plus a per-row binary-bit constraint (bit*(1-bit) = 0).
//
// The chain constraint at the very last row (row N-1) is OMITTED. In a
// full verifier, that row's expected must equal finalPoly[s mod len(...)] —
// that connection is the responsibility of a future gadget that wires
// the FRI module to the finalPoly representation.
//
// Module shape: capacity is rounded up to the next power of two. Padding
// rows beyond the real fold rounds store P=Q=alpha=xInv=bit=expected=0,
// which trivially satisfies both constraints.
//
// Note on batching: this gadget does NOT incorporate the gamma-mix step.
// If a level enters at round j+1 in a real FRI verifier, the chain target
// is expected + gamma*leaf rather than expected. To wire batching, either
// (a) introduce an "expectedNext" witness column and equality-link it to
// expected per row via the fribatch gadget through a cross-module lookup,
// or (b) inline the gamma-mix into the chain constraint when level data
// is available — both are addressed in a follow-up milestone.
package friquery

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
)

// Column-name helpers.
func PColName(name string, i int) string     { return fmt.Sprintf("%s.P_%d", name, i) }
func QColName(name string, i int) string     { return fmt.Sprintf("%s.Q_%d", name, i) }
func AlphaColName(name string, i int) string { return fmt.Sprintf("%s.alpha_%d", name, i) }
func ExpColName(name string, i int) string   { return fmt.Sprintf("%s.expected_%d", name, i) }
func XInvColName(name string) string         { return fmt.Sprintf("%s.xInv", name) }
func BitColName(name string) string          { return fmt.Sprintf("%s.bit", name) }

// ColumnNames lists every witness column the trace generator must fill.
type ColumnNames struct {
	ModuleName string
	P          [extfield.Limbs]string
	Q          [extfield.Limbs]string
	Alpha      [extfield.Limbs]string
	Expected   [extfield.Limbs]string
	XInv       string
	Bit        string
}

func makeColumnNames(name string) ColumnNames {
	cn := ColumnNames{ModuleName: name, XInv: XInvColName(name), Bit: BitColName(name)}
	for i := 0; i < extfield.Limbs; i++ {
		cn.P[i] = PColName(name, i)
		cn.Q[i] = QColName(name, i)
		cn.Alpha[i] = AlphaColName(name, i)
		cn.Expected[i] = ExpColName(name, i)
	}
	return cn
}

// invTwo returns 1/2 in koalabear.
func invTwo() koalabear.Element {
	var two, r koalabear.Element
	two.SetUint64(2)
	r.Inverse(&two)
	return r
}

// BuildModule registers the FRI per-query traversal module in the builder.
// capacity is rounded up to the next power of two. The caller must arrange
// the rows so that row k is fold-round k of the single query being checked
// (rows numRounds..N-1 are padding).
func BuildModule(builder *board.Builder, name string, capacity int) ColumnNames {
	if capacity <= 0 {
		panic("friquery.BuildModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := makeColumnNames(name)

	one := expr.Const(koalabear.One())
	invHalf := expr.Const(invTwo())
	bit := expr.Col(cn.Bit)
	xInv := expr.Col(cn.XInv)

	// (1) bit*(1-bit) = 0 at every row.
	mod.AssertZero(bit.Mul(one.Sub(bit)))

	P := extfield.FromLimbs(expr.Col(cn.P[0]), expr.Col(cn.P[1]), expr.Col(cn.P[2]), expr.Col(cn.P[3]), expr.Col(cn.P[4]), expr.Col(cn.P[5]))
	Q := extfield.FromLimbs(expr.Col(cn.Q[0]), expr.Col(cn.Q[1]), expr.Col(cn.Q[2]), expr.Col(cn.Q[3]), expr.Col(cn.Q[4]), expr.Col(cn.Q[5]))
	alpha := extfield.FromLimbs(expr.Col(cn.Alpha[0]), expr.Col(cn.Alpha[1]), expr.Col(cn.Alpha[2]), expr.Col(cn.Alpha[3]), expr.Col(cn.Alpha[4]), expr.Col(cn.Alpha[5]))
	expected := extfield.FromLimbs(expr.Col(cn.Expected[0]), expr.Col(cn.Expected[1]), expr.Col(cn.Expected[2]), expr.Col(cn.Expected[3]), expr.Col(cn.Expected[4]), expr.Col(cn.Expected[5]))

	// (2) Fold equation at every row.
	sumHalf := P.Add(Q).MulByBase(invHalf)
	diff := P.Sub(Q)
	scaled := alpha.Mul(diff).MulByBase(invHalf).MulByBase(xInv)
	foldRhs := sumHalf.Add(scaled)
	for _, rel := range expected.EqualityConstraints(foldRhs) {
		mod.AssertZero(rel)
	}

	// (3) Chain to next row, applied at every row except the last (N-1).
	//   expected[k] = (1 - bit[k+1])*P[k+1] + bit[k+1]*Q[k+1]
	// Encoded with Rot(*,1) and AssertZeroExceptAt(N-1).
	bitNext := expr.Rot(cn.Bit, 1)
	for i := 0; i < extfield.Limbs; i++ {
		pNext := expr.Rot(cn.P[i], 1)
		qNext := expr.Rot(cn.Q[i], 1)
		// selected = (1 - bitNext)*pNext + bitNext*qNext
		// Rewrite as pNext + bitNext*(qNext - pNext) to keep the expression compact.
		selected := pNext.Add(bitNext.Mul(qNext.Sub(pNext)))
		rel := expr.Col(cn.Expected[i]).Sub(selected)
		mod.AssertZeroExceptAt(rel, n-1)
	}

	builder.AddModule(mod)
	return cn
}

// Round captures the inputs for one fold round inside a query.
type Round struct {
	P     ext.E6
	Q     ext.E6
	Alpha ext.E6
	XInv  koalabear.Element
	Bit   uint64 // 0 or 1; bit at row 0 may be set to 0
}

// Folded computes the per-row fold result natively.
func (r Round) Folded() ext.E6 {
	half := invTwo()
	var sum, diff, scaled, out ext.E6
	sum.Add(&r.P, &r.Q)
	sum.MulByElement(&sum, &half)
	diff.Sub(&r.P, &r.Q)
	diff.MulByElement(&diff, &half)
	diff.MulByElement(&diff, &r.XInv)
	scaled.Mul(&diff, &r.Alpha)
	out.Add(&sum, &scaled)
	return out
}

// GenerateTrace fills witness columns for a complete per-query fold
// traversal. The slice rounds[k] must contain the inputs for fold round k.
// The function asserts that the chain consistency holds at each row k <
// len(rounds)-1: the next round's P (when bit=0) or Q (when bit=1) must
// equal this round's folded value. If the rounds slice is internally
// inconsistent, the function panics — a debug aid to catch test-data bugs
// before the prover would.
//
// Padding rows (capacity > len(rounds), rounded up to a power of two) store
// all zeros and trivially satisfy both constraints.
func GenerateTrace(cn ColumnNames, capacity int, rounds []Round) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	if len(rounds) > n {
		panic("friquery.GenerateTrace: more rounds than module rows")
	}

	cols := make(map[string][]koalabear.Element, 4*extfield.Limbs+2)
	alloc := func(name string) []koalabear.Element {
		col := make([]koalabear.Element, n)
		cols[name] = col
		return col
	}

	var pCols, qCols, aCols, eCols [extfield.Limbs][]koalabear.Element
	for i := 0; i < extfield.Limbs; i++ {
		pCols[i] = alloc(cn.P[i])
		qCols[i] = alloc(cn.Q[i])
		aCols[i] = alloc(cn.Alpha[i])
		eCols[i] = alloc(cn.Expected[i])
	}
	xInvCol := alloc(cn.XInv)
	bitCol := alloc(cn.Bit)

	for row := 0; row < n; row++ {
		if row >= len(rounds) {
			continue // zeros (trivially valid)
		}
		r := rounds[row]
		pLimbs := extfield.FromE6(r.P)
		qLimbs := extfield.FromE6(r.Q)
		aLimbs := extfield.FromE6(r.Alpha)
		folded := r.Folded()
		fLimbs := extfield.FromE6(folded)
		for i := 0; i < extfield.Limbs; i++ {
			pCols[i][row].Set(&pLimbs[i])
			qCols[i][row].Set(&qLimbs[i])
			aCols[i][row].Set(&aLimbs[i])
			eCols[i][row].Set(&fLimbs[i])
		}
		xInvCol[row].Set(&r.XInv)
		bitCol[row].SetUint64(r.Bit)
	}

	// Sanity-check chain consistency between successive real rounds. (Panics
	// here serve as early warning for test-data errors; in production this
	// loop can be elided.)
	for k := 0; k+1 < len(rounds); k++ {
		folded := rounds[k].Folded()
		var target ext.E6
		switch rounds[k+1].Bit {
		case 0:
			target = rounds[k+1].P
		case 1:
			target = rounds[k+1].Q
		default:
			panic(fmt.Sprintf("friquery.GenerateTrace: rounds[%d].Bit must be 0 or 1, got %d", k+1, rounds[k+1].Bit))
		}
		if !folded.Equal(&target) {
			panic(fmt.Sprintf(
				"friquery.GenerateTrace: chain mismatch at row %d -> %d: folded != next.%s",
				k, k+1, []string{"P", "Q"}[rounds[k+1].Bit],
			))
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
