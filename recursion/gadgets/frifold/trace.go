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

package frifold

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/recursion/extfield"
)

// ExtFold is one E4-rail fold-step input record.
type ExtFold struct {
	P     ext.E6
	Q     ext.E6
	Alpha ext.E6
	XInv  koalabear.Element // = omega_j^{-base}
}

// Folded computes the native fold result for sanity-checking outside the
// gadget.
func (f ExtFold) Folded() ext.E6 {
	half := invTwo()

	var sum, diff, scaled, out ext.E6
	sum.Add(&f.P, &f.Q)
	sum.MulByElement(&sum, &half)

	diff.Sub(&f.P, &f.Q)
	diff.MulByElement(&diff, &half)
	diff.MulByElement(&diff, &f.XInv)
	scaled.Mul(&diff, &f.Alpha)

	out.Add(&sum, &scaled)
	return out
}

// GenerateExtTrace fills the witness columns for an E4-rail fold module. The
// number of folds may be less than capacity; padding rows store
// P = Q = alpha = 0, xInv = 1, folded = 0 (which satisfies the constraint
// trivially).
func GenerateExtTrace(cn ExtColumnNames, capacity int, folds []ExtFold) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	if len(folds) > n {
		panic("frifold.GenerateExtTrace: more folds than module rows")
	}

	cols := make(map[string][]koalabear.Element, 4*4+1+1)
	alloc := func(name string) []koalabear.Element {
		col := make([]koalabear.Element, n)
		cols[name] = col
		return col
	}

	var pCols, qCols, aCols, fCols [extfield.Limbs][]koalabear.Element
	for i := 0; i < extfield.Limbs; i++ {
		pCols[i] = alloc(cn.P[i])
		qCols[i] = alloc(cn.Q[i])
		aCols[i] = alloc(cn.Alpha[i])
		fCols[i] = alloc(cn.Folded[i])
	}
	xInvCol := alloc(cn.XInv)

	for row := 0; row < n; row++ {
		if row < len(folds) {
			f := folds[row]
			pLimbs := extfield.FromE6(f.P)
			qLimbs := extfield.FromE6(f.Q)
			aLimbs := extfield.FromE6(f.Alpha)
			folded := f.Folded()
			fLimbs := extfield.FromE6(folded)
			for i := 0; i < extfield.Limbs; i++ {
				pCols[i][row].Set(&pLimbs[i])
				qCols[i][row].Set(&qLimbs[i])
				aCols[i][row].Set(&aLimbs[i])
				fCols[i][row].Set(&fLimbs[i])
			}
			xInvCol[row].Set(&f.XInv)
		} else {
			// Pad row: P = Q = alpha = 0, xInv = 1, folded = 0.
			xInvCol[row].SetOne()
		}
	}

	return cols
}

// BaseFold is one base-rail fold-step input record.
type BaseFold struct {
	P, Q, Alpha, XInv koalabear.Element
}

// Folded computes the native base-rail fold result.
func (f BaseFold) Folded() koalabear.Element {
	half := invTwo()
	var sum, diff, out, term koalabear.Element
	sum.Add(&f.P, &f.Q)
	sum.Mul(&sum, &half)

	diff.Sub(&f.P, &f.Q)
	diff.Mul(&diff, &half)
	diff.Mul(&diff, &f.XInv)
	term.Mul(&diff, &f.Alpha)

	out.Add(&sum, &term)
	return out
}

// GenerateBaseTrace fills the witness columns for a base-rail fold module.
func GenerateBaseTrace(cn BaseColumnNames, capacity int, folds []BaseFold) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	if len(folds) > n {
		panic("frifold.GenerateBaseTrace: more folds than module rows")
	}

	cols := make(map[string][]koalabear.Element, 5)
	alloc := func(name string) []koalabear.Element {
		col := make([]koalabear.Element, n)
		cols[name] = col
		return col
	}

	pCol := alloc(cn.P)
	qCol := alloc(cn.Q)
	aCol := alloc(cn.Alpha)
	xInvCol := alloc(cn.XInv)
	fCol := alloc(cn.Folded)

	for row := 0; row < n; row++ {
		if row < len(folds) {
			f := folds[row]
			pCol[row].Set(&f.P)
			qCol[row].Set(&f.Q)
			aCol[row].Set(&f.Alpha)
			xInvCol[row].Set(&f.XInv)
			out := f.Folded()
			fCol[row].Set(&out)
		} else {
			xInvCol[row].SetOne()
		}
	}

	return cols
}
