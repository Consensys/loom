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

// Package extfield provides expr-level helpers for arithmetic in the Koalabear
// E4 extension field. An E4Expr carries four expr.Expr limbs corresponding to
// the linear basis {1, v, v^2, v^3} of E4 = Fq[v]/(v^4 - 3).
//
// The limb-to-extensions.E4 mapping is:
//
//	limb[0] = B0.A0   (coefficient of 1)
//	limb[1] = B1.A0   (coefficient of v)
//	limb[2] = B0.A1   (coefficient of v^2)
//	limb[3] = B1.A1   (coefficient of v^3)
//
// Multiplication uses v^4 = 3:
//
//	(a0+a1 v+a2 v^2+a3 v^3)(b0+b1 v+b2 v^2+b3 v^3)
//	  = (a0 b0 + 3(a1 b3 + a2 b2 + a3 b1))
//	  + (a0 b1 + a1 b0 + 3(a2 b3 + a3 b2)) v
//	  + (a0 b2 + a1 b1 + a2 b0 + 3 a3 b3) v^2
//	  + (a0 b3 + a1 b2 + a2 b1 + a3 b0) v^3
package extfield

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/expr"
)

// Limbs is the number of base-field limbs in an E4 element.
const Limbs = 4

// E4Expr represents an E4 element as four base-field expressions, in the
// linear basis {1, v, v^2, v^3}. The zero value is not a valid E4Expr; use
// the constructors below.
type E4Expr struct {
	Limb [Limbs]expr.Expr
}

// FromLimbs wraps four base-field expressions into an E4Expr without copying.
func FromLimbs(l0, l1, l2, l3 expr.Expr) E4Expr {
	return E4Expr{Limb: [Limbs]expr.Expr{l0, l1, l2, l3}}
}

// FromBase lifts a base-field expression into E4 by placing it in the v^0
// slot and zeroing the other limbs.
func FromBase(e expr.Expr) E4Expr {
	zero := expr.Const(koalabear.Element{})
	return FromLimbs(e, zero, zero, zero)
}

// Const wraps a native E4 element as an E4Expr of constants.
func Const(v ext.E4) E4Expr {
	return FromLimbs(
		expr.Const(v.B0.A0),
		expr.Const(v.B1.A0),
		expr.Const(v.B0.A1),
		expr.Const(v.B1.A1),
	)
}

// Zero returns the additive identity in E4.
func Zero() E4Expr {
	z := koalabear.Element{}
	return FromLimbs(expr.Const(z), expr.Const(z), expr.Const(z), expr.Const(z))
}

// One returns the multiplicative identity in E4.
func One() E4Expr {
	one := koalabear.One()
	z := koalabear.Element{}
	return FromLimbs(expr.Const(one), expr.Const(z), expr.Const(z), expr.Const(z))
}

// ToE4 lifts a [4]koalabear.Element limb tuple into a native extensions.E4
// value, using the same limb ordering as E4Expr.
func ToE4(l [Limbs]koalabear.Element) ext.E4 {
	var v ext.E4
	v.B0.A0.Set(&l[0])
	v.B1.A0.Set(&l[1])
	v.B0.A1.Set(&l[2])
	v.B1.A1.Set(&l[3])
	return v
}

// FromE4 returns the limb tuple of a native E4 element in linear-basis order.
func FromE4(v ext.E4) [Limbs]koalabear.Element {
	return [Limbs]koalabear.Element{v.B0.A0, v.B1.A0, v.B0.A1, v.B1.A1}
}

// Add returns z = a + b limb-wise.
func (a E4Expr) Add(b E4Expr) E4Expr {
	return FromLimbs(
		a.Limb[0].Add(b.Limb[0]),
		a.Limb[1].Add(b.Limb[1]),
		a.Limb[2].Add(b.Limb[2]),
		a.Limb[3].Add(b.Limb[3]),
	)
}

// Sub returns z = a - b limb-wise.
func (a E4Expr) Sub(b E4Expr) E4Expr {
	return FromLimbs(
		a.Limb[0].Sub(b.Limb[0]),
		a.Limb[1].Sub(b.Limb[1]),
		a.Limb[2].Sub(b.Limb[2]),
		a.Limb[3].Sub(b.Limb[3]),
	)
}

// Neg returns z = -a limb-wise.
func (a E4Expr) Neg() E4Expr {
	return Zero().Sub(a)
}

// MulByBase scales every limb of a by the base-field expression s.
func (a E4Expr) MulByBase(s expr.Expr) E4Expr {
	return FromLimbs(
		a.Limb[0].Mul(s),
		a.Limb[1].Mul(s),
		a.Limb[2].Mul(s),
		a.Limb[3].Mul(s),
	)
}

// MulByConstBase scales every limb of a by a base-field constant.
func (a E4Expr) MulByConstBase(s koalabear.Element) E4Expr {
	return a.MulByBase(expr.Const(s))
}

// Mul returns the full E4 product a*b expanded into limb expressions. The
// reduction uses v^4 = 3 — multiplications by 3 are encoded as (x+x+x).
func (a E4Expr) Mul(b E4Expr) E4Expr {
	// d_k = sum_{i+j=k} a_i*b_j for k=0..6
	d0 := a.Limb[0].Mul(b.Limb[0])
	d1 := a.Limb[0].Mul(b.Limb[1]).Add(a.Limb[1].Mul(b.Limb[0]))
	d2 := a.Limb[0].Mul(b.Limb[2]).Add(a.Limb[1].Mul(b.Limb[1])).Add(a.Limb[2].Mul(b.Limb[0]))
	d3 := a.Limb[0].Mul(b.Limb[3]).Add(a.Limb[1].Mul(b.Limb[2])).Add(a.Limb[2].Mul(b.Limb[1])).Add(a.Limb[3].Mul(b.Limb[0]))
	d4 := a.Limb[1].Mul(b.Limb[3]).Add(a.Limb[2].Mul(b.Limb[2])).Add(a.Limb[3].Mul(b.Limb[1]))
	d5 := a.Limb[2].Mul(b.Limb[3]).Add(a.Limb[3].Mul(b.Limb[2]))
	d6 := a.Limb[3].Mul(b.Limb[3])

	return FromLimbs(
		d0.Add(times3(d4)),
		d1.Add(times3(d5)),
		d2.Add(times3(d6)),
		d3,
	)
}

// Square returns a*a.
func (a E4Expr) Square() E4Expr {
	return a.Mul(a)
}

// EqualityConstraints returns four base-field expressions whose vanishing is
// equivalent to a == b in E4 (limb-wise). The caller is expected to feed each
// into Module.AssertZero or similar.
func (a E4Expr) EqualityConstraints(b E4Expr) [Limbs]expr.Expr {
	return [Limbs]expr.Expr{
		a.Limb[0].Sub(b.Limb[0]),
		a.Limb[1].Sub(b.Limb[1]),
		a.Limb[2].Sub(b.Limb[2]),
		a.Limb[3].Sub(b.Limb[3]),
	}
}

// times3 returns 3*e via additions to avoid stitching a constant-3 leaf into
// the expression tree (slightly leaner DAG and easier to read in dumps).
func times3(e expr.Expr) expr.Expr {
	var three koalabear.Element
	three.SetUint64(3)
	return e.Mul(expr.Const(three))
}
