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
// E6 extension field. An E6Expr carries six expr.Expr limbs corresponding to
// the tower basis of E6 = E2[v]/(v^3 - (u+1)), with E2 = Fq[u]/(u^2 - 3).
//
// The limb-to-extensions.E6 mapping (matching gnark-crypto's layout) is:
//
//	limb[0] = B0.A0   (coefficient of 1)
//	limb[1] = B0.A1   (coefficient of u)
//	limb[2] = B1.A0   (coefficient of v)
//	limb[3] = B1.A1   (coefficient of u*v)
//	limb[4] = B2.A0   (coefficient of v^2)
//	limb[5] = B2.A1   (coefficient of u*v^2)
//
// Multiplication is implemented via the tower:
//
//	x = B0 + B1*v + B2*v^2,    Bi in E2
//	x*y = B0 B0' + (B1 B2' + B2 B1')(1+u)
//	    + (B0 B1' + B1 B0' + B2 B2' (1+u)) * v
//	    + (B0 B2' + B1 B1' + B2 B0') * v^2
//
// where E2 multiplication uses u^2 = 3 and multiplication by (1+u) maps
// (c0, c1) to (c0 + 3 c1, c0 + c1).
package extfield

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/expr"
)

// Limbs is the number of base-field limbs in an E6 element.
const Limbs = 6

// E6Expr represents an E6 element as six base-field expressions in the tower
// basis {1, u, v, u*v, v^2, u*v^2}. The zero value is not a valid E6Expr; use
// the constructors below.
type E6Expr struct {
	Limb [Limbs]expr.Expr
}

// FromLimbs wraps six base-field expressions into an E6Expr without copying.
func FromLimbs(l0, l1, l2, l3, l4, l5 expr.Expr) E6Expr {
	return E6Expr{Limb: [Limbs]expr.Expr{l0, l1, l2, l3, l4, l5}}
}

// FromBase lifts a base-field expression into E6 by placing it in the 1
// slot and zeroing the other limbs.
func FromBase(e expr.Expr) E6Expr {
	zero := expr.Const(koalabear.Element{})
	return FromLimbs(e, zero, zero, zero, zero, zero)
}

// Const wraps a native E6 element as an E6Expr of constants.
func Const(v ext.E6) E6Expr {
	return FromLimbs(
		expr.Const(v.B0.A0),
		expr.Const(v.B0.A1),
		expr.Const(v.B1.A0),
		expr.Const(v.B1.A1),
		expr.Const(v.B2.A0),
		expr.Const(v.B2.A1),
	)
}

// Zero returns the additive identity in E6.
func Zero() E6Expr {
	z := koalabear.Element{}
	return FromLimbs(expr.Const(z), expr.Const(z), expr.Const(z), expr.Const(z), expr.Const(z), expr.Const(z))
}

// One returns the multiplicative identity in E6.
func One() E6Expr {
	one := koalabear.One()
	z := koalabear.Element{}
	return FromLimbs(expr.Const(one), expr.Const(z), expr.Const(z), expr.Const(z), expr.Const(z), expr.Const(z))
}

// ToE6 lifts a [6]koalabear.Element limb tuple into a native extensions.E6
// value, using the same limb ordering as E6Expr.
func ToE6(l [Limbs]koalabear.Element) ext.E6 {
	var v ext.E6
	v.B0.A0.Set(&l[0])
	v.B0.A1.Set(&l[1])
	v.B1.A0.Set(&l[2])
	v.B1.A1.Set(&l[3])
	v.B2.A0.Set(&l[4])
	v.B2.A1.Set(&l[5])
	return v
}

// FromE6 returns the limb tuple of a native E6 element in tower-basis order.
func FromE6(v ext.E6) [Limbs]koalabear.Element {
	return [Limbs]koalabear.Element{
		v.B0.A0, v.B0.A1,
		v.B1.A0, v.B1.A1,
		v.B2.A0, v.B2.A1,
	}
}

// Add returns z = a + b limb-wise.
func (a E6Expr) Add(b E6Expr) E6Expr {
	return FromLimbs(
		a.Limb[0].Add(b.Limb[0]),
		a.Limb[1].Add(b.Limb[1]),
		a.Limb[2].Add(b.Limb[2]),
		a.Limb[3].Add(b.Limb[3]),
		a.Limb[4].Add(b.Limb[4]),
		a.Limb[5].Add(b.Limb[5]),
	)
}

// Sub returns z = a - b limb-wise.
func (a E6Expr) Sub(b E6Expr) E6Expr {
	return FromLimbs(
		a.Limb[0].Sub(b.Limb[0]),
		a.Limb[1].Sub(b.Limb[1]),
		a.Limb[2].Sub(b.Limb[2]),
		a.Limb[3].Sub(b.Limb[3]),
		a.Limb[4].Sub(b.Limb[4]),
		a.Limb[5].Sub(b.Limb[5]),
	)
}

// Neg returns z = -a limb-wise.
func (a E6Expr) Neg() E6Expr {
	return Zero().Sub(a)
}

// MulByBase scales every limb of a by the base-field expression s.
func (a E6Expr) MulByBase(s expr.Expr) E6Expr {
	return FromLimbs(
		a.Limb[0].Mul(s),
		a.Limb[1].Mul(s),
		a.Limb[2].Mul(s),
		a.Limb[3].Mul(s),
		a.Limb[4].Mul(s),
		a.Limb[5].Mul(s),
	)
}

// MulByConstBase scales every limb of a by a base-field constant.
func (a E6Expr) MulByConstBase(s koalabear.Element) E6Expr {
	return a.MulByBase(expr.Const(s))
}

// Mul returns the full E6 product a*b expanded into limb expressions. The
// reduction uses v^3 = u+1 and u^2 = 3 (multiplications by 3 are encoded
// via the times3 helper).
func (a E6Expr) Mul(b E6Expr) E6Expr {
	// Helper: E2 product (c0, c1) = (a0 + a1 u)(b0 + b1 u)
	//   c0 = a0 b0 + 3 a1 b1
	//   c1 = a0 b1 + a1 b0
	mulE2 := func(a0, a1, b0, b1 expr.Expr) (expr.Expr, expr.Expr) {
		c0 := a0.Mul(b0).Add(times3(a1.Mul(b1)))
		c1 := a0.Mul(b1).Add(a1.Mul(b0))
		return c0, c1
	}
	// Helper: multiply an E2 element (c0, c1) by (1+u):
	//   (c0 + c1 u)(1 + u) = (c0 + 3 c1) + (c0 + c1) u
	mul1PlusU := func(c0, c1 expr.Expr) (expr.Expr, expr.Expr) {
		return c0.Add(times3(c1)), c0.Add(c1)
	}

	// 9 E2 cross products Bi * Bj' for i,j in 0..2.
	p00_0, p00_1 := mulE2(a.Limb[0], a.Limb[1], b.Limb[0], b.Limb[1])
	p01_0, p01_1 := mulE2(a.Limb[0], a.Limb[1], b.Limb[2], b.Limb[3])
	p02_0, p02_1 := mulE2(a.Limb[0], a.Limb[1], b.Limb[4], b.Limb[5])
	p10_0, p10_1 := mulE2(a.Limb[2], a.Limb[3], b.Limb[0], b.Limb[1])
	p11_0, p11_1 := mulE2(a.Limb[2], a.Limb[3], b.Limb[2], b.Limb[3])
	p12_0, p12_1 := mulE2(a.Limb[2], a.Limb[3], b.Limb[4], b.Limb[5])
	p20_0, p20_1 := mulE2(a.Limb[4], a.Limb[5], b.Limb[0], b.Limb[1])
	p21_0, p21_1 := mulE2(a.Limb[4], a.Limb[5], b.Limb[2], b.Limb[3])
	p22_0, p22_1 := mulE2(a.Limb[4], a.Limb[5], b.Limb[4], b.Limb[5])

	// C0 = B0 B0' + (B1 B2' + B2 B1') (1+u)
	s12_0 := p12_0.Add(p21_0)
	s12_1 := p12_1.Add(p21_1)
	s12_0x, s12_1x := mul1PlusU(s12_0, s12_1)
	c0_0 := p00_0.Add(s12_0x)
	c0_1 := p00_1.Add(s12_1x)

	// C1 = B0 B1' + B1 B0' + B2 B2' (1+u)
	p22_0x, p22_1x := mul1PlusU(p22_0, p22_1)
	c1_0 := p01_0.Add(p10_0).Add(p22_0x)
	c1_1 := p01_1.Add(p10_1).Add(p22_1x)

	// C2 = B0 B2' + B1 B1' + B2 B0'
	c2_0 := p02_0.Add(p11_0).Add(p20_0)
	c2_1 := p02_1.Add(p11_1).Add(p20_1)

	return FromLimbs(c0_0, c0_1, c1_0, c1_1, c2_0, c2_1)
}

// Square returns a*a.
func (a E6Expr) Square() E6Expr {
	return a.Mul(a)
}

// EqualityConstraints returns six base-field expressions whose vanishing is
// equivalent to a == b in E6 (limb-wise). The caller is expected to feed each
// into Module.AssertZero or similar.
func (a E6Expr) EqualityConstraints(b E6Expr) [Limbs]expr.Expr {
	return [Limbs]expr.Expr{
		a.Limb[0].Sub(b.Limb[0]),
		a.Limb[1].Sub(b.Limb[1]),
		a.Limb[2].Sub(b.Limb[2]),
		a.Limb[3].Sub(b.Limb[3]),
		a.Limb[4].Sub(b.Limb[4]),
		a.Limb[5].Sub(b.Limb[5]),
	}
}

// times3 returns 3*e via multiplication by the constant 3.
func times3(e expr.Expr) expr.Expr {
	var three koalabear.Element
	three.SetUint64(3)
	return e.Mul(expr.Const(three))
}
