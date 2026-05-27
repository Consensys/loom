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
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
)

// ExtColumnNames describes every witness column the E4-rail trace generator
// must fill.
type ExtColumnNames struct {
	ModuleName string
	P          [extfield.Limbs]string
	Q          [extfield.Limbs]string
	Alpha      [extfield.Limbs]string
	XInv       string
	Folded     [extfield.Limbs]string
}

func makeExtColumnNames(name string) ExtColumnNames {
	cn := ExtColumnNames{ModuleName: name, XInv: XInvColName(name)}
	for i := 0; i < extfield.Limbs; i++ {
		cn.P[i] = ExtPColName(name, i)
		cn.Q[i] = ExtQColName(name, i)
		cn.Alpha[i] = ExtAlphaColName(name, i)
		cn.Folded[i] = ExtFoldedColName(name, i)
	}
	return cn
}

// BaseColumnNames describes every witness column the base-rail trace
// generator must fill.
type BaseColumnNames struct {
	ModuleName string
	P          string
	Q          string
	Alpha      string
	XInv       string
	Folded     string
}

func makeBaseColumnNames(name string) BaseColumnNames {
	return BaseColumnNames{
		ModuleName: name,
		P:          BasePColName(name),
		Q:          BaseQColName(name),
		Alpha:      BaseAlphaColName(name),
		XInv:       XInvColName(name),
		Folded:     BaseFoldedColName(name),
	}
}

// invTwo returns 1/2 in koalabear.
func invTwo() koalabear.Element {
	var two, r koalabear.Element
	two.SetUint64(2)
	r.Inverse(&two)
	return r
}

// BuildExtModule registers an E4-rail fold module in the builder. capacity is
// the number of fold steps stored; the module size is rounded up to the next
// power of two.
//
// The constraint per row (per limb i in 0..3):
//
//	folded[i] = ((P[i] + Q[i]) * invTwo)
//	          + (alpha * (P - Q))[i] * invTwo * xInv
//
// Encoded by AssertZero(folded[i] - rhs[i]). Constraint degree: 2 (alpha and
// (P-Q) are both witnesses).
func BuildExtModule(builder *board.Builder, name string, capacity int) ExtColumnNames {
	if capacity <= 0 {
		panic("frifold.BuildExtModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := makeExtColumnNames(name)

	xInv := expr.Col(cn.XInv)
	invHalf := expr.Const(invTwo())

	P := extfield.FromLimbs(expr.Col(cn.P[0]), expr.Col(cn.P[1]), expr.Col(cn.P[2]), expr.Col(cn.P[3]))
	Q := extfield.FromLimbs(expr.Col(cn.Q[0]), expr.Col(cn.Q[1]), expr.Col(cn.Q[2]), expr.Col(cn.Q[3]))
	alpha := extfield.FromLimbs(expr.Col(cn.Alpha[0]), expr.Col(cn.Alpha[1]), expr.Col(cn.Alpha[2]), expr.Col(cn.Alpha[3]))
	folded := extfield.FromLimbs(expr.Col(cn.Folded[0]), expr.Col(cn.Folded[1]), expr.Col(cn.Folded[2]), expr.Col(cn.Folded[3]))

	// sumHalf = (P + Q) * invTwo
	sumHalf := P.Add(Q).MulByBase(invHalf)
	// diff = P - Q (limb-wise)
	diff := P.Sub(Q)
	// alphaDiff = alpha * diff, in E4
	alphaDiff := alpha.Mul(diff)
	// alphaDiffScaled = alphaDiff * invTwo * xInv (scalar multiplications)
	alphaDiffScaled := alphaDiff.MulByBase(invHalf).MulByBase(xInv)

	expected := sumHalf.Add(alphaDiffScaled)
	for _, rel := range folded.EqualityConstraints(expected) {
		mod.AssertZero(rel)
	}

	builder.AddModule(mod)
	return cn
}

// BuildBaseModule registers a base-rail fold module. P, Q, alpha, xInv,
// folded are all single base-field columns.
//
// Constraint: folded = (P+Q)*invTwo + alpha * (P-Q) * invTwo * xInv.
// Degree: 2 (alpha * (P-Q)).
func BuildBaseModule(builder *board.Builder, name string, capacity int) BaseColumnNames {
	if capacity <= 0 {
		panic("frifold.BuildBaseModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := makeBaseColumnNames(name)

	xInv := expr.Col(cn.XInv)
	invHalf := expr.Const(invTwo())
	P := expr.Col(cn.P)
	Q := expr.Col(cn.Q)
	alpha := expr.Col(cn.Alpha)
	folded := expr.Col(cn.Folded)

	sumHalf := P.Add(Q).Mul(invHalf)
	diff := P.Sub(Q)
	scaled := diff.Mul(invHalf).Mul(xInv).Mul(alpha)
	expected := sumHalf.Add(scaled)

	mod.AssertZero(folded.Sub(expected))

	builder.AddModule(mod)
	return cn
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
