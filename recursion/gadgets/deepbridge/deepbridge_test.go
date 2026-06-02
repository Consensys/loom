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

package deepbridge_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/deepbridge"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randExt(t *testing.T) ext.E6 {
	t.Helper()
	var v ext.E6
	if _, err := v.B0.A0.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B0.A1.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B1.A0.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B1.A1.SetRandom(); err != nil {
		t.Fatal(err)
	}
	return v
}

func makeE6ExprConst(t *testing.T, name string, v ext.E6, cols map[string][]koalabear.Element, n int) extfield.E6Expr {
	t.Helper()
	limbs := extfield.FromE6(v)
	var names [extfield.Limbs]string
	for i := 0; i < extfield.Limbs; i++ {
		names[i] = name + "_" + string('0'+rune(i))
		c := make([]koalabear.Element, n)
		for r := range c {
			c[r].Set(&limbs[i])
		}
		cols[names[i]] = c
	}
	return extfield.FromLimbs(
		expr.Col(names[0]), expr.Col(names[1]),
		expr.Col(names[2]), expr.Col(names[3]),
		expr.Col(names[4]), expr.Col(names[5]),
	)
}

// fillDivWitness writes the native value of num/denom into the four
// columns RegisterDivExt allocated under prefix. The caller invokes
// this after building the gadget to populate the witness.
func fillDivWitness(prefix string, num, denom ext.E6, cols map[string][]koalabear.Element, n int) {
	var inv, res ext.E6
	inv.Inverse(&denom)
	res.Mul(&num, &inv)
	limbs := extfield.FromE6(res)
	for i := 0; i < extfield.Limbs; i++ {
		name := deepbridge.DivColName(prefix, i)
		c := make([]koalabear.Element, n)
		for r := range c {
			c[r].Set(&limbs[i])
		}
		cols[name] = c
	}
}

// TestDivExtPositive proves the gadget for several random (num, denom)
// pairs in one module.
func TestDivExtPositive(t *testing.T) {
	const n = 4 // module size; values are constant across rows so any N works

	mod := board.NewModule("divext")
	mod.N = n

	cols := make(map[string][]koalabear.Element)

	pairs := []struct {
		name       string
		num, denom ext.E6
	}{
		{"p0", randExt(t), randExt(t)},
		{"p1", randExt(t), randExt(t)},
		{"p2", randExt(t), randExt(t)},
	}

	for _, p := range pairs {
		numExpr := makeE6ExprConst(t, p.name+".num", p.num, cols, n)
		denomExpr := makeE6ExprConst(t, p.name+".denom", p.denom, cols, n)
		_ = deepbridge.RegisterDivExt(&mod, p.name, numExpr, denomExpr)
		fillDivWitness(p.name, p.num, p.denom, cols, n)
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestDivExtRejectsWrongQuotient tampers with one limb of the
// division-result witness to confirm the constraint catches it.
func TestDivExtRejectsWrongQuotient(t *testing.T) {
	const n = 4

	num := randExt(t)
	denom := randExt(t)

	mod := board.NewModule("divext_bad")
	mod.N = n

	cols := make(map[string][]koalabear.Element)

	numExpr := makeE6ExprConst(t, "num", num, cols, n)
	denomExpr := makeE6ExprConst(t, "denom", denom, cols, n)
	_ = deepbridge.RegisterDivExt(&mod, "d", numExpr, denomExpr)
	fillDivWitness("d", num, denom, cols, n)

	// Corrupt limb 0 of the quotient.
	col := cols[deepbridge.DivColName("d", 0)]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestSummandMatchesNative builds one DEEP-quotient summand and an
// explicit "expected" E6Expr; the equality constraint passes only when
// the summand matches (v - C)/(z - X).
func TestSummandMatchesNative(t *testing.T) {
	const n = 4

	v := randExt(t)
	C := randExt(t)
	z := randExt(t)
	X := randExt(t)

	// Native expected value.
	var num, denom, expected ext.E6
	num.Sub(&v, &C)
	denom.Sub(&z, &X)
	var inv ext.E6
	inv.Inverse(&denom)
	expected.Mul(&num, &inv)

	mod := board.NewModule("summand")
	mod.N = n

	cols := make(map[string][]koalabear.Element)

	vExpr := makeE6ExprConst(t, "v", v, cols, n)
	cExpr := makeE6ExprConst(t, "C", C, cols, n)
	zExpr := makeE6ExprConst(t, "z", z, cols, n)
	xExpr := makeE6ExprConst(t, "X", X, cols, n)
	wantExpr := makeE6ExprConst(t, "want", expected, cols, n)

	got := deepbridge.RegisterSummand(&mod, "s", vExpr, cExpr, zExpr, xExpr)
	for _, rel := range got.EqualityConstraints(wantExpr) {
		mod.AssertZero(rel)
	}

	// Fill the underlying div witness (RegisterSummand calls
	// RegisterDivExt under the same prefix).
	fillDivWitness("s", num, denom, cols, n)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestSummandSum exercises the typical use pattern: build several
// summands for one shift group and assert their sum equals a known
// reference (the level-0 LeafP for a single-column case).
func TestSummandSum(t *testing.T) {
	const n = 4

	// Three columns at the same shift, alpha-batched.
	alpha := randExt(t)
	cols0 := []ext.E6{randExt(t), randExt(t), randExt(t)} // f_k(zeta)
	cols1 := []ext.E6{randExt(t), randExt(t), randExt(t)} // f_k(X)
	z := randExt(t)
	X := randExt(t)

	// Native expected: DQ = sum_k alpha^k * (f_k(zeta) - f_k(X)) / (z - X)
	var V, Cx ext.E6
	var alphaAcc ext.E6
	alphaAcc.SetOne()
	for k := range cols0 {
		var t1 ext.E6
		t1.Mul(&cols0[k], &alphaAcc)
		V.Add(&V, &t1)
		t1.Mul(&cols1[k], &alphaAcc)
		Cx.Add(&Cx, &t1)
		alphaAcc.Mul(&alphaAcc, &alpha)
	}
	var num, denom, expected ext.E6
	num.Sub(&V, &Cx)
	denom.Sub(&z, &X)
	var inv ext.E6
	inv.Inverse(&denom)
	expected.Mul(&num, &inv)

	mod := board.NewModule("summand_sum")
	mod.N = n

	colsTr := make(map[string][]koalabear.Element)

	vExpr := makeE6ExprConst(t, "V", V, colsTr, n)
	cExpr := makeE6ExprConst(t, "Cx", Cx, colsTr, n)
	zExpr := makeE6ExprConst(t, "z", z, colsTr, n)
	xExpr := makeE6ExprConst(t, "X", X, colsTr, n)
	wantExpr := makeE6ExprConst(t, "want", expected, colsTr, n)

	got := deepbridge.RegisterSummand(&mod, "s", vExpr, cExpr, zExpr, xExpr)
	for _, rel := range got.EqualityConstraints(wantExpr) {
		mod.AssertZero(rel)
	}

	fillDivWitness("s", num, denom, colsTr, n)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range colsTr {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}
