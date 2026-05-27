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

package extfield_test

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

// e4FromUint builds an E4 from four uint64s (small test values).
func e4FromUint(a, b, c, d uint64) ext.E4 {
	var v ext.E4
	v.B0.A0.SetUint64(a)
	v.B1.A0.SetUint64(b)
	v.B0.A1.SetUint64(c)
	v.B1.A1.SetUint64(d)
	return v
}

func randE4(t *testing.T) ext.E4 {
	t.Helper()
	var v ext.E4
	if _, err := v.B0.A0.SetRandom(); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := v.B0.A1.SetRandom(); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := v.B1.A0.SetRandom(); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := v.B1.A1.SetRandom(); err != nil {
		t.Fatalf("rand: %v", err)
	}
	_ = rand.Reader
	return v
}

// buildBaseTrace registers a 4-row module with columns A,B,C,D set to the
// given values across all rows. Returns the trace.
func constModuleN4() (board.Builder, trace.Trace) {
	builder := board.NewBuilder()
	module := board.NewModule("ef")
	module.N = 4
	builder.AddModule(module)
	return builder, trace.New()
}

func fillConst(tr trace.Trace, name string, v koalabear.Element, n int) {
	col := make([]koalabear.Element, n)
	for i := range col {
		col[i].Set(&v)
	}
	tr.SetBase(name, col)
}

// asE4Expr wraps four committed base columns into an E4Expr.
func asE4Expr(prefix string) extfield.E4Expr {
	return extfield.FromLimbs(
		expr.Col(prefix+"_0"),
		expr.Col(prefix+"_1"),
		expr.Col(prefix+"_2"),
		expr.Col(prefix+"_3"),
	)
}

func registerE4Constant(t *testing.T, builder *board.Builder, tr trace.Trace, modName, prefix string, v ext.E4) {
	t.Helper()
	mod := builder.Modules[modName]
	limbs := extfield.FromE4(v)
	for i, l := range limbs {
		name := prefix + "_" + string('0'+rune(i))
		_ = mod
		fillConst(tr, name, l, builder.Modules[modName].N)
	}
}

// proveOp builds a module asserting expected == op(a,b) and runs through the
// prover/verifier. It uses constant columns (same value at every row) since
// AssertZero must hold at every row of the module domain.
func proveOp(t *testing.T, op func(a, b extfield.E4Expr) extfield.E4Expr, a, b, expected ext.E4) {
	t.Helper()
	builder, tr := constModuleN4()
	mod := builder.Modules["ef"]

	registerE4Constant(t, &builder, tr, "ef", "a", a)
	registerE4Constant(t, &builder, tr, "ef", "b", b)
	registerE4Constant(t, &builder, tr, "ef", "e", expected)

	got := op(asE4Expr("a"), asE4Expr("b"))
	for _, rel := range got.EqualityConstraints(asE4Expr("e")) {
		mod.AssertZero(rel)
	}
	builder.AddModule(*mod)

	testutil.ProveAndVerify(t, &builder, tr)
}

func TestE4Add(t *testing.T) {
	for i := 0; i < 32; i++ {
		a := randE4(t)
		b := randE4(t)
		var want ext.E4
		want.Add(&a, &b)
		proveOp(t, func(x, y extfield.E4Expr) extfield.E4Expr { return x.Add(y) }, a, b, want)
	}
}

func TestE4Sub(t *testing.T) {
	for i := 0; i < 32; i++ {
		a := randE4(t)
		b := randE4(t)
		var want ext.E4
		want.Sub(&a, &b)
		proveOp(t, func(x, y extfield.E4Expr) extfield.E4Expr { return x.Sub(y) }, a, b, want)
	}
}

func TestE4Mul(t *testing.T) {
	for i := 0; i < 32; i++ {
		a := randE4(t)
		b := randE4(t)
		var want ext.E4
		want.Mul(&a, &b)
		proveOp(t, func(x, y extfield.E4Expr) extfield.E4Expr { return x.Mul(y) }, a, b, want)
	}
}

func TestE4Square(t *testing.T) {
	for i := 0; i < 16; i++ {
		a := randE4(t)
		var want ext.E4
		want.Square(&a)
		proveOp(t, func(x, _ extfield.E4Expr) extfield.E4Expr { return x.Square() }, a, ext.E4{}, want)
	}
}

func TestE4MulByBase(t *testing.T) {
	for i := 0; i < 16; i++ {
		a := randE4(t)
		var s koalabear.Element
		if _, err := s.SetRandom(); err != nil {
			t.Fatal(err)
		}
		var want ext.E4
		want.MulByElement(&a, &s)

		builder, tr := constModuleN4()
		mod := builder.Modules["ef"]

		registerE4Constant(t, &builder, tr, "ef", "a", a)
		registerE4Constant(t, &builder, tr, "ef", "e", want)
		fillConst(tr, "s", s, 4)

		got := asE4Expr("a").MulByBase(expr.Col("s"))
		for _, rel := range got.EqualityConstraints(asE4Expr("e")) {
			mod.AssertZero(rel)
		}
		builder.AddModule(*mod)

		testutil.ProveAndVerify(t, &builder, tr)
	}
}

// TestE4MulSanityVector pins the limb-mapping with a small hand-checked case
// so future refactors of FromE4/ToE4 don't silently swap limbs.
func TestE4MulSanityVector(t *testing.T) {
	a := e4FromUint(1, 2, 3, 4)
	b := e4FromUint(5, 6, 7, 8)
	var want ext.E4
	want.Mul(&a, &b)
	proveOp(t, func(x, y extfield.E4Expr) extfield.E4Expr { return x.Mul(y) }, a, b, want)
}

// TestE4MulRejectsCorruption confirms a tampered "expected" trace breaks
// verification — guards against trivial proofs that don't actually constrain
// the operation.
func TestE4MulRejectsCorruption(t *testing.T) {
	a := randE4(t)
	b := randE4(t)
	var corrupted ext.E4
	corrupted.Mul(&a, &b)
	corrupted.B0.A0.SetUint64(uint64(corrupted.B0.A0[0]) + 1) // perturb limb 0

	builder, tr := constModuleN4()
	mod := builder.Modules["ef"]

	registerE4Constant(t, &builder, tr, "ef", "a", a)
	registerE4Constant(t, &builder, tr, "ef", "b", b)
	registerE4Constant(t, &builder, tr, "ef", "e", corrupted)

	got := asE4Expr("a").Mul(asE4Expr("b"))
	for _, rel := range got.EqualityConstraints(asE4Expr("e")) {
		mod.AssertZero(rel)
	}
	builder.AddModule(*mod)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
