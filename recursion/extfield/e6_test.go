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

// e6FromUint builds an E6 from six uint64s (small test values).
func e6FromUint(a, b, c, d, e, f uint64) ext.E6 {
	var v ext.E6
	v.B0.A0.SetUint64(a)
	v.B0.A1.SetUint64(b)
	v.B1.A0.SetUint64(c)
	v.B1.A1.SetUint64(d)
	v.B2.A0.SetUint64(e)
	v.B2.A1.SetUint64(f)
	return v
}

func randE6(t *testing.T) ext.E6 {
	t.Helper()
	var v ext.E6
	for _, p := range []*koalabear.Element{&v.B0.A0, &v.B0.A1, &v.B1.A0, &v.B1.A1, &v.B2.A0, &v.B2.A1} {
		if _, err := p.SetRandom(); err != nil {
			t.Fatalf("rand: %v", err)
		}
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

// asE6Expr wraps six committed base columns into an E6Expr.
func asE6Expr(prefix string) extfield.E6Expr {
	return extfield.FromLimbs(
		expr.Col(prefix+"_0"),
		expr.Col(prefix+"_1"),
		expr.Col(prefix+"_2"),
		expr.Col(prefix+"_3"),
		expr.Col(prefix+"_4"),
		expr.Col(prefix+"_5"),
	)
}

func registerE6Constant(t *testing.T, builder *board.Builder, tr trace.Trace, modName, prefix string, v ext.E6) {
	t.Helper()
	mod := builder.Modules[modName]
	limbs := extfield.FromE6(v)
	for i, l := range limbs {
		name := prefix + "_" + string('0'+rune(i))
		_ = mod
		fillConst(tr, name, l, builder.Modules[modName].N)
	}
}

// proveOp builds a module asserting expected == op(a,b) and runs through the
// prover/verifier. It uses constant columns (same value at every row) since
// AssertZero must hold at every row of the module domain.
func proveOp(t *testing.T, op func(a, b extfield.E6Expr) extfield.E6Expr, a, b, expected ext.E6) {
	t.Helper()
	builder, tr := constModuleN4()
	mod := builder.Modules["ef"]

	registerE6Constant(t, &builder, tr, "ef", "a", a)
	registerE6Constant(t, &builder, tr, "ef", "b", b)
	registerE6Constant(t, &builder, tr, "ef", "e", expected)

	got := op(asE6Expr("a"), asE6Expr("b"))
	for _, rel := range got.EqualityConstraints(asE6Expr("e")) {
		mod.AssertZero(rel)
	}
	builder.AddModule(*mod)

	testutil.ProveAndVerify(t, &builder, tr)
}

func TestE6Add(t *testing.T) {
	for i := 0; i < 32; i++ {
		a := randE6(t)
		b := randE6(t)
		var want ext.E6
		want.Add(&a, &b)
		proveOp(t, func(x, y extfield.E6Expr) extfield.E6Expr { return x.Add(y) }, a, b, want)
	}
}

func TestE6Sub(t *testing.T) {
	for i := 0; i < 32; i++ {
		a := randE6(t)
		b := randE6(t)
		var want ext.E6
		want.Sub(&a, &b)
		proveOp(t, func(x, y extfield.E6Expr) extfield.E6Expr { return x.Sub(y) }, a, b, want)
	}
}

func TestE6Mul(t *testing.T) {
	for i := 0; i < 32; i++ {
		a := randE6(t)
		b := randE6(t)
		var want ext.E6
		want.Mul(&a, &b)
		proveOp(t, func(x, y extfield.E6Expr) extfield.E6Expr { return x.Mul(y) }, a, b, want)
	}
}

func TestE6Square(t *testing.T) {
	for i := 0; i < 16; i++ {
		a := randE6(t)
		var want ext.E6
		want.Square(&a)
		proveOp(t, func(x, _ extfield.E6Expr) extfield.E6Expr { return x.Square() }, a, ext.E6{}, want)
	}
}

func TestE6MulByBase(t *testing.T) {
	for i := 0; i < 16; i++ {
		a := randE6(t)
		var s koalabear.Element
		if _, err := s.SetRandom(); err != nil {
			t.Fatal(err)
		}
		var want ext.E6
		want.MulByElement(&a, &s)

		builder, tr := constModuleN4()
		mod := builder.Modules["ef"]

		registerE6Constant(t, &builder, tr, "ef", "a", a)
		registerE6Constant(t, &builder, tr, "ef", "e", want)
		fillConst(tr, "s", s, 4)

		got := asE6Expr("a").MulByBase(expr.Col("s"))
		for _, rel := range got.EqualityConstraints(asE6Expr("e")) {
			mod.AssertZero(rel)
		}
		builder.AddModule(*mod)

		testutil.ProveAndVerify(t, &builder, tr)
	}
}

// TestE6MulSanityVector pins the limb-mapping with a small hand-checked case
// so future refactors of FromE6/ToE6 don't silently swap limbs.
func TestE6MulSanityVector(t *testing.T) {
	a := e6FromUint(1, 2, 3, 4, 5, 6)
	b := e6FromUint(7, 8, 9, 10, 11, 12)
	var want ext.E6
	want.Mul(&a, &b)
	proveOp(t, func(x, y extfield.E6Expr) extfield.E6Expr { return x.Mul(y) }, a, b, want)
}

// TestE6MulRejectsCorruption confirms a tampered "expected" trace breaks
// verification — guards against trivial proofs that don't actually constrain
// the operation.
func TestE6MulRejectsCorruption(t *testing.T) {
	a := randE6(t)
	b := randE6(t)
	var corrupted ext.E6
	corrupted.Mul(&a, &b)
	corrupted.B0.A0.SetUint64(uint64(corrupted.B0.A0[0]) + 1) // perturb limb 0

	builder, tr := constModuleN4()
	mod := builder.Modules["ef"]

	registerE6Constant(t, &builder, tr, "ef", "a", a)
	registerE6Constant(t, &builder, tr, "ef", "b", b)
	registerE6Constant(t, &builder, tr, "ef", "e", corrupted)

	got := asE6Expr("a").Mul(asE6Expr("b"))
	for _, rel := range got.EqualityConstraints(asE6Expr("e")) {
		mod.AssertZero(rel)
	}
	builder.AddModule(*mod)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
