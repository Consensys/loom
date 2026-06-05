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

package airzeta_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/dag"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/airzeta"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randExt() ext.E6 {
	var v ext.E6
	v.MustSetRandom()
	return v
}

// runDAGTest builds a 4-row module with leaf-value columns wired to the
// gadget output, then proves+verifies that the gadget's E6Expr evaluates
// to the same value the native dag.EvalExt does. The proof passes only
// if the in-circuit walk matches the native walk on every limb.
func runDAGTest(t *testing.T, name string, relation expr.Expr, vals map[string]ext.E6) {
	t.Helper()

	d := dag.ExprToDAG(relation)

	// Native expected value at zeta.
	want := d.EvalExt(vals)

	mod := board.NewModule(name)
	mod.N = 4

	// For each leaf, allocate 6 base columns holding its E6 value and
	// build an extfield.E6Expr referencing those columns. Also allocate
	// 6 base columns for the expected output and assert equality.
	leafValues := make(map[string]extfield.E6Expr, len(vals))
	cols := make(map[string][]koalabear.Element)
	allocCol := func(col string, v koalabear.Element) {
		c := make([]koalabear.Element, mod.N)
		for i := range c {
			c[i].Set(&v)
		}
		cols[col] = c
	}
	for leafName, val := range vals {
		limbs := extfield.FromE6(val)
		var leafCols [extfield.Limbs]string
		for i := 0; i < extfield.Limbs; i++ {
			c := name + "." + leafName + "_" + string('0'+rune(i))
			leafCols[i] = c
			allocCol(c, limbs[i])
		}
		leafValues[leafName] = extfield.FromLimbs(
			expr.Col(leafCols[0]), expr.Col(leafCols[1]),
			expr.Col(leafCols[2]), expr.Col(leafCols[3]),
			expr.Col(leafCols[4]), expr.Col(leafCols[5]),
		)
	}

	gadgetExpr := airzeta.EvalDAG(d, leafValues)

	wantLimbs := extfield.FromE6(want)
	for i := 0; i < extfield.Limbs; i++ {
		c := name + ".want_" + string('0'+rune(i))
		allocCol(c, wantLimbs[i])
		mod.AssertZero(gadgetExpr.Limb[i].Sub(expr.Col(c)))
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestEvalDAGLeafIdentity covers the simplest DAG: a single leaf.
func TestEvalDAGLeafIdentity(t *testing.T) {
	rel := expr.Col("A")
	vals := map[string]ext.E6{"A": randExt()}
	runDAGTest(t, "leaf", rel, vals)
}

// TestEvalDAGAddSubMul covers Add/Sub/Mul combinations.
func TestEvalDAGAddSubMul(t *testing.T) {
	// (A + B) * (C - A)
	rel := expr.Col("A").Add(expr.Col("B")).Mul(expr.Col("C").Sub(expr.Col("A")))
	vals := map[string]ext.E6{
		"A": randExt(),
		"B": randExt(),
		"C": randExt(),
	}
	runDAGTest(t, "addsubmul", rel, vals)
}

// TestEvalDAGPow exercises the Pow node (square-and-multiply).
func TestEvalDAGPow(t *testing.T) {
	rel := expr.Col("X").Pow(5).Sub(expr.Col("Y"))
	vals := map[string]ext.E6{
		"X": randExt(),
		"Y": randExt(),
	}
	// Compute the native expected; XX is X^5, so we set Y = X^5 + perturbation
	// — but for this test we just want gadget == native, regardless of vals.
	runDAGTest(t, "pow", rel, vals)
}

// TestEvalDAGFibonacciStyle uses a Fibonacci-like constraint to exercise
// a realistic DAG shape with constants.
func TestEvalDAGFibonacciStyle(t *testing.T) {
	// C - A - B (the standard Fibonacci recurrence relation per row)
	rel := expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B"))
	vals := map[string]ext.E6{
		"A": randExt(),
		"B": randExt(),
		"C": randExt(),
	}
	runDAGTest(t, "fibo", rel, vals)
}

// TestEvalDAGConstants covers DAG paths through constants.
func TestEvalDAGConstants(t *testing.T) {
	var seven koalabear.Element
	seven.SetUint64(7)
	rel := expr.Col("X").Mul(expr.Const(seven)).Add(expr.Col("Y"))
	vals := map[string]ext.E6{
		"X": randExt(),
		"Y": randExt(),
	}
	runDAGTest(t, "consts", rel, vals)
}

// TestAIRCheckHappyPath constructs synthetic values that satisfy
// V(zeta) == (zeta^N - 1) * Q(zeta) and proves the gadget accepts
// them. Uses a trivial DAG V = X so we can freely choose X to match.
func TestAIRCheckHappyPath(t *testing.T) {
	const N = 8
	zeta := randExt()
	chunkVals := []ext.E6{randExt(), randExt(), randExt()}

	// Compute target V = (zeta^N - 1) * sum_i chunks[i] * (zeta^N)^i
	var zetaN ext.E6
	zetaN.Set(&zeta)
	for i := 1; i < N; i++ {
		zetaN.Mul(&zetaN, &zeta)
	}
	var zetaNm1 ext.E6
	var one ext.E6
	one.SetOne()
	zetaNm1.Sub(&zetaN, &one)
	var qZeta ext.E6
	qZeta.Set(&chunkVals[0])
	var zetaPowIN ext.E6
	zetaPowIN.Set(&zetaN)
	for i := 1; i < len(chunkVals); i++ {
		var term ext.E6
		term.Mul(&chunkVals[i], &zetaPowIN)
		qZeta.Add(&qZeta, &term)
		if i+1 < len(chunkVals) {
			zetaPowIN.Mul(&zetaPowIN, &zetaN)
		}
	}
	var V ext.E6
	V.Mul(&zetaNm1, &qZeta)

	rel := expr.Col("X")
	d := dag.ExprToDAG(rel)

	mod := board.NewModule("aircheck")
	mod.N = 4

	cols := make(map[string][]koalabear.Element)
	allocAndFill := func(name string, v koalabear.Element) {
		c := make([]koalabear.Element, mod.N)
		for i := range c {
			c[i].Set(&v)
		}
		cols[name] = c
	}
	makeE6Expr := func(prefix string, v ext.E6) extfield.E6Expr {
		limbs := extfield.FromE6(v)
		names := [6]string{
			prefix + "_0", prefix + "_1", prefix + "_2", prefix + "_3", prefix + "_4", prefix + "_5",
		}
		for i := 0; i < extfield.Limbs; i++ {
			allocAndFill(names[i], limbs[i])
		}
		return extfield.FromLimbs(
			expr.Col(names[0]), expr.Col(names[1]),
			expr.Col(names[2]), expr.Col(names[3]),
			expr.Col(names[4]), expr.Col(names[5]),
		)
	}

	leafValues := map[string]extfield.E6Expr{
		"X": makeE6Expr("X", V),
	}
	zetaExpr := makeE6Expr("zeta", zeta)
	chunks := make([]extfield.E6Expr, len(chunkVals))
	for i, c := range chunkVals {
		chunks[i] = makeE6Expr("chunk_"+string('0'+rune(i)), c)
	}

	airzeta.RegisterAIRCheck(&mod, d, N, leafValues, zetaExpr, chunks)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestAIRCheckRejectsBadV tampers V (sets X to a non-matching value)
// and expects the equality constraint to fail.
func TestAIRCheckRejectsBadV(t *testing.T) {
	const N = 4
	zeta := randExt()
	chunks := []ext.E6{randExt()}

	rel := expr.Col("X")
	d := dag.ExprToDAG(rel)

	mod := board.NewModule("aircheck_bad")
	mod.N = 4

	cols := make(map[string][]koalabear.Element)
	allocAndFill := func(name string, v koalabear.Element) {
		c := make([]koalabear.Element, mod.N)
		for i := range c {
			c[i].Set(&v)
		}
		cols[name] = c
	}
	makeE6Expr := func(prefix string, v ext.E6) extfield.E6Expr {
		limbs := extfield.FromE6(v)
		names := [6]string{
			prefix + "_0", prefix + "_1", prefix + "_2", prefix + "_3", prefix + "_4", prefix + "_5",
		}
		for i := 0; i < extfield.Limbs; i++ {
			allocAndFill(names[i], limbs[i])
		}
		return extfield.FromLimbs(
			expr.Col(names[0]), expr.Col(names[1]),
			expr.Col(names[2]), expr.Col(names[3]),
			expr.Col(names[4]), expr.Col(names[5]),
		)
	}

	// Set X to a random value that does NOT match (zeta^N - 1) * Q.
	leafValues := map[string]extfield.E6Expr{
		"X": makeE6Expr("X", randExt()),
	}
	zetaExpr := makeE6Expr("zeta", zeta)
	chunkExprs := []extfield.E6Expr{makeE6Expr("chunk", chunks[0])}

	airzeta.RegisterAIRCheck(&mod, d, N, leafValues, zetaExpr, chunkExprs)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestPowExtMatchesNative cross-checks PowExt for several small exponents.
// Larger exponents (e.g. 64+) work but are slow under the current
// expression-blowup; if production needs zeta^N for N ~ 1024, PowExt
// will need to materialize intermediate witness columns.
func TestPowExtMatchesNative(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 5, 8, 13, 16} {
		base := randExt()
		var want ext.E6
		want.SetOne()
		var baseCopy ext.E6
		baseCopy.Set(&base)
		// Square-and-multiply on the native side.
		expN := n
		for expN > 0 {
			if expN&1 == 1 {
				want.Mul(&want, &baseCopy)
			}
			baseCopy.Mul(&baseCopy, &baseCopy)
			expN >>= 1
		}
		_ = big.NewInt // satisfies import expectations if I later need it

		mod := board.NewModule("powext")
		mod.N = 4

		baseLimbs := extfield.FromE6(base)
		var baseCols [extfield.Limbs]string
		cols := make(map[string][]koalabear.Element)
		for i := 0; i < extfield.Limbs; i++ {
			baseCols[i] = "powext.base_" + string('0'+rune(i))
			c := make([]koalabear.Element, mod.N)
			for r := range c {
				c[r].Set(&baseLimbs[i])
			}
			cols[baseCols[i]] = c
		}
		baseExpr := extfield.FromLimbs(
			expr.Col(baseCols[0]), expr.Col(baseCols[1]),
			expr.Col(baseCols[2]), expr.Col(baseCols[3]),
			expr.Col(baseCols[4]), expr.Col(baseCols[5]),
		)

		gadgetExpr := airzeta.PowExt(baseExpr, n)

		wantLimbs := extfield.FromE6(want)
		for i := 0; i < extfield.Limbs; i++ {
			c := "powext.want_" + string('0'+rune(i))
			col := make([]koalabear.Element, mod.N)
			for r := range col {
				col[r].Set(&wantLimbs[i])
			}
			cols[c] = col
			mod.AssertZero(gadgetExpr.Limb[i].Sub(expr.Col(c)))
		}

		builder := board.NewBuilder()
		builder.AddModule(mod)

		tr := trace.New()
		for k, v := range cols {
			tr.SetBase(k, v)
		}
		testutil.ProveAndVerify(t, &builder, tr)
	}
}
