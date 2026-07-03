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

package frifold_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/frifold"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randomExt(t *testing.T) ext.E6 {
	t.Helper()
	var v ext.E6
	v.MustSetRandom()
	return v
}

func randomBase(t *testing.T) koalabear.Element {
	t.Helper()
	var v koalabear.Element
	v.MustSetRandom()
	return v
}

// nativeFoldExtSinglePosition computes the per-position fold formula directly,
// without relying on internal/fri internals — so the test is self-contained.
//
//	folded = (P+Q)/2 + alpha * (P-Q)/(2 * omega^base)
func nativeFoldExtSinglePosition(p, q, alpha ext.E6, xInv koalabear.Element) ext.E6 {
	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)

	var sum, diff, scaled, out ext.E6
	sum.Add(&p, &q)
	sum.MulByElement(&sum, &invTwo)

	diff.Sub(&p, &q)
	diff.MulByElement(&diff, &invTwo)
	diff.MulByElement(&diff, &xInv)
	scaled.Mul(&diff, &alpha)

	out.Add(&sum, &scaled)
	return out
}

// TestExtFoldGadgetMatchesNative runs many random ext-rail folds through the
// gadget and confirms each one produces the same value as the standalone
// per-position fold formula.
func TestExtFoldGadgetMatchesNative(t *testing.T) {
	const nFolds = 8
	folds := make([]frifold.ExtFold, nFolds)
	for i := 0; i < nFolds; i++ {
		folds[i] = frifold.ExtFold{
			P:     randomExt(t),
			Q:     randomExt(t),
			Alpha: randomExt(t),
			XInv:  randomBase(t),
		}
		want := nativeFoldExtSinglePosition(folds[i].P, folds[i].Q, folds[i].Alpha, folds[i].XInv)
		got := folds[i].Folded()
		if !got.Equal(&want) {
			t.Fatalf("ExtFold.Folded mismatch row=%d", i)
		}
	}

	builder := board.NewBuilder()
	cn := frifold.BuildExtModule(&builder, "frifold_ext", nFolds)
	cols := frifold.GenerateExtTrace(cn, nFolds, folds)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestExtFoldGadgetXInvFromDomain pins the meaning of xInv against a real
// FRI fold computation pattern: xInv at position base is omega^{-base},
// computed from the level-j fft.Domain's GeneratorInv.
func TestExtFoldGadgetXInvFromDomain(t *testing.T) {
	const cardinality = 16
	domain := fft.NewDomain(cardinality)

	// Choose base = 5 (any 0 <= base < cardinality/2).
	const base = 5
	var xInv koalabear.Element
	xInv.Exp(domain.GeneratorInv, big.NewInt(base))

	f := frifold.ExtFold{
		P:     randomExt(t),
		Q:     randomExt(t),
		Alpha: randomExt(t),
		XInv:  xInv,
	}

	// Sanity-check: the same xInv equals omega^{Nj - base} since omega^Nj == 1.
	var alt koalabear.Element
	alt.Exp(domain.Generator, big.NewInt(int64(cardinality-base)))
	if !alt.Equal(&xInv) {
		t.Fatalf("xInv parity check failed: omega^(N-base) != omega^{-base}")
	}

	builder := board.NewBuilder()
	cn := frifold.BuildExtModule(&builder, "frifold_ext_dom", 1)
	cols := frifold.GenerateExtTrace(cn, 1, []frifold.ExtFold{f})

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestExtFoldGadgetRejectsCorruption flips a limb of the folded output and
// confirms verification fails.
func TestExtFoldGadgetRejectsCorruption(t *testing.T) {
	folds := []frifold.ExtFold{
		{P: randomExt(t), Q: randomExt(t), Alpha: randomExt(t), XInv: randomBase(t)},
	}

	builder := board.NewBuilder()
	cn := frifold.BuildExtModule(&builder, "frifold_ext_corrupt", 1)
	cols := frifold.GenerateExtTrace(cn, 1, folds)

	// Flip folded[0] by adding 1.
	col := cols[cn.Folded[0]]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestExtFoldGadgetWithPadding confirms padding rows (where P=Q=alpha=0,
// xInv=1, folded=0) satisfy the constraint.
func TestExtFoldGadgetWithPadding(t *testing.T) {
	folds := []frifold.ExtFold{
		{P: randomExt(t), Q: randomExt(t), Alpha: randomExt(t), XInv: randomBase(t)},
	}
	builder := board.NewBuilder()
	cn := frifold.BuildExtModule(&builder, "frifold_ext_pad", 4) // capacity 4, only 1 real fold
	cols := frifold.GenerateExtTrace(cn, 4, folds)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// ── Base-rail tests ──────────────────────────────────────────────────────────

func TestBaseFoldGadget(t *testing.T) {
	const nFolds = 8
	folds := make([]frifold.BaseFold, nFolds)
	for i := 0; i < nFolds; i++ {
		folds[i] = frifold.BaseFold{
			P:     randomBase(t),
			Q:     randomBase(t),
			Alpha: randomBase(t),
			XInv:  randomBase(t),
		}
	}

	builder := board.NewBuilder()
	cn := frifold.BuildBaseModule(&builder, "frifold_base", nFolds)
	cols := frifold.GenerateBaseTrace(cn, nFolds, folds)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

func TestBaseFoldGadgetRejectsCorruption(t *testing.T) {
	folds := []frifold.BaseFold{
		{P: randomBase(t), Q: randomBase(t), Alpha: randomBase(t), XInv: randomBase(t)},
	}
	builder := board.NewBuilder()
	cn := frifold.BuildBaseModule(&builder, "frifold_base_corrupt", 1)
	cols := frifold.GenerateBaseTrace(cn, 1, folds)

	col := cols[cn.Folded]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
