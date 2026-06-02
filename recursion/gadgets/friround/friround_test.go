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

package friround_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/friround"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randomExt(t *testing.T) ext.E6 {
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

// roundDomainParams returns (omegaInv, kBits) for a FRI round whose
// half-domain size is halfNj (so base in [0, halfNj)).
func roundDomainParams(halfNj uint64) (koalabear.Element, int) {
	// Domain at this round has cardinality 2*halfNj.
	domain := fft.NewDomain(2 * halfNj)
	omegaInv := domain.GeneratorInv
	k := 0
	for v := halfNj; v > 0; v >>= 1 {
		k++
	}
	if halfNj > 0 && halfNj&(halfNj-1) == 0 {
		k-- // halfNj is a power of two; need log2(halfNj) bits to index [0, halfNj)
	}
	if k == 0 {
		k = 1
	}
	return omegaInv, k
}

// TestFriRoundGadgetBasic runs a single round verification across 8 queries
// with a 32-element half-domain (so kBits = 5).
func TestFriRoundGadgetBasic(t *testing.T) {
	const halfNj = 32
	omegaInv, kBits := roundDomainParams(halfNj)
	if kBits != 5 {
		t.Fatalf("expected kBits=5, got %d", kBits)
	}

	queries := make([]friround.Query, 8)
	bases := []uint64{0, 1, 5, 17, 31, 13, 2, 30}
	alpha := randomExt(t)
	for i := range queries {
		queries[i] = friround.Query{
			P:     randomExt(t),
			Q:     randomExt(t),
			Alpha: alpha,
			Base:  bases[i],
		}
	}

	builder := board.NewBuilder()
	cn := friround.BuildModule(&builder, "round", len(queries), omegaInv, kBits)
	cols := friround.GenerateTrace(cn, len(queries), queries)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestFriRoundGadgetMatchesNative cross-checks the gadget's computed
// expected against a direct fold formula using omega^{-base}.
func TestFriRoundGadgetMatchesNative(t *testing.T) {
	const halfNj = 8
	omegaInv, kBits := roundDomainParams(halfNj)

	q := friround.Query{
		P:     randomExt(t),
		Q:     randomExt(t),
		Alpha: randomExt(t),
		Base:  3,
	}

	// Native formula.
	var xInv koalabear.Element
	xInv.Exp(omegaInv, big.NewInt(int64(q.Base)))
	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)
	var sum, diff, scaled, expected ext.E6
	sum.Add(&q.P, &q.Q)
	sum.MulByElement(&sum, &invTwo)
	diff.Sub(&q.P, &q.Q)
	diff.MulByElement(&diff, &invTwo)
	diff.MulByElement(&diff, &xInv)
	scaled.Mul(&diff, &q.Alpha)
	expected.Add(&sum, &scaled)

	got := q.Folded(omegaInv)
	if !got.Equal(&expected) {
		t.Fatalf("native vs gadget Folded mismatch")
	}

	builder := board.NewBuilder()
	cn := friround.BuildModule(&builder, "round_match", 1, omegaInv, kBits)
	cols := friround.GenerateTrace(cn, 1, []friround.Query{q})

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestFriRoundGadgetRejectsCorruptBase tampers with the base column (so
// bits no longer match value) and confirms rejection. This exercises the
// bit decomposition constraint inside friround.
func TestFriRoundGadgetRejectsCorruptBase(t *testing.T) {
	const halfNj = 16
	omegaInv, kBits := roundDomainParams(halfNj)

	q := friround.Query{
		P: randomExt(t), Q: randomExt(t), Alpha: randomExt(t), Base: 7,
	}

	builder := board.NewBuilder()
	cn := friround.BuildModule(&builder, "round_corrupt", 1, omegaInv, kBits)
	cols := friround.GenerateTrace(cn, 1, []friround.Query{q})

	// Change `base` value column without updating bits — the sum check breaks.
	cols[cn.Bits.Value][0].SetUint64(9)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestFriRoundGadgetRejectsVaryingAlpha confirms the new alpha-pinning
// constraint rejects a witness where alpha differs between rows. The
// fold equation would still hold on each row in isolation; pinning
// catches the cross-row inconsistency.
func TestFriRoundGadgetRejectsVaryingAlpha(t *testing.T) {
	const halfNj = 16
	omegaInv, kBits := roundDomainParams(halfNj)

	q1 := friround.Query{P: randomExt(t), Q: randomExt(t), Alpha: randomExt(t), Base: 1}
	q2 := friround.Query{P: randomExt(t), Q: randomExt(t), Alpha: randomExt(t), Base: 2}

	builder := board.NewBuilder()
	cn := friround.BuildModule(&builder, "round_alpha", 2, omegaInv, kBits)
	cols := friround.GenerateTrace(cn, 2, []friround.Query{q1, q2})

	// q1.Alpha != q2.Alpha (overwhelmingly likely for random samples), so
	// the alpha columns already differ row-to-row. The trace remains
	// self-consistent on each row (each row's expected matches its own
	// fold formula), but the pinning constraint detects the mismatch.

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestFriRoundGadgetRejectsCorruptXInv tampers with one binexp step,
// breaking the xInv derivation chain and hence the fold equation.
func TestFriRoundGadgetRejectsCorruptXInv(t *testing.T) {
	const halfNj = 16
	omegaInv, kBits := roundDomainParams(halfNj)

	q := friround.Query{
		P: randomExt(t), Q: randomExt(t), Alpha: randomExt(t), Base: 5,
	}

	builder := board.NewBuilder()
	cn := friround.BuildModule(&builder, "round_xinv", 1, omegaInv, kBits)
	cols := friround.GenerateTrace(cn, 1, []friround.Query{q})

	// Corrupt the final binexp step (= xInv).
	var one koalabear.Element
	one.SetOne()
	cols[cn.XInvColName()][0].Add(&cols[cn.XInvColName()][0], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
