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

package bits_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/gadgets/bits"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func TestBitsGadget(t *testing.T) {
	const k = 8
	values := []uint64{0, 1, 2, 3, 100, 200, 255, 17}

	builder := board.NewBuilder()
	cn := bits.BuildModule(&builder, "bits", len(values), k)
	cols := bits.GenerateTrace(cn, len(values), values)

	tr := trace.New()
	for kn, v := range cols {
		tr.SetBase(kn, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestBitsGadgetPadding pads to a capacity larger than the value count.
func TestBitsGadgetPadding(t *testing.T) {
	const k = 4
	values := []uint64{5}

	builder := board.NewBuilder()
	cn := bits.BuildModule(&builder, "bits_pad", 8, k)
	cols := bits.GenerateTrace(cn, 8, values)

	tr := trace.New()
	for kn, v := range cols {
		tr.SetBase(kn, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestBitsGadgetRejectsNonBinaryBit corrupts a bit column to a non-binary
// value; the bit-binary constraint must catch it.
func TestBitsGadgetRejectsNonBinaryBit(t *testing.T) {
	const k = 4
	values := []uint64{5} // = 0101 in binary

	builder := board.NewBuilder()
	cn := bits.BuildModule(&builder, "bits_nonbin", 1, k)
	cols := bits.GenerateTrace(cn, 1, values)

	// Set bit_0 = 3 instead of 1. To keep the sum constraint satisfied (so
	// the failure is isolated to the binary check), also reduce the value by
	// 2 to compensate (3*1 + 0*2 + 1*4 = 7 — but we want value=5, so we'd
	// need to also corrupt value, which then breaks the sum). Just leave
	// value=5 and bit_0=3 — both the binary check (b_0*(1-b_0)) AND the sum
	// will fail, that's fine for a corruption test.
	cols[cn.Bits[0]][0].SetUint64(3)

	tr := trace.New()
	for kn, v := range cols {
		tr.SetBase(kn, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestBitsGadgetRejectsBadSum keeps each bit binary but corrupts the value
// so the decomposition no longer matches.
func TestBitsGadgetRejectsBadSum(t *testing.T) {
	const k = 4
	values := []uint64{5}

	builder := board.NewBuilder()
	cn := bits.BuildModule(&builder, "bits_sum", 1, k)
	cols := bits.GenerateTrace(cn, 1, values)

	// Change value to 6 while keeping bits = decomposition of 5.
	cols[cn.Value][0].SetUint64(6)

	tr := trace.New()
	for kn, v := range cols {
		tr.SetBase(kn, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestBitsRegisterAt exercises the sparse-row variant: the bit
// decomposition is only enforced at one row, and the value column is
// supplied by the caller (rather than allocated by the gadget). The
// off-row positions of the bits and value can hold arbitrary garbage
// without breaking the proof.
func TestBitsRegisterAt(t *testing.T) {
	const k = 8
	const rowIdx = 2
	const valueColName = "sponge.digest_1"

	mod := board.NewModule("bits_at")
	mod.N = 4
	// Identity constraint so the module isn't empty for the prover.
	mod.AssertZero(expr.Col("dummy").Sub(expr.Col("dummy")))

	cn := bits.RegisterAt(&mod, "bits_at", valueColName, k, rowIdx)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	// At rowIdx the value is 173 = 0b10101101 and bits decompose
	// accordingly. Other rows hold garbage on both the value column and
	// the bit columns to verify the constraint is row-gated.
	valueAtRow := uint64(173)
	valCol := make([]koalabear.Element, mod.N)
	valCol[0].SetUint64(99)
	valCol[1].SetUint64(7)
	valCol[2].SetUint64(valueAtRow)
	valCol[3].SetUint64(42)

	tr := trace.New()
	tr.SetBase(valueColName, valCol)
	tr.SetBase("dummy", make([]koalabear.Element, mod.N))

	for i := 0; i < k; i++ {
		col := make([]koalabear.Element, mod.N)
		// Random garbage off-row; bits gadget only checks rowIdx.
		col[0].SetUint64(uint64(i + 7))
		col[1].SetUint64(uint64(i*3 + 1))
		col[3].SetUint64(uint64(i + 100))
		if (valueAtRow>>uint(i))&1 == 1 {
			col[rowIdx].SetOne()
		}
		tr.SetBase(cn.Bits[i], col)
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestBitsRegisterAtRejectsBadBitsAtRow corrupts a bit at the gated
// row; the sparse constraint must catch it.
func TestBitsRegisterAtRejectsBadBitsAtRow(t *testing.T) {
	const k = 4
	const rowIdx = 1
	const valueColName = "sponge.digest_1"

	mod := board.NewModule("bits_at_bad")
	mod.N = 2

	cn := bits.RegisterAt(&mod, "bits_at_bad", valueColName, k, rowIdx)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	valCol := make([]koalabear.Element, mod.N)
	valCol[rowIdx].SetUint64(5) // 0b0101

	tr := trace.New()
	tr.SetBase(valueColName, valCol)

	// Correct decomposition for 5 is bits [1, 0, 1, 0]; flip bit_0 to 0 to
	// break the sum constraint at the gated row.
	for i := 0; i < k; i++ {
		col := make([]koalabear.Element, mod.N)
		tr.SetBase(cn.Bits[i], col)
	}
	col := make([]koalabear.Element, mod.N)
	col[rowIdx].SetUint64(0) // should be 1
	tr.SetBase(cn.Bits[0], col)
	col2 := make([]koalabear.Element, mod.N)
	col2[rowIdx].SetUint64(1)
	tr.SetBase(cn.Bits[2], col2)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestBitsGadgetRoundTrip cross-checks the witness against expected
// bit-patterns before the prover sees the data.
func TestBitsGadgetRoundTrip(t *testing.T) {
	const k = 6
	values := []uint64{63, 32, 1, 17, 42, 0, 7, 15}

	builder := board.NewBuilder()
	cn := bits.BuildModule(&builder, "bits_roundtrip", len(values), k)
	cols := bits.GenerateTrace(cn, len(values), values)

	for row, v := range values {
		var got koalabear.Element
		var two koalabear.Element
		two.SetUint64(2)
		pow := koalabear.One()
		for i := 0; i < k; i++ {
			bit := cols[cn.Bits[i]][row]
			var term koalabear.Element
			term.Mul(&bit, &pow)
			got.Add(&got, &term)
			pow.Mul(&pow, &two)
		}
		var want koalabear.Element
		want.SetUint64(v)
		if !got.Equal(&want) {
			t.Fatalf("row %d: reconstructed %s, want %s", row, got.String(), want.String())
		}
	}

	tr := trace.New()
	for kn, v := range cols {
		tr.SetBase(kn, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}
