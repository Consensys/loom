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

package binexp_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/binexp"
	"github.com/consensys/loom/recursion/gadgets/bits"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

// nextPow2 returns the smallest power of 2 >= n.
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

// TestBinExpGadgetXInvFromBase composes bits + binexp in one module to
// compute xInv = omega^{-base} for several `base` values, cross-checked
// against a direct gnark-crypto Exp call.
func TestBinExpGadgetXInvFromBase(t *testing.T) {
	const k = 5 // 2^5 = 32 possible base values
	bases := []uint64{0, 1, 2, 7, 13, 31, 20, 17}

	domain := fft.NewDomain(1 << uint(k+1)) // larger than 2^k
	omegaInv := domain.GeneratorInv

	n := nextPow2(len(bases))

	// Build a single module containing both bits and binexp constraints.
	mod := board.NewModule("xinv")
	mod.N = n
	bitsCN := bits.Register(&mod, "idx", k)
	expCN := binexp.Register(&mod, "xinv_val", omegaInv, bitsCN)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	// Generate the bits trace (which also writes the value column).
	bitsCols := bits.GenerateTrace(bitsCN, len(bases), bases)

	// Build the per-row bit slices for the binexp trace generator.
	bitRows := make([][]uint64, n)
	for row := 0; row < n; row++ {
		bitRows[row] = make([]uint64, k)
		if row < len(bases) {
			b := bases[row]
			for i := 0; i < k; i++ {
				bitRows[row][i] = (b >> uint(i)) & 1
			}
		}
	}
	expCols := binexp.GenerateTraceFor(expCN, bitRows)

	// Cross-check the final result against omegaInv^base.
	for row := 0; row < len(bases); row++ {
		var want koalabear.Element
		want.Exp(omegaInv, big.NewInt(int64(bases[row])))
		got := expCols[expCN.Result()][row]
		if !got.Equal(&want) {
			t.Fatalf("row %d (base=%d): got %s, want %s", row, bases[row], got.String(), want.String())
		}
	}

	tr := trace.New()
	for kn, v := range bitsCols {
		tr.SetBase(kn, v)
	}
	for kn, v := range expCols {
		tr.SetBase(kn, v)
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestBinExpGadgetRejectsCorruption flips the final result and expects the
// chain to break.
func TestBinExpGadgetRejectsCorruption(t *testing.T) {
	const k = 4
	bases := []uint64{5}
	domain := fft.NewDomain(1 << uint(k+1))
	omegaInv := domain.GeneratorInv

	mod := board.NewModule("xinv_corrupt")
	mod.N = nextPow2(len(bases))
	bitsCN := bits.Register(&mod, "idx", k)
	expCN := binexp.Register(&mod, "xinv_val", omegaInv, bitsCN)
	builder := board.NewBuilder()
	builder.AddModule(mod)

	bitsCols := bits.GenerateTrace(bitsCN, len(bases), bases)
	bitRows := [][]uint64{{1, 0, 1, 0}} // = 5
	expCols := binexp.GenerateTraceFor(expCN, bitRows)

	// Corrupt the final step.
	var one koalabear.Element
	one.SetOne()
	expCols[expCN.Result()][0].Add(&expCols[expCN.Result()][0], &one)

	tr := trace.New()
	for kn, v := range bitsCols {
		tr.SetBase(kn, v)
	}
	for kn, v := range expCols {
		tr.SetBase(kn, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestBinExpGadgetEdgeBase0 verifies result == 1 when base = 0 (all bits
// zero). This is the canonical xInv at FRI query position 0.
func TestBinExpGadgetEdgeBase0(t *testing.T) {
	const k = 4
	bases := []uint64{0}
	domain := fft.NewDomain(1 << uint(k+1))
	omegaInv := domain.GeneratorInv

	mod := board.NewModule("xinv_zero")
	mod.N = nextPow2(len(bases))
	bitsCN := bits.Register(&mod, "idx", k)
	expCN := binexp.Register(&mod, "xinv_val", omegaInv, bitsCN)
	builder := board.NewBuilder()
	builder.AddModule(mod)

	bitsCols := bits.GenerateTrace(bitsCN, len(bases), bases)
	bitRows := [][]uint64{{0, 0, 0, 0}}
	expCols := binexp.GenerateTraceFor(expCN, bitRows)

	tr := trace.New()
	for kn, v := range bitsCols {
		tr.SetBase(kn, v)
	}
	for kn, v := range expCols {
		tr.SetBase(kn, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)

	// Cross-check.
	var one koalabear.Element
	one.SetOne()
	if !expCols[expCN.Result()][0].Equal(&one) {
		t.Fatalf("expected xInv at base=0 to be 1, got %s", expCols[expCN.Result()][0].String())
	}
}
