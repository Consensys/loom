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

package poly

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestPowUint64(t *testing.T) {
	var base koalabear.Element
	base.SetUint64(7)

	// Exponents covering edge cases: zero, one, small, larger, and 64-bit-ish.
	exps := []uint64{0, 1, 2, 3, 5, 17, 64, 1023, 1 << 20, (1 << 31) - 1}
	for _, e := range exps {
		got := PowUint64(base, e)
		var want koalabear.Element
		want.Exp(base, new(big.Int).SetUint64(e))
		if !got.Equal(&want) {
			t.Errorf("PowUint64(7, %d) = %s, want %s", e, got.String(), want.String())
		}
	}
}

func TestPowUint64_ZeroBase(t *testing.T) {
	var zero koalabear.Element
	// 0^0 = 1 (by convention), 0^k = 0 for k > 0.
	if got := PowUint64(zero, 0); !got.IsOne() {
		t.Errorf("PowUint64(0, 0) = %s, want 1", got.String())
	}
	if got := PowUint64(zero, 5); !got.IsZero() {
		t.Errorf("PowUint64(0, 5) = %s, want 0", got.String())
	}
}

func TestPowUint64_OneBase(t *testing.T) {
	one := koalabear.One()
	for _, e := range []uint64{0, 1, 7, 1 << 30} {
		got := PowUint64(one, e)
		if !got.IsOne() {
			t.Errorf("PowUint64(1, %d) = %s, want 1", e, got.String())
		}
	}
}

func TestPowUint64_MatchesRepeatedMul(t *testing.T) {
	var base koalabear.Element
	base.SetUint64(0x12345)

	var acc koalabear.Element
	acc.SetOne()
	for i := uint64(0); i < 100; i++ {
		got := PowUint64(base, i)
		if !got.Equal(&acc) {
			t.Errorf("PowUint64(base, %d) diverges from repeated mul: got %s want %s", i, got.String(), acc.String())
		}
		acc.Mul(&acc, &base)
	}
}
