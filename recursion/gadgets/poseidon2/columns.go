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

// Package poseidon2 implements an in-circuit gadget for the width-16
// Koalabear Poseidon2 permutation used by Loom's Merkle-Damgard hasher.
//
// One row of the gadget module computes one full Poseidon2 permutation. The
// witness columns are:
//
//   - in_0..in_15        : input state
//   - r{R}_sbox_{i}      : value of (prev_state[i] + RC)^3 after the S-box
//                          (full rounds: i in 0..15; partial rounds: i = 0 only)
//   - r{R}_post_0..15    : state after the linear layer of round R
//
// The constraints for round R relate r{R}_sbox and r{R}_post to either in
// (for R == 0) or r{R-1}_post (for R > 0); see constraints.go for details.
//
// The output of the permutation is r{LastRound}_post_*.
//
// Padded rows: the module size N must be a power of two and may exceed the
// number of permutations actually used. The padding rows can be set to any
// self-consistent permutation; trace.go pads with Permutation([0]*16).
package poseidon2

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/internal/hash"
)

// Width, FullRounds, PartialRounds mirror the native Poseidon2 parameters in
// /internal/hash so that the gadget and the native hasher always use the same
// round counts. They are kept as package-level constants so other gadgets
// (Merkle, Challenger) can pin to them.
const (
	Width          = hash.WIDTH
	NbFullRounds   = hash.NB_FULL_ROUND   // total full rounds (split evenly head/tail)
	NbPartialRound = hash.NB_PARTIAL_ROUNDS
)

// NbRounds is the total number of rounds in the gadget — i.e. the number of
// (sbox, post) snapshot pairs per permutation.
const NbRounds = NbFullRounds + NbPartialRound

// RfHead is the number of full rounds before the partial rounds (rf/2 in
// native code).
const RfHead = NbFullRounds / 2

// PartialEnd is the round index (exclusive) of the last partial round.
const PartialEnd = RfHead + NbPartialRound

// Params returns a fresh native Poseidon2 parameters object, used for round
// constants in BuildModule and for reference traces in GenerateTrace. Loom's
// native Poseidon2 (internal/hash) is built from the same NewParameters seed,
// so the round keys are identical.
func Params() *poseidon2.Parameters {
	return poseidon2.NewParameters(Width, NbFullRounds, NbPartialRound)
}

// InColName returns the witness column name for input limb i (0..Width-1).
func InColName(name string, i int) string {
	return fmt.Sprintf("%s.in_%d", name, i)
}

// SBoxColName returns the witness column name for the cubed value at round r,
// position i. For full rounds, i ranges over 0..Width-1; for partial rounds,
// only i == 0 is a witness (other lanes pass straight through prev_post).
func SBoxColName(name string, r, i int) string {
	return fmt.Sprintf("%s.r%02d_sbox_%d", name, r, i)
}

// PostColName returns the witness column name for the state after the linear
// layer of round r, at position i (0..Width-1).
func PostColName(name string, r, i int) string {
	return fmt.Sprintf("%s.r%02d_post_%d", name, r, i)
}

// OutColName returns the column that holds the permutation output at lane i —
// it is the post column of the last round.
func OutColName(name string, i int) string {
	return PostColName(name, NbRounds-1, i)
}

// IsFullRound reports whether round r uses a full S-box layer.
func IsFullRound(r int) bool {
	return r < RfHead || r >= PartialEnd
}

// internalDiag returns the diagonal vector D such that the internal matrix is
// J + diag(D) (all-ones plus diagonal correction). The native code computes
// out[i] = sum + diag[i]*input[i], which is equivalent because sum already
// includes input[i].
func internalDiag() [Width]koalabear.Element {
	// Mirrors the per-lane multipliers in poseidon2.matMulInternalInPlace for
	// width 16. Values are exact field elements (1/2, 1/8, 1/(2^8), etc. are
	// inverses modulo q, computed once at gadget-init time).
	var d [Width]koalabear.Element

	// Helpers for inverses of small powers of two.
	pow2InvN := func(n int) koalabear.Element {
		// 2^n mod q, then invert.
		var two, x koalabear.Element
		two.SetUint64(2)
		x.SetOne()
		for i := 0; i < n; i++ {
			x.Mul(&x, &two)
		}
		x.Inverse(&x)
		return x
	}
	neg := func(e koalabear.Element) koalabear.Element {
		var z koalabear.Element
		z.Neg(&e)
		return z
	}
	mkU := func(v uint64) koalabear.Element {
		var e koalabear.Element
		e.SetUint64(v)
		return e
	}

	// [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
	d[0] = neg(mkU(2))
	d[1] = mkU(1)
	d[2] = mkU(2)
	d[3] = pow2InvN(1)
	d[4] = mkU(3)
	d[5] = mkU(4)
	d[6] = neg(pow2InvN(1))
	d[7] = neg(mkU(3))
	d[8] = neg(mkU(4))
	d[9] = pow2InvN(8)
	d[10] = pow2InvN(3)
	d[11] = pow2InvN(24)
	d[12] = neg(pow2InvN(8))
	d[13] = neg(pow2InvN(3))
	d[14] = neg(pow2InvN(4))
	d[15] = neg(pow2InvN(24))
	return d
}
