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

// Package poseidon2sponge implements the width-24 Koalabear Poseidon2
// permutation in-circuit. This is the variant Loom uses for Merkle leaf
// hashing and the Fiat-Shamir transcript (sponge over a width-24 state
// with rate 16, capacity 8).
//
// The package mirrors gadgets/poseidon2 (the width-16 MD variant) — same
// round counts and S-box, but with a 24-element state and a different
// internal-matrix diagonal. Column layout per row:
//
//   - in_0..in_23                   : input state (24 limbs)
//   - r{R}_sbox_{i}                  : (prev_state[i] + RC)^3
//                                       full rounds: i in 0..23
//                                       partial rounds: i = 0 only
//   - r{R}_post_0..23               : state after round R's linear layer
//
// One row computes one full Poseidon2 permutation. Padded rows replay
// Permutation([0]*24), which is a self-consistent witness.
package poseidon2sponge

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/internal/hash"
)

// Width24 mirrors hash.SPONGE_WIDTH (the width Loom's sponge hasher uses).
const (
	Width          = hash.SPONGE_WIDTH      // 24
	NbFullRounds   = hash.NB_FULL_ROUND     // 6
	NbPartialRound = hash.NB_PARTIAL_ROUNDS // 21
	Rate           = hash.SPONGE_RATE       // 16 — exposed for absorbing layers
	Capacity       = Width - Rate           // 8
)

// NbRounds is the total number of rounds — same as the width-16 variant
// (only width and internal diagonal differ between the two).
const NbRounds = NbFullRounds + NbPartialRound

// RfHead is the number of full rounds before the partial rounds.
const RfHead = NbFullRounds / 2

// PartialEnd is the round index (exclusive) of the last partial round.
const PartialEnd = RfHead + NbPartialRound

// Params returns a fresh native Poseidon2 parameters object for width 24.
// Loom's native sponge hasher uses the same parameters and seed, so the
// round keys match exactly.
func Params() *poseidon2.Parameters {
	return poseidon2.NewParameters(Width, NbFullRounds, NbPartialRound)
}

// Column-name helpers.
func InColName(name string, i int) string { return fmt.Sprintf("%s.in_%d", name, i) }
func SBoxColName(name string, r, i int) string {
	return fmt.Sprintf("%s.r%02d_sbox_%d", name, r, i)
}
func PostColName(name string, r, i int) string {
	return fmt.Sprintf("%s.r%02d_post_%d", name, r, i)
}
func OutColName(name string, i int) string {
	return PostColName(name, NbRounds-1, i)
}

// IsFullRound reports whether round r uses a full S-box layer.
func IsFullRound(r int) bool {
	return r < RfHead || r >= PartialEnd
}

// internalDiag returns the width-24 diagonal D such that the internal
// matrix is J + diag(D). Values mirror the per-lane multipliers in
// poseidon2.matMulInternalInPlace for width 24:
//
//	[-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4,
//	 1/2^8, 1/4, 1/8, 1/16, 1/32, 1/64, 1/2^24,
//	 -1/2^8, -1/8, -1/16, -1/32, -1/64, -1/2^7, -1/2^9, -1/2^24]
func internalDiag() [Width]koalabear.Element {
	var d [Width]koalabear.Element

	pow2InvN := func(n int) koalabear.Element {
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
	d[10] = pow2InvN(2)
	d[11] = pow2InvN(3)
	d[12] = pow2InvN(4)
	d[13] = pow2InvN(5)
	d[14] = pow2InvN(6)
	d[15] = pow2InvN(24)
	d[16] = neg(pow2InvN(8))
	d[17] = neg(pow2InvN(3))
	d[18] = neg(pow2InvN(4))
	d[19] = neg(pow2InvN(5))
	d[20] = neg(pow2InvN(6))
	d[21] = neg(pow2InvN(7))
	d[22] = neg(pow2InvN(9))
	d[23] = neg(pow2InvN(24))
	return d
}
