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

package poseidon2sponge

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
)

// GenerateTrace replays the native width-24 Poseidon2 permutation round-by-
// round for every input in `inputs`, producing witness columns that
// satisfy the BuildModule / Register constraints.
//
// Rows with row >= len(inputs) replay Permutation([0]*Width).
func GenerateTrace(cn ColumnNames, n int, inputs [][Width]koalabear.Element) (map[string][]koalabear.Element, [][Width]koalabear.Element) {
	if len(inputs) > n {
		panic("poseidon2sponge.GenerateTrace: more inputs than module rows")
	}
	cols := make(map[string][]koalabear.Element, 1+Width+NbRounds*2*Width)
	alloc := func(name string) []koalabear.Element {
		col := make([]koalabear.Element, n)
		cols[name] = col
		return col
	}

	in := [Width][]koalabear.Element{}
	for i := 0; i < Width; i++ {
		in[i] = alloc(cn.In[i])
	}
	var sbox [NbRounds][Width][]koalabear.Element
	var post [NbRounds][Width][]koalabear.Element
	for r := 0; r < NbRounds; r++ {
		for i := 0; i < Width; i++ {
			post[r][i] = alloc(cn.Post[r][i])
		}
		if IsFullRound(r) {
			for i := 0; i < Width; i++ {
				sbox[r][i] = alloc(cn.SBox[r][i])
			}
		} else {
			sbox[r][0] = alloc(cn.SBox[r][0])
		}
	}

	outputs := make([][Width]koalabear.Element, len(inputs))

	params := Params()
	for row := 0; row < n; row++ {
		var state [Width]koalabear.Element
		if row < len(inputs) {
			state = inputs[row]
		}
		for i := 0; i < Width; i++ {
			in[i][row].Set(&state[i])
		}

		matMulExternalInPlaceNative(state[:])

		for r := 0; r < NbRounds; r++ {
			rc := params.RoundKeys[r]
			full := IsFullRound(r)

			if full {
				for i := 0; i < Width; i++ {
					var t koalabear.Element
					t.Add(&state[i], &rc[i])
					var cubed koalabear.Element
					cubed.Square(&t).Mul(&cubed, &t)
					state[i].Set(&cubed)
					sbox[r][i][row].Set(&cubed)
				}
				matMulExternalInPlaceNative(state[:])
			} else {
				var t koalabear.Element
				t.Add(&state[0], &rc[0])
				var cubed koalabear.Element
				cubed.Square(&t).Mul(&cubed, &t)
				state[0].Set(&cubed)
				sbox[r][0][row].Set(&cubed)
				matMulInternalInPlaceNative(state[:])
			}

			for i := 0; i < Width; i++ {
				post[r][i][row].Set(&state[i])
			}
		}

		if row < len(inputs) {
			outputs[row] = state
		}
	}

	// Sanity-check against the native permutation on real inputs.
	perm := poseidon2.NewPermutation(Width, NbFullRounds, NbPartialRound)
	for row := 0; row < len(inputs); row++ {
		expected := inputs[row]
		if err := perm.Permutation(expected[:]); err != nil {
			panic(err)
		}
		if expected != outputs[row] {
			panic("poseidon2sponge.GenerateTrace: native permutation disagrees with row-by-row replay")
		}
	}

	return cols, outputs
}

// matMulExternalInPlaceNative mirrors poseidon2.matMulExternalInPlace for
// width 24 (6 chunks of 4 elements).
func matMulExternalInPlaceNative(s []koalabear.Element) {
	nChunks := Width / 4
	for c := 0; c < nChunks; c++ {
		var t01, t23, t0123, t01123, t01233 koalabear.Element
		s0 := s[4*c+0]
		s1 := s[4*c+1]
		s2 := s[4*c+2]
		s3 := s[4*c+3]
		t01.Add(&s0, &s1)
		t23.Add(&s2, &s3)
		t0123.Add(&t01, &t23)
		t01123.Add(&t0123, &s1)
		t01233.Add(&t0123, &s3)
		var d0, d1, d2, d3 koalabear.Element
		d3.Double(&s0).Add(&d3, &t01233)
		d1.Double(&s2).Add(&d1, &t01123)
		d0.Add(&t01, &t01123)
		d2.Add(&t23, &t01233)
		s[4*c+0] = d0
		s[4*c+1] = d1
		s[4*c+2] = d2
		s[4*c+3] = d3
	}
	var tmp [4]koalabear.Element
	for i := 0; i < nChunks; i++ {
		tmp[0].Add(&tmp[0], &s[4*i+0])
		tmp[1].Add(&tmp[1], &s[4*i+1])
		tmp[2].Add(&tmp[2], &s[4*i+2])
		tmp[3].Add(&tmp[3], &s[4*i+3])
	}
	for i := 0; i < nChunks; i++ {
		s[4*i+0].Add(&s[4*i+0], &tmp[0])
		s[4*i+1].Add(&s[4*i+1], &tmp[1])
		s[4*i+2].Add(&s[4*i+2], &tmp[2])
		s[4*i+3].Add(&s[4*i+3], &tmp[3])
	}
}

// matMulInternalInPlaceNative: out[i] = (sum_j s[j]) + diag[i] * s[i].
func matMulInternalInPlaceNative(s []koalabear.Element) {
	var sum koalabear.Element
	sum.Set(&s[0])
	for i := 1; i < Width; i++ {
		sum.Add(&sum, &s[i])
	}
	diag := internalDiag()
	for i := 0; i < Width; i++ {
		var t koalabear.Element
		t.Mul(&diag[i], &s[i])
		t.Add(&t, &sum)
		s[i].Set(&t)
	}
}
