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

package challenger

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	rp2 "github.com/consensys/loom/recursion/gadgets/poseidon2"
)

// Permute folds any buffered inputs into the sponge state (overwrite mode
// over the rate lanes), then "uses" the next Poseidon2 gadget slot to mark
// where the constraints must reference the underlying permutation columns.
//
// The symbolic state's permuted values are NOT inlined here — instead, the
// State.Sym is replaced by symbolic references to the Poseidon2 gadget's
// output columns at this slot. The caller is responsible for wiring the same
// slot's input columns to the pre-permute Sym values via lookups or direct
// equality, and for filling the trace via PermuteNative.
//
// The challenger module name is used to disambiguate permutation slots when
// multiple challengers share a Poseidon2 gadget module.
func (s *State) Permute(challengerName string) {
	// 1. Absorb buffered inputs into the rate lanes (overwrite mode).
	for i := 0; i < len(s.Buf) && i < Rate; i++ {
		s.Sym[i] = s.Buf[i]
	}
	s.Buf = s.Buf[:0]

	// 2. The next state is bound to the Poseidon2 gadget's output at the
	// current slot. Constraints binding the slot's input columns to the
	// (just-overwritten) Sym must be emitted by the caller — see gadget_test
	// for the wiring pattern.
	for i := 0; i < StateWidth; i++ {
		s.Sym[i] = expr.Col(PermOutColName(challengerName, s.Slot, i))
	}
	s.Slot++
}

// SqueezeBase returns one fresh base-field expr from the rate region. If the
// buffer is non-empty, Permute is invoked first. Repeated calls within the
// same rate block return distinct positions.
func (s *State) SqueezeBase(challengerName string) expr.Expr {
	if len(s.Buf) > 0 {
		s.Permute(challengerName)
	}
	// Take the first rate lane. A more featureful variant would track a
	// "squeeze position" so successive squeezes pull from rate[0], rate[1],
	// ... without re-permuting; for milestone 1 we re-permute every squeeze.
	v := s.Sym[0]
	s.Permute(challengerName)
	return v
}

// SqueezeExt returns one fresh E6 expression by pulling 6 base elements from
// the sponge.
func (s *State) SqueezeExt(challengerName string) extfield.E6Expr {
	limbs := [extfield.Limbs]expr.Expr{}
	if len(s.Buf) > 0 {
		s.Permute(challengerName)
	}
	for i := 0; i < extfield.Limbs; i++ {
		limbs[i] = s.Sym[i]
	}
	s.Permute(challengerName)
	return extfield.FromLimbs(limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5])
}

// PermuteNative mirrors Permute on native values for trace generation: it
// overwrites rate lanes with the buffer, runs the width-16 Poseidon2
// permutation, and increments the slot counter. Returns the (in, out) pair
// produced by this slot — the caller should write these into the Poseidon2
// gadget's input/output columns at the matching row.
func (s *NativeState) PermuteNative() ([rp2.Width]koalabear.Element, [rp2.Width]koalabear.Element) {
	// 1. Absorb.
	for i := 0; i < len(s.Buf) && i < Rate; i++ {
		s.Sym[i].Set(&s.Buf[i])
	}
	s.Buf = s.Buf[:0]

	// 2. Snapshot input, permute, snapshot output.
	var in [rp2.Width]koalabear.Element
	for i := 0; i < rp2.Width; i++ {
		in[i].Set(&s.Sym[i])
	}
	perm := poseidon2.NewPermutation(rp2.Width, rp2.NbFullRounds, rp2.NbPartialRound)
	tmp := in
	if err := perm.Permutation(tmp[:]); err != nil {
		panic(err)
	}
	for i := 0; i < rp2.Width; i++ {
		s.Sym[i].Set(&tmp[i])
	}
	s.Slot++
	return in, tmp
}

// SqueezeBaseNative is the native counterpart of SqueezeBase; returns the
// extracted element after performing the necessary permutations.
func (s *NativeState) SqueezeBaseNative() (koalabear.Element, []SlotIO) {
	var ios []SlotIO
	if len(s.Buf) > 0 {
		in, out := s.PermuteNative()
		ios = append(ios, SlotIO{In: in, Out: out})
	}
	var v koalabear.Element
	v.Set(&s.Sym[0])
	in, out := s.PermuteNative()
	ios = append(ios, SlotIO{In: in, Out: out})
	return v, ios
}

// SlotIO records the I/O of one Poseidon2 gadget slot during native replay.
type SlotIO struct {
	In  [rp2.Width]koalabear.Element
	Out [rp2.Width]koalabear.Element
}
