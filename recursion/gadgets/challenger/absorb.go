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
	"github.com/consensys/loom/expr"
)

// State holds the running sponge state during in-circuit Fiat-Shamir. It
// tracks (a) the symbolic state elements as expr.Expr (initially constants
// holding zero), and (b) the buffer of absorbed inputs waiting to be folded
// into the state at the next permutation.
//
// The state is shared structurally with the trace generator — see
// NativeState — so that the same operations can be replayed in plain
// koalabear arithmetic for cross-checks.
type State struct {
	// Symbolic sponge state (expr-level).
	Sym [StateWidth]expr.Expr
	// Buffer of inputs accumulated since the last permutation (length up to Rate).
	Buf []expr.Expr
	// Number of permutations consumed so far. Used to allocate slot indices
	// when calling into the Poseidon2 module.
	Slot int
}

// Init returns an empty challenger state where every sponge element is the
// base-field constant zero.
func Init() *State {
	var zero koalabear.Element
	s := &State{}
	for i := 0; i < StateWidth; i++ {
		s.Sym[i] = expr.Const(zero)
	}
	return s
}

// Absorb queues base-field expressions for absorption. The actual sponge
// permutation happens lazily on Squeeze or when the buffer reaches Rate. The
// caller is responsible for issuing the Poseidon2-gadget I/O column
// references at the relevant slots — the challenger gadget itself encodes
// only the "absorb-overwrite" step and the rate/capacity bookkeeping.
func (s *State) Absorb(values ...expr.Expr) {
	s.Buf = append(s.Buf, values...)
}

// NativeState mirrors State in plain koalabear arithmetic; used to compute
// the witness values for the challenger module's columns.
type NativeState struct {
	Sym  [StateWidth]koalabear.Element
	Buf  []koalabear.Element
	Slot int
}

// NewNativeState returns a NativeState with all zeros.
func NewNativeState() *NativeState {
	return &NativeState{}
}

// AbsorbNative queues base-field elements for absorption.
func (s *NativeState) AbsorbNative(values ...koalabear.Element) {
	s.Buf = append(s.Buf, values...)
}
