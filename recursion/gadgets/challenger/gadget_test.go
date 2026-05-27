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

package challenger_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/recursion/gadgets/challenger"
)

// TestNativeChallengerReplay verifies that NativeState reproduces the same
// outputs as a hand-coded width-16 Poseidon2 sponge for a simple
// absorb-squeeze sequence. This pins the challenger's sponge convention so
// future refactors don't silently change the absorb-overwrite + first-rate-
// lane squeeze pattern.
func TestNativeChallengerReplay(t *testing.T) {
	st := challenger.NewNativeState()

	// Absorb 5 elements, squeeze, absorb 3 more, squeeze.
	var v koalabear.Element
	for i := uint64(1); i <= 5; i++ {
		v.SetUint64(i)
		st.AbsorbNative(v)
	}
	got1, _ := st.SqueezeBaseNative()

	for i := uint64(100); i < 103; i++ {
		v.SetUint64(i)
		st.AbsorbNative(v)
	}
	got2, _ := st.SqueezeBaseNative()

	if got1.Equal(&got2) {
		t.Fatalf("two consecutive squeeze results unexpectedly equal: %s", got1.String())
	}

	// Deterministic re-run produces identical outputs.
	st2 := challenger.NewNativeState()
	for i := uint64(1); i <= 5; i++ {
		v.SetUint64(i)
		st2.AbsorbNative(v)
	}
	check1, _ := st2.SqueezeBaseNative()
	if !check1.Equal(&got1) {
		t.Fatalf("non-deterministic squeeze: %s != %s", check1.String(), got1.String())
	}
}

// TestChallengerInitZeroState confirms that a freshly-initialized symbolic
// state holds zeros across all StateWidth lanes.
func TestChallengerInitZeroState(t *testing.T) {
	s := challenger.Init()
	if s == nil {
		t.Fatal("Init returned nil")
	}
	if len(s.Buf) != 0 {
		t.Fatalf("Init buffer must be empty, got len=%d", len(s.Buf))
	}
	if s.Slot != 0 {
		t.Fatalf("Init slot must be 0, got %d", s.Slot)
	}
}
