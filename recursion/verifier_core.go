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

package recursion

import (
	"errors"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/trace"
)

// buildVerifierCore compiles a board.Program that verifies a single inner
// Loom proof, together with a witness trace that satisfies it.
//
// Stub for milestone 1: returns an error so that the gadget primitives can be
// exercised in isolation while the end-to-end wiring lands incrementally.
//
// Planned phases for the full implementation:
//
//  1. Derive every Fiat-Shamir challenge in-circuit using the challenger
//     gadget (sponge over the Poseidon2 gadget).
//  2. Reconstruct exposed columns, Lagrange columns, and public columns at
//     zeta from in-circuit arithmetic (extfield helpers).
//  3. Check the logup bus consistency from the exposed values.
//  4. Evaluate the AIR vanishing relation at zeta and assert
//     V(zeta) == (zeta^N - 1) * Q(zeta) per module.
//  5. Verify the FRI proof: fold rounds via in-circuit linear combinations
//     and verify each query path through the Merkle gadget.
//  6. Verify every PointSamplings Merkle opening against the canonical
//     tree-layout roots.
//  7. Check the FRI <-> PointSamplings DEEP-quotient bridge.
//
//nolint:unused // referenced by aggregation.go and external packages once wired up.
func buildVerifierCore(input RecursionInput, cfg Config) (board.Program, trace.Trace, error) {
	if err := validateInnerProof(input.Proof, cfg); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	return board.Program{}, trace.Trace{}, errors.New("recursion: buildVerifierCore not yet implemented")
}
