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

// buildAggregationCore compiles a board.Program that verifies two inner
// proofs at once, enabling tree-based aggregation: pairs of leaf proofs are
// folded into a single aggregated proof at each level of the tree.
//
// Stub for milestone 1. The planned implementation invokes BuildVerifierCore
// twice into the same builder (so the two sub-verifiers share the same outer
// transcript, lookup buses, and Poseidon2 gadget module), then commits the
// concatenated verification claims.
//
//nolint:unused // referenced externally once wired up.
func buildAggregationCore(input AggregationInput, cfg Config) (board.Program, trace.Trace, error) {
	if err := validateInnerProof(input.Left.Proof, cfg); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	if err := validateInnerProof(input.Right.Proof, cfg); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	return board.Program{}, trace.Trace{}, errors.New("recursion: buildAggregationCore not yet implemented")
}
