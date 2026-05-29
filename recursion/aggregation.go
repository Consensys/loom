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
	"fmt"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/trace"
)

// BuildAggregationCore compiles a board.Program that verifies BOTH inner
// proofs in a single outer circuit. The two sub-verifiers are wired into
// the same builder under disjoint module-name prefixes ("L_" and "R_") so
// they share no columns or modules, but a single board.Compile + outer
// prove/verify covers them at once — yielding one aggregated proof for
// the pair.
//
// This is the foundation of tree-aggregation: each non-leaf node of the
// aggregation tree is a BuildAggregationCore circuit verifying the two
// child proofs from the level below; AggregateProofs drives that loop.
//
// The Left and Right halves are independent — programs may differ in
// shape, sizes, and hash backends (though both must be Poseidon2, per
// validateInnerProof). Per-half customisation through cfg.ModulePrefix
// is ignored here; this function manages the prefixes itself.
func BuildAggregationCore(input AggregationInput, cfg Config) (board.Program, trace.Trace, error) {
	if err := validateInnerProof(input.Left.Proof, cfg); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("aggregation: left: %w", err)
	}
	if err := validateInnerProof(input.Right.Proof, cfg); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("aggregation: right: %w", err)
	}

	leftCfg := cfg
	leftCfg.ModulePrefix = "L_"
	rightCfg := cfg
	rightCfg.ModulePrefix = "R_"

	builder := board.NewBuilder()
	leftTrace, err := buildVerifierCoreInto(&builder, input.Left, leftCfg)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("aggregation: build left: %w", err)
	}
	rightTrace, err := buildVerifierCoreInto(&builder, input.Right, rightCfg)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("aggregation: build right: %w", err)
	}

	merged, err := trace.MergeMatching(leftTrace, rightTrace)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("aggregation: merge traces: %w", err)
	}

	pg, err := board.Compile(&builder)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("aggregation: compile: %w", err)
	}
	return pg, merged, nil
}
