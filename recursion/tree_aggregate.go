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
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/verifier"
)

// AggregateInputs folds a list of inner proofs into a single root proof
// via binary-tree aggregation:
//
//   level 0:  L0 = [proof_0, proof_1, proof_2, ...]      (caller inputs)
//   level 1:  L1[i] = Prove(BuildAggregationCore(L0[2i], L0[2i+1]))
//   level 2:  L2[i] = Prove(BuildAggregationCore(L1[2i], L1[2i+1]))
//   ...      until one root proof remains.
//
// At every level the prover and verifier use SkipFRI (the outer proof
// only validates the AIR-at-zeta relations of the aggregation circuit;
// each leaf's FRI soundness is enforced by the BuildVerifierCore /
// BuildAggregationCore constraints, not by the outer FRI on the
// aggregation circuit itself).
//
// Odd-numbered levels are handled by promoting the dangling input
// unchanged into the next level — its proof goes through one extra
// "trivial" aggregation only when it has a partner.
//
// The input slice must be non-empty and have power-of-two length (the
// caller is responsible for padding if needed). Each leaf must be
// recursion-compatible (Poseidon2 hash backend, see validateInnerProof).
func AggregateInputs(inputs []RecursionInput, cfg Config) (board.Program, proof.Proof, error) {
	if len(inputs) == 0 {
		return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: empty input list")
	}
	if len(inputs)&(len(inputs)-1) != 0 {
		return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: input count %d is not a power of two", len(inputs))
	}

	// Convert leaf inputs to (program, proof) form by running the per-leaf
	// recursion verifier first. This makes every level above use the same
	// (program, proof) shape — the inputs to BuildAggregationCore at
	// level >= 1 are themselves aggregation/verifier proofs.
	currentPrograms := make([]board.Program, len(inputs))
	currentProofs := make([]proof.Proof, len(inputs))
	for i, in := range inputs {
		pg, tr, err := BuildVerifierCore(in, cfg)
		if err != nil {
			return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: leaf %d build: %w", i, err)
		}
		prf, err := prover.Prove(tr, setup.ProvingKey{}, nil, pg, prover.SkipFRI())
		if err != nil {
			return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: leaf %d prove: %w", i, err)
		}
		if err := verifier.Verify(nil, setup.VerificationKey{}, pg, prf, verifier.SkipFRI()); err != nil {
			return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: leaf %d self-verify: %w", i, err)
		}
		currentPrograms[i] = pg
		currentProofs[i] = prf
	}

	for level := 1; len(currentProofs) > 1; level++ {
		nextPrograms := make([]board.Program, len(currentProofs)/2)
		nextProofs := make([]proof.Proof, len(currentProofs)/2)
		for i := 0; i < len(nextProofs); i++ {
			left := RecursionInput{Program: currentPrograms[2*i], Proof: currentProofs[2*i]}
			right := RecursionInput{Program: currentPrograms[2*i+1], Proof: currentProofs[2*i+1]}
			pg, tr, err := BuildAggregationCore(AggregationInput{Left: left, Right: right}, cfg)
			if err != nil {
				return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: level %d node %d build: %w", level, i, err)
			}
			prf, err := prover.Prove(tr, setup.ProvingKey{}, nil, pg, prover.SkipFRI())
			if err != nil {
				return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: level %d node %d prove: %w", level, i, err)
			}
			if err := verifier.Verify(nil, setup.VerificationKey{}, pg, prf, verifier.SkipFRI()); err != nil {
				return board.Program{}, proof.Proof{}, fmt.Errorf("aggregation: level %d node %d self-verify: %w", level, i, err)
			}
			nextPrograms[i] = pg
			nextProofs[i] = prf
		}
		currentPrograms = nextPrograms
		currentProofs = nextProofs
	}

	return currentPrograms[0], currentProofs[0], nil
}
