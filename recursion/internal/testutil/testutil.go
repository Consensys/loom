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

// Package testutil contains helpers shared by recursion gadget tests.
package testutil

import (
	"testing"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

// ProveAndVerify compiles the builder, runs the prover on the given witness
// trace, then verifies the resulting proof. It fails the test on any error.
// FRI is skipped so that gadget tests stay fast — gadgets are tested for AIR
// correctness, not commitment-scheme integration.
func ProveAndVerify(t *testing.T, builder *board.Builder, witness trace.Trace) {
	t.Helper()

	program, err := board.Compile(builder)
	if err != nil {
		t.Fatalf("board.Compile: %v", err)
	}

	prf, err := prover.Prove(witness, setup.ProvingKey{}, nil, program, prover.SkipFRI())
	if err != nil {
		t.Fatalf("prover.Prove: %v", err)
	}

	if err := verifier.Verify(nil, setup.VerificationKey{}, program, prf, verifier.SkipFRI()); err != nil {
		t.Fatalf("verifier.Verify: %v", err)
	}
}

// ExpectProveOrVerifyFailure compiles the builder and asserts that either the
// prover or verifier rejects the (presumably corrupted) witness. Used by
// negative tests to confirm that a tampered trace breaks the proof.
func ExpectProveOrVerifyFailure(t *testing.T, builder *board.Builder, witness trace.Trace) {
	t.Helper()

	program, err := board.Compile(builder)
	if err != nil {
		// A compile error counts as a rejection.
		return
	}

	prf, err := prover.Prove(witness, setup.ProvingKey{}, nil, program, prover.SkipFRI())
	if err != nil {
		return
	}

	if err := verifier.Verify(nil, setup.VerificationKey{}, program, prf, verifier.SkipFRI()); err == nil {
		t.Fatalf("expected prove-or-verify to fail with corrupted witness, but it succeeded")
	}
}
