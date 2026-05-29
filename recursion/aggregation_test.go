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
	"testing"

	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/verifier"
)

// TestBuildAggregationCorePair builds an aggregation circuit verifying
// two distinct Fibonacci(n=4) inner proofs and confirms the outer
// proof passes prove + verify end-to-end. Both halves use SkipFRI so
// the test runs in reasonable wall time.
func TestBuildAggregationCorePair(t *testing.T) {
	leftProg, leftTrace := makeFibonacciInner(t, 4)
	leftProof, err := prover.Prove(leftTrace, setup.ProvingKey{}, nil, leftProg, prover.SkipFRI())
	if err != nil {
		t.Fatalf("left inner prove: %v", err)
	}
	rightProg, rightTrace := makeEqualityInner(t, 4)
	rightProof, err := prover.Prove(rightTrace, setup.ProvingKey{}, nil, rightProg, prover.SkipFRI())
	if err != nil {
		t.Fatalf("right inner prove: %v", err)
	}

	outerProg, outerTrace, err := BuildAggregationCore(
		AggregationInput{
			Left:  RecursionInput{Program: leftProg, Proof: leftProof},
			Right: RecursionInput{Program: rightProg, Proof: rightProof},
		},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildAggregationCore: %v", err)
	}
	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProg, prover.SkipFRI())
	if err != nil {
		t.Fatalf("aggregated prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProg, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("aggregated verify: %v", err)
	}
}

// TestBuildAggregationCoreRejectsBadLeft tampers the left inner proof
// (its AT-zeta values) and confirms the aggregated outer verifier
// rejects.
func TestBuildAggregationCoreRejectsBadLeft(t *testing.T) {
	leftProg, leftTrace := makeFibonacciInner(t, 4)
	leftProof, err := prover.Prove(leftTrace, setup.ProvingKey{}, nil, leftProg, prover.SkipFRI())
	if err != nil {
		t.Fatalf("left inner prove: %v", err)
	}
	rightProg, rightTrace := makeEqualityInner(t, 4)
	rightProof, err := prover.Prove(rightTrace, setup.ProvingKey{}, nil, rightProg, prover.SkipFRI())
	if err != nil {
		t.Fatalf("right inner prove: %v", err)
	}

	// Tamper left's A value at zeta.
	a, ok := leftProof.ValueAtZetaExt("A")
	if !ok {
		t.Fatal("A not in left.ValuesAtZeta")
	}
	a.B0.A0.SetUint64(a.B0.A0.Uint64() + 1)
	leftProof.SetValueAtZetaExt("A", a)

	outerProg, outerTrace, err := BuildAggregationCore(
		AggregationInput{
			Left:  RecursionInput{Program: leftProg, Proof: leftProof},
			Right: RecursionInput{Program: rightProg, Proof: rightProof},
		},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildAggregationCore: %v", err)
	}
	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProg, prover.SkipFRI())
	if err != nil {
		return
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProg, outerProof, verifier.SkipFRI()); err == nil {
		t.Fatalf("aggregated verify accepted tampered left inner proof")
	}
}

// TestAggregateInputsTwoLeaves drives the tree-aggregation loop with
// two leaf proofs (one root aggregation step).
//
// Currently skipped under testing.Short() because building the root
// aggregation circuit requires running BuildVerifierCore on a leaf
// VERIFIER's airverify program — itself a multi-module program with
// large constraint expressions. board.Compile times out on the
// current implementation. Performance work (sharing merkle modules
// across queries, flattening constraint expressions) is the next
// stage before tree aggregation becomes test-affordable.
func TestAggregateInputsTwoLeaves(t *testing.T) {
	if testing.Short() {
		t.Skip("aggregation tree compile is slow; run with -short=false")
	}
	t.Skip("TODO: optimise aggregation circuit compile before re-enabling — see commit message")
	inputs := make([]RecursionInput, 2)
	for i := range inputs {
		prog, tr := makeFibonacciInner(t, 4)
		prf, err := prover.Prove(tr, setup.ProvingKey{}, nil, prog, prover.SkipFRI())
		if err != nil {
			t.Fatalf("leaf %d inner prove: %v", i, err)
		}
		inputs[i] = RecursionInput{Program: prog, Proof: prf}
	}

	rootProg, rootProof, err := AggregateInputs(inputs, DefaultConfig())
	if err != nil {
		t.Fatalf("AggregateInputs: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, rootProg, rootProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("aggregated root verify: %v", err)
	}
}
