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

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

// makeEqualityInner builds a tiny inner program: one module of size N
// with one constraint A - B = 0. No Lagrange / Public / Exposed leaves,
// so every DAG leaf is in the prover's ValuesAtZeta after Prove.
func makeEqualityInner(t *testing.T, n int) (board.Program, trace.Trace) {
	t.Helper()

	builder := board.NewBuilder()
	mod := board.NewModule("inner")
	mod.N = n
	mod.AssertZero(expr.Col("A").Sub(expr.Col("B")))
	builder.AddModule(mod)

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatalf("inner Compile: %v", err)
	}

	tr := trace.New()
	vals := make([]koalabear.Element, n)
	for i := range vals {
		vals[i].SetUint64(uint64(i*7 + 1))
	}
	tr.SetBase("A", vals)
	// Copy so B holds a distinct slice with equal values.
	valsCopy := make([]koalabear.Element, n)
	copy(valsCopy, vals)
	tr.SetBase("B", valsCopy)

	return program, tr
}

// TestBuildVerifierCoreAIROnlyEquality builds a tiny inner program,
// proves it natively, then constructs the recursive verifier with
// buildVerifierCore (Stage 1) and proves+verifies the outer program.
// The outer proof attests to the AIR relation V(zeta) == (zeta^N - 1) * Q(zeta).
func TestBuildVerifierCoreAIROnlyEquality(t *testing.T) {
	innerProgram, innerTrace := makeEqualityInner(t, 4)

	// Native inner prove + verify (sanity).
	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("inner verify: %v", err)
	}

	cfg := DefaultConfig()
	outerProgram, outerTrace, err := buildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		cfg,
	)
	if err != nil {
		t.Fatalf("buildVerifierCore: %v", err)
	}

	// Prove + verify the outer recursive program.
	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("outer verify: %v", err)
	}
}

// TestBuildVerifierCoreRejectsBadInnerProof confirms a tampered inner
// proof (with one ValueAtZeta corrupted) cannot be wrapped into a
// satisfiable outer program — the AIR check would not hold.
func TestBuildVerifierCoreRejectsBadInnerProof(t *testing.T) {
	innerProgram, innerTrace := makeEqualityInner(t, 4)

	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}

	// Tamper one ValueAtZeta entry: change A's value at zeta so V(zeta)
	// no longer matches (zeta^N - 1) * Q(zeta).
	a, ok := innerProof.ValueAtZetaExt("A")
	if !ok {
		t.Fatal("A not in ValuesAtZeta")
	}
	var one koalabear.Element
	one.SetOne()
	a.B0.A0.Add(&a.B0.A0, &one)
	innerProof.SetValueAtZetaExt("A", a)

	cfg := DefaultConfig()
	outerProgram, outerTrace, err := buildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		cfg,
	)
	if err != nil {
		t.Fatalf("buildVerifierCore: %v", err)
	}

	// Outer prove should fail (or verify fails) because the AIR constraint
	// V(zeta) - (zeta^N-1)*Q(zeta) = 0 is now violated.
	_, err = prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		// Prove failing is one acceptable rejection path.
		return
	}
	// If prove succeeded, verify must fail.
	// We can't call verify on the same outerProof object — let's just
	// re-prove via the standard path and check verify fails.
	outerProof, _ := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err == nil {
		t.Fatalf("outer verify accepted tampered inner proof")
	}
}
