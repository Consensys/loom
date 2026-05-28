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
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/public"
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

// makeFibonacciInner builds the canonical Fibonacci program at size N:
// columns A, B, C with constraints A_{i+1} = B_i, B_{i+1} = C_i (except
// at the last row to avoid wraparound), and C_i = A_i + B_i. Uses
// AssertZeroExceptAt which introduces LagrangeColumn leaves — exercising
// the Lagrange path in buildVerifierCore.
func makeFibonacciInner(t *testing.T, n int) (board.Program, trace.Trace) {
	t.Helper()

	builder := board.NewBuilder()
	mod := board.NewModule("fib")
	mod.N = n
	mod.AssertZeroExceptAt(expr.Rot("A", 1).Sub(expr.Col("B")), n-1)
	mod.AssertZeroExceptAt(expr.Rot("B", 1).Sub(expr.Col("C")), n-1)
	mod.AssertZero(expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B")))
	builder.AddModule(mod)

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatalf("inner Compile: %v", err)
	}

	// Native Fibonacci values: A_0 = 0, B_0 = 1, then A,B,C iteratively.
	a := make([]koalabear.Element, n)
	b := make([]koalabear.Element, n)
	c := make([]koalabear.Element, n)
	a[0].SetZero()
	b[0].SetOne()
	for i := 0; i < n; i++ {
		c[i].Add(&a[i], &b[i])
		if i+1 < n {
			a[i+1].Set(&b[i])
			b[i+1].Set(&c[i])
		}
	}

	tr := trace.New()
	tr.SetBase("A", a)
	tr.SetBase("B", b)
	tr.SetBase("C", c)
	return program, tr
}

// TestBuildVerifierCoreFibonacci wraps a 4-row Fibonacci inner proof
// into a Stage-1 recursive verifier. Exercises Lagrange leaves (from
// AssertZeroExceptAt) and the row-rotation leaves.
func TestBuildVerifierCoreFibonacci(t *testing.T) {
	innerProgram, innerTrace := makeFibonacciInner(t, 4)

	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("inner verify: %v", err)
	}

	outerProgram, outerTrace, err := buildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("buildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("outer verify: %v", err)
	}
}

// TestBuildVerifierCoreWithExposedValues exercises ExposedColumn leaves.
// Uses AddExposeLastEntryStep to expose the last value of column A;
// the gadget reconstructs the exposed value at zeta via Lagrange and
// the AIR check holds.
func TestBuildVerifierCoreWithExposedValues(t *testing.T) {
	const n = 4

	builder := board.NewBuilder()
	mod := board.NewModule("expose_demo")
	mod.N = n
	// Constraint: A = B (trivial). Expose A's last entry.
	mod.AssertZero(expr.Col("A").Sub(expr.Col("B")))
	builder.AddModule(mod)
	builder.AddExposeLastEntryStep("expose_demo", expr.Col("A"), "last_a")

	innerProgram, err := board.Compile(&builder)
	if err != nil {
		t.Fatalf("inner Compile: %v", err)
	}

	a := make([]koalabear.Element, n)
	for i := range a {
		a[i].SetUint64(uint64(i*13 + 5))
	}
	b := make([]koalabear.Element, n)
	copy(b, a)

	tr := trace.New()
	tr.SetBase("A", a)
	tr.SetBase("B", b)

	innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, innerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("inner verify: %v", err)
	}

	outerProgram, outerTrace, err := buildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("buildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("outer verify: %v", err)
	}
}

// TestBuildVerifierCoreWithPublicInputs exercises PublicInputColumn
// leaves. Builds an inner program that references a verifier-supplied
// public input column at row 0; buildVerifierCore reconstructs the
// public value at zeta natively.
func TestBuildVerifierCoreWithPublicInputs(t *testing.T) {
	const n = 4

	builder := board.NewBuilder()
	mod := board.NewModule("pub_demo")
	mod.N = n
	// Constraint: at row 0, A equals the public input "pub_val".
	one := koalabear.Element{}
	one.SetOne()
	lagAt0 := mod.LagrangeCol(0)
	rel := lagAt0.Mul(expr.Col("A").Sub(expr.PublicInput("pub_val")))
	mod.AssertZero(rel)
	builder.AddModule(mod)

	innerProgram, err := board.Compile(&builder)
	if err != nil {
		t.Fatalf("inner Compile: %v", err)
	}

	// Witness: A[0] = 42, others arbitrary; public input "pub_val" = 42 at row 0.
	a := make([]koalabear.Element, n)
	a[0].SetUint64(42)
	for i := 1; i < n; i++ {
		a[i].SetUint64(uint64(i))
	}
	tr := trace.New()
	tr.SetBase("A", a)

	publicInputs := public.Inputs{
		"pub_val": public.Input{
			Module: "pub_demo",
			Entries: []public.Entry{
				{Idx: 0, Field: field.Base, Value: a[0]},
			},
		},
	}

	innerProof, err := prover.Prove(tr, setup.ProvingKey{}, publicInputs, innerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(publicInputs, setup.VerificationKey{}, innerProgram, innerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("inner verify: %v", err)
	}

	outerProgram, outerTrace, err := buildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof, PublicInputs: publicInputs},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("buildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("outer verify: %v", err)
	}
	_ = one
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
