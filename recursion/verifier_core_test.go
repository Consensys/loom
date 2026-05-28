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
// BuildVerifierCore (Stage 1) and proves+verifies the outer program.
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
	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		cfg,
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
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
// the Lagrange path in BuildVerifierCore.
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

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
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

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
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
// public input column at row 0; BuildVerifierCore reconstructs the
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

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof, PublicInputs: publicInputs},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
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

// TestBuildVerifierCoreNonSkipFRI confirms BuildVerifierCore extends
// the FS chain through fri_fold_0 when the inner proof carries real
// FRI data (DeepQuotientCommitment non-empty). The recursive verifier
// still only checks the AIR relation in-circuit; FRI verification
// itself is the next stage. But the chain machinery is exercised.
func TestBuildVerifierCoreNonSkipFRI(t *testing.T) {
	innerProgram, innerTrace := makeEqualityInner(t, 4)

	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram)
	if err != nil {
		t.Fatalf("inner prove (with FRI): %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof); err != nil {
		t.Fatalf("inner verify (with FRI): %v", err)
	}

	// Sanity: the inner proof must actually carry FRI data, otherwise
	// the chain extension is a no-op and the test isn't testing anything.
	if len(innerProof.DeepQuotientCommitment) == 0 {
		t.Fatal("expected inner proof to carry FRI DEEP-quotient commitments")
	}

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("outer verify: %v", err)
	}
}

// TestBuildVerifierCoreNonSkipFRIFibonacci is the Fibonacci variant of
// TestBuildVerifierCoreNonSkipFRI: the chain machinery is exercised
// with both real FRI data AND the Lagrange-leaf rotation pattern of
// AssertZeroExceptAt. Confirms the chain reconstruction holds across
// the more typical Loom program shape.
func TestBuildVerifierCoreNonSkipFRIFibonacci(t *testing.T) {
	innerProgram, innerTrace := makeFibonacciInner(t, 4)

	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram)
	if err != nil {
		t.Fatalf("inner prove (with FRI): %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof); err != nil {
		t.Fatalf("inner verify (with FRI): %v", err)
	}
	if len(innerProof.DeepQuotientCommitment) == 0 {
		t.Fatal("expected inner proof to carry FRI DEEP-quotient commitments")
	}

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
		t.Fatalf("outer verify: %v", err)
	}
}

// TestBuildVerifierCoreRejectsAtZetaTamperingViaDeepAlpha is an
// additional negative test specific to the Stage-5 witness binding:
// once DEEP_ALPHA's bindings reference the same airverify witness
// columns as the AIR check, tampering an at-zeta value affects BOTH
// the AIR check AND the in-circuit alpha derivation. The constraint
// system must reject the tampered proof.
//
// We tamper B's value at zeta — A and B are equal so the AIR
// constraint (A - B = 0 evaluated at zeta) is sensitive to B too;
// in Stage 4 only the AIR check caught the tampering. With Stage 5,
// the DEEP_ALPHA sponge inputs also pick up the tampered B via the
// witness column, so the in-circuit alpha differs from the native
// chain reconstruction. The sanity check on the chain-zeta-step
// digest still passes (zeta doesn't depend on B), so the failure
// must come from the AIR check itself — confirming Stage 4 behavior
// is preserved when DEEP_ALPHA bindings are promoted to witnesses.
func TestBuildVerifierCoreRejectsAtZetaTamperingViaDeepAlpha(t *testing.T) {
	innerProgram, innerTrace := makeEqualityInner(t, 4)
	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram, prover.SkipFRI())
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}

	// Tamper B at zeta.
	b, ok := innerProof.ValueAtZetaExt("B")
	if !ok {
		t.Fatal("B not in ValuesAtZeta")
	}
	var two koalabear.Element
	two.SetUint64(2)
	b.B0.A0.Add(&b.B0.A0, &two)
	innerProof.SetValueAtZetaExt("B", b)

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		// Prover rejection counts as a successful detection.
		return
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err == nil {
		t.Fatalf("outer verify accepted at-zeta tampering")
	}
}

// TestBuildVerifierCoreRejectsBadFRILeaf tampers the LeafPExt at the
// last fold round for query 0 in the inner proof and expects the outer
// proof to be rejected: the Stage 8 final-poly match constraint should
// fail because the in-circuit fold result no longer agrees with
// finalPoly[s_0 mod len(finalPoly)].
func TestBuildVerifierCoreRejectsBadFRILeaf(t *testing.T) {
	innerProgram, innerTrace := makeEqualityInner(t, 4)
	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram)
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof); err != nil {
		t.Fatalf("inner verify: %v", err)
	}
	if len(innerProof.DeepQuotientCommitment) == 0 {
		t.Fatal("expected FRI data on inner proof")
	}

	// Tamper LeafPExt at the last fold round, query 0. Adding 1 to the
	// B0.A0 limb breaks the fold equation but not the Merkle proof
	// (which we don't check in-circuit yet) — the final-poly match is
	// the only Stage 8 lever, and it should catch this.
	q0 := &innerProof.DeepQuotientFriProof.FRIQueries[0]
	lastIdx := len(q0.Layers) - 1
	var one koalabear.Element
	one.SetOne()
	q0.Layers[lastIdx].LeafPExt.B0.A0.Add(&q0.Layers[lastIdx].LeafPExt.B0.A0, &one)

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		return // prover rejection is also a successful detection
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err == nil {
		t.Fatalf("outer verify accepted FRI leaf tampering at last round")
	}
}

// TestBuildVerifierCoreRejectsBadFRILeafMidRound flips LeafPExt at an
// intermediate fold round (round 0 for the Fibonacci(n=4) inner, where
// numRounds == 2 — so round 0 is the only non-final round) and
// expects the outer verifier to reject via the cross-round fold-chain
// constraint.
func TestBuildVerifierCoreRejectsBadFRILeafMidRound(t *testing.T) {
	innerProgram, innerTrace := makeFibonacciInner(t, 4)
	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram)
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof); err != nil {
		t.Fatalf("inner verify: %v", err)
	}

	// Tamper LeafPExt at round 0 (the only non-final round here).
	q0 := &innerProof.DeepQuotientFriProof.FRIQueries[0]
	if len(q0.Layers) < 2 {
		t.Fatalf("expected ≥ 2 fold rounds, got %d", len(q0.Layers))
	}
	var one koalabear.Element
	one.SetOne()
	q0.Layers[0].LeafPExt.B0.A0.Add(&q0.Layers[0].LeafPExt.B0.A0, &one)

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		return
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err == nil {
		t.Fatalf("outer verify accepted FRI leaf tampering at intermediate round")
	}
}

// TestBuildVerifierCoreRejectsBadMerkleSibling tampers a sibling in
// the FRI Merkle path for query 0 round 0. The fold-chain checks
// (Stages 8 and 9) do NOT consume sibling digests at all, so only the
// per-layer Merkle verification can catch this — confirming Stage 10
// is doing real work, not piggybacking on earlier soundness layers.
func TestBuildVerifierCoreRejectsBadMerkleSibling(t *testing.T) {
	innerProgram, innerTrace := makeFibonacciInner(t, 4)
	innerProof, err := prover.Prove(innerTrace, setup.ProvingKey{}, nil, innerProgram)
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, innerProgram, innerProof); err != nil {
		t.Fatalf("inner verify: %v", err)
	}

	siblings := innerProof.DeepQuotientFriProof.FRIQueries[0].Layers[0].Path.Siblings
	if len(siblings) == 0 {
		t.Fatal("expected non-empty Merkle path at query 0 round 0")
	}
	// Flip one byte of the first sibling. The fold chain doesn't read
	// siblings; only the in-circuit Merkle path verification does.
	siblings[0][0].SetUint64(siblings[0][0].Uint64() ^ 1)

	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
	}

	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		return
	}
	if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err == nil {
		t.Fatalf("outer verify accepted tampered Merkle sibling")
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
	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: innerProgram, Proof: innerProof},
		cfg,
	)
	if err != nil {
		t.Fatalf("BuildVerifierCore: %v", err)
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
