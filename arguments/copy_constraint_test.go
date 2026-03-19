package arguments

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	derive "github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/loom/trace"
)

func TestCopyPermutation(t *testing.T) {
	const N = 16

	// Permutation S: shift by 4 on the concatenated P1||P2 of size 32.
	S := make([]int64, 2*N)
	for i := range S {
		S[i] = int64((i + 4) % (2 * N))
	}

	// Build 4-periodic columns P1 and P2 so that S(P1||P2) = P1||P2.
	// S shifts the concatenated column by 4, so any 4-periodic column is invariant.
	var base [4]koalabear.Element
	for i := range base {
		base[i].SetRandom()
	}
	p1 := make(poly.Polynomial, N)
	p2 := make(poly.Polynomial, N)
	for j := 0; j < N; j++ {
		p1[j].Set(&base[j%4])
		p2[j].Set(&base[j%4])
	}

	T := trace.Trace{"P1": p1, "P2": p2}

	system := constraint.NewBuilder(N, nil)
	P1 := expr.Col("P1")
	P2 := expr.Col("P2")
	err := CopyPermutation(&system, []expr.Expr{P1, P2}, S)
	if err != nil {
		t.Fatal(err)
	}

	cp := system.Compile(nil)
	proverRunTime := prover.NewProver(cp, T, nil)
	proof := derive.NewProof(system.N)

	// 1. DerivePlan + sanity checks
	err = proverRunTime.DerivePlan(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 3. ComputeQuotient + sanity checks
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 4. DeriveOpeningChallenge + sanity checks
	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 4b. OpenCommitments
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier runtime and check Fiat-Shamir consistency
	verifierRunTime := verifier.NewRunTime(cp, nil)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	// 6. Verify
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCopyPermutationTuple(t *testing.T) {
	const N = 16

	// Permutation S: shift by 4 on the concatenated P1||P2 of size 32.
	S := make([]int64, 2*N)
	for i := range S {
		S[i] = int64((i + 4) % (2 * N))
	}

	// Build 4-periodic columns P1 and P2 so that S(P1||P2) = P1||P2.
	var base [4]koalabear.Element
	for i := range base {
		base[i].SetRandom()
	}
	p1 := make(poly.Polynomial, N)
	p2 := make(poly.Polynomial, N)
	for j := 0; j < N; j++ {
		p1[j].Set(&base[j%4])
		p2[j].Set(&base[j%4])
	}

	T := trace.Trace{"P1": p1, "P2": p2}

	system := constraint.NewBuilder(N, nil)
	// wires: two chunks, each with the column repeated twice: {P1,P1} and {P2,P2}
	P1 := expr.Col("P1")
	P2 := expr.Col("P2")
	err := CopyPermtutationTuple(&system, [][]expr.Expr{{P1, P2}, {P1, P2}}, S)
	if err != nil {
		t.Fatal(err)
	}

	cp := system.Compile(nil)
	proverRunTime := prover.NewProver(cp, T, nil)
	proof := derive.NewProof(system.N)

	// 1. DerivePlan + sanity checks
	err = proverRunTime.DerivePlan(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 3. ComputeQuotient + sanity checks
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 4. DeriveOpeningChallenge + sanity checks
	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 4b. OpenCommitments
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier runtime and check Fiat-Shamir consistency
	verifierRunTime := verifier.NewRunTime(cp, nil)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	// 6. Verify
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}
