package arguments

import (
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/univariate"
	"github.com/consensys/giop/prover"
	derive "github.com/consensys/giop/derive"
	"github.com/consensys/giop/trace"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
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
	p1 := make(univariate.Polynomial, N)
	p2 := make(univariate.Polynomial, N)
	for j := 0; j < N; j++ {
		p1[j].Set(&base[j%4])
		p2[j].Set(&base[j%4])
	}

	T := trace.Trace{"P1": p1, "P2": p2}

	system := cs.NewBuilder(N)
	err := CopyPermutation(&system, []string{"P1", "P2"}, S)
	if err != nil {
		t.Fatal(err)
	}

	cciop := cs.Compile(&system)
	proverRunTime := prover.NewRuntime(cciop, T)
	knownColumns := map[string]bool{"P1": true, "P2": true}
	proof := derive.NewProof(system.N)

	// 1. Solve + sanity checks
	err = proverRunTime.Solve(knownColumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 2. DeriveFinalFoldingChallenge + sanity checks
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
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
	verifierRunTime := verifier.NewRunTime(cciop)
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
	p1 := make(univariate.Polynomial, N)
	p2 := make(univariate.Polynomial, N)
	for j := 0; j < N; j++ {
		p1[j].Set(&base[j%4])
		p2[j].Set(&base[j%4])
	}

	T := trace.Trace{"P1": p1, "P2": p2}

	system := cs.NewBuilder(N)
	// wires: two chunks, each with the column repeated twice: {P1,P1} and {P2,P2}
	err := CopyPermtutationTuple(&system, [][]string{{"P1", "P1"}, {"P2", "P2"}}, S)
	if err != nil {
		t.Fatal(err)
	}

	cciop := cs.Compile(&system)
	proverRunTime := prover.NewRuntime(cciop, T)
	knownColumns := map[string]bool{"P1": true, "P2": true}
	proof := derive.NewProof(system.N)

	// 1. Solve + sanity checks
	err = proverRunTime.Solve(knownColumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 2. DeriveFinalFoldingChallenge + sanity checks
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
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
	verifierRunTime := verifier.NewRunTime(cciop)
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
