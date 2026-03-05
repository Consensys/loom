package std

import (
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestPermutation(t *testing.T) {

	size := 16

	trace := cs.BuildPermutationCircuit(t, size)
	system := cs.NewSystem(size)

	EqualityUpToPermutationIOP(&system, []string{"P0"}, []string{"P1"})

	cciop := cs.Compile(&system)

	proverRunTime := prover.NewRuntime(cciop, trace)

	// begin proving
	knowncolumns := map[string]bool{"P0": true, "P1": true}
	proof := cs.NewProof(system.N)

	// 1. Solve + sanity checks
	err := proverRunTime.Solve(knowncolumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 2. DeriveFinalFoldingChallenge + sanity checks
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	// viewer.WriteTraceToCSV("trace.csv", proverRunTime.Trace, system.N)
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 3. ComputeQuotient + sanity checks
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 4. DeriveOpeningChallenge + sanity checks
	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 4b. OpenCommitments: evaluate all committed polynomials (and the quotient) at zeta
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier verifierRunTime and derive the challenge + sanity check: are the verifier challenges in sync with the prover's
	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	// 6. verify
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPermutationMultiSet(t *testing.T) {

	size := 16

	trace := cs.BuildPermutationMultiSet(t, size)
	system := cs.NewSystem(size)

	err := MultiSetEqualityUpToPermutationIOP(&system, [][]string{{"P0", "P1"}}, [][]string{{"Q0", "Q1"}})
	if err != nil {
		t.Fatal(err)
	}

	knowncolumns := map[string]bool{"P0": true, "P1": true, "Q0": true, "Q1": true}
	cciop := cs.Compile(&system)

	proverRunTime := prover.NewRuntime(cciop, trace)

	proof := cs.NewProof(system.N)

	// 1. Solve + sanity checks
	err = proverRunTime.Solve(knowncolumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 2. DeriveFinalFoldingChallenge + sanity checks
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 3. ComputeQuotient + sanity checks
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 4. DeriveOpeningChallenge + sanity checks
	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

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
