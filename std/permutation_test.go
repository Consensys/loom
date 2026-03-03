package std

import (
	"testing"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func sanityCheck(proverRunTime *prover.Runtime, constraints []cs.Constraint, N int, t *testing.T) {
	err := cs.BruteForceChecker(proverRunTime.Trace, constraints, N)
	if err != nil {
		t.Fatal(err)
	}
	err = cs.QuotientChecker(proverRunTime.Trace, constraints, N)
	if err != nil {
		t.Fatal(err)
	}
}

func CheckFiatShamir(proverRunTime *prover.Runtime, verifierRunTime *verifier.Runtime, proof *cs.Proof, zeta koalabear.Element, t *testing.T) {

	proverChallenges := proverRunTime.CompiledIOP.VanishingRelation.Leaves(sym.NewConfig(sym.WithoutCommittedColumns(), sym.WithoutComputableColumns()))
	proverChallenges = sym.RemoveDuplicates(proverChallenges)
	mapProverChallenges := make(map[string]koalabear.Element)
	for _, c := range proverChallenges {
		tc := proverRunTime.Trace[c]
		mapProverChallenges[c] = tc.EP.Coefficients[0]
	}
	mapProverChallenges[constants.FINAL_EVALUATION_POINT] = zeta // <- zeta is registered separately, it does not appear in proof.VanishingRelation

	mapVerifierChallenges := make(map[string]koalabear.Element)
	for _, r := range proof.Rounds {
		mapVerifierChallenges[r.ChallengeName] = verifierRunTime.Vars[r.ChallengeName]
	}
	if len(mapVerifierChallenges) != len(mapProverChallenges) {
		t.Errorf("prover and verifier did not derive the same number of challenge: got %d and %d", len(mapProverChallenges), len(mapVerifierChallenges))
	}
	for k, pc := range mapProverChallenges {
		pv, ok := mapVerifierChallenges[k]
		if !ok {
			t.Errorf("%s does not appear in the challenge list of the verifier", k)
		}
		if !pc.Equal(&pv) {
			t.Errorf("%s = %s [Prover size]\n%s = %s [Verifier side]", k, pc.String(), k, pv.String())
		}
	}
}

func TestPermutation(t *testing.T) {

	size := 16

	trace := cs.BuildPermutationCircuit(t, size)
	system := cs.NewSystem(size)

	EqualityUpToPermutationIOP(&system, []string{"P0"}, []string{"P1"}, "GrandProduct", "gamma")

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
	err = verifierRunTime.Verify(&proof)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPermutationMultiSet(t *testing.T) {

	size := 16

	trace := cs.BuildPermutationMultiSet(t, size)
	system := cs.NewSystem(size)

	err := MultiSetEqualityUpToPermutationIOP(&system, [][]string{{"P0", "P1"}}, [][]string{{"Q0", "Q1"}}, "GrandProduct", "alpha", "gamma")
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
	err = verifierRunTime.Verify(&proof)
	if err != nil {
		t.Fatal(err)
	}
}
