package std

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/constants"
	"github.com/consensys/iop/cs"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/prover"
	"github.com/consensys/iop/verifier"
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

	proverChallenges := proof.VanishingRelation.Leaves(sym.NewConfig(sym.WithoutCommittedColumns(), sym.WithoutComputableColumns()))
	proverChallenges = sym.RemoveDuplicates(proverChallenges)
	mapProverChallenges := make(map[string]koalabear.Element)
	for _, c := range proverChallenges {
		tc := proverRunTime.Trace[c]
		mapProverChallenges[c] = tc.EP.Coefficients[0]
	}
	mapProverChallenges[constants.FINAL_EVALUATION_POINT] = zeta // <- zeta is registered separately, it does not appear in proof.VanishingRelation

	mapVerifierChallenges := make(map[string]koalabear.Element)
	for _, r := range proof.Rounds {
		mapVerifierChallenges[r.ChallengeName] = verifierRunTime.Vars[verifierRunTime.Varindex[r.ChallengeName]]
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

	// 5. Build verifier verifierRunTime and derive the challenge + sanity check: are the verifier challenges in sync with the prover's
	verifierRunTime := verifier.NewRunTime(&proof)
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
