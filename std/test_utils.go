package std

import (
	"testing"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/prover"
	proveractions "github.com/consensys/giop/prover_actions"
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

func CheckFiatShamir(proverRunTime *prover.Runtime, verifierRunTime *verifier.Runtime, proof *proveractions.Proof, zeta koalabear.Element, t *testing.T) {

	proverChallenges := proverRunTime.CompiledIOP.VanishingRelation.Leaves(
		sym.NewConfig(sym.WithoutCommittedColumns(),
			sym.WithoutComputableColumns(),
			sym.WithoutShiftedColumns()))
	proverChallenges = sym.RemoveDuplicates(proverChallenges)
	mapProverChallenges := make(map[string]koalabear.Element)
	for _, c := range proverChallenges {
		tc := proverRunTime.Trace[c]
		mapProverChallenges[c] = tc[0]
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
