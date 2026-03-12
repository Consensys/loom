package arguments

import (
	"testing"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/constraint"
	derive "github.com/consensys/giop/internal/derive"
	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func sanityCheck(proverRunTime *prover.Prover, constraints []constraint.Relation, N int, t *testing.T) {
	err := constraint.BruteForceChecker(proverRunTime.Trace, constraints, N)
	if err != nil {
		t.Fatal(err)
	}
	err = constraint.QuotientChecker(proverRunTime.Trace, constraints, N)
	if err != nil {
		t.Fatal(err)
	}
}

func CheckFiatShamir(proverRunTime *prover.Prover, verifierRunTime *verifier.Verifier, proof *derive.Proof, zeta koalabear.Element, t *testing.T) {

	proverChallenges := proverRunTime.Program.VanishingRelation.Leaves(
		expr.NewConfig(expr.WithoutCommittedColumns(),
			expr.WithoutVirtualumns(),
			expr.WithoutRotatedColumns()))
	proverChallenges = expr.RemoveDuplicates(proverChallenges)
	mapProverChallenges := make(map[string]koalabear.Element)
	for _, c := range proverChallenges {
		tc := proverRunTime.Trace[c]
		mapProverChallenges[c] = tc[0]
	}
	mapProverChallenges[constants.FINAL_EVALUATION_POINT] = zeta // <- zeta is registered separately, it does not appear in proof.VanishingRelation

	mapVerifierChallenges := make(map[string]koalabear.Element)
	for _, r := range proof.TranscriptRounds {
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
