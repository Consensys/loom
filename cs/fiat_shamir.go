package cs

import (
	"crypto/sha256"
	"fmt"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/giop/crypto/dummycommitment"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
)

// GetCommittedColumnsID returns the list of the names appearing in E
func GetColumnsId(E []sym.Expr, opts ...sym.Option) []string {
	var ids []string
	for _, c := range E {
		n := c.Leaves(sym.NewConfig(opts...))
		sym.RemoveDuplicates(n) // avoid the expression to grow too big
		ids = append(ids, n...)
	}
	ids = sym.RemoveDuplicates(ids)
	return ids
}

// GetChallengesID returns the list of the names of Challenges appearing in E
func GetChallengesID(E []sym.Expr) []string {
	var ids []string
	for _, c := range E {
		n := c.Leaves(sym.NewConfig(sym.WithoutComputableColumns(), sym.WithoutCommittedColumns()))
		sym.RemoveDuplicates(n) // avoid the expression to grow too big
		ids = append(ids, n...)
	}
	ids = sym.RemoveDuplicates(ids)
	return ids
}

// SendMeAChallenge type of ProverAction creates a challenge named GP[0] which is derived via FS
// from the commitments of all the leaves appearing in E.
func SendMeAChallenge(trace trace.Trace, proof *Proof, E []sym.Expr, GP []string) error {

	if len(GP) == 0 {
		return fmt.Errorf("len(GP)=0, it must contain the name of the challenge")
	}
	challengeName := GP[0]

	// 1. record the round: the challenge dependencies are CommittedColumns AND challenges, otherwise
	// the prover<->verifier interactionit is oblivious of the FS order and gives security gaps, but we ditch
	// the Computationable columns.
	var round Round
	round.ChallengeName = challengeName
	round.DependenciesCommittedColumns = GetColumnsId(E, sym.WithoutChallenges(), sym.WithoutComputableColumns())
	round.DependenciesChallenges = GetColumnsId(E, sym.WithoutCommittedColumns(), sym.WithoutComputableColumns())
	proof.Rounds = append(proof.Rounds, round)

	// 2. Commit to all the polynomials whose name matches leaves. Record the commitments in the proof, and update FS along the way
	fs := fiatshamir.NewTranscript(sha256.New())
	err := fs.NewChallenge(challengeName)
	if err != nil {
		return err
	}
	for _, id := range round.DependenciesCommittedColumns {

		// if the commitment exists, we bind it to challenge
		_, ok := proof.OpeningProofs[id]
		if ok {
			comPacked := proof.OpeningProofs[id]
			err = fs.Bind(challengeName, comPacked.Digest.Marshal())
			if err != nil {
				return err
			}
			continue
		}

		// if not, we commit, record the commitment, and bind it to challenge
		poly, ok := trace[id]
		if !ok {
			return fmt.Errorf("polynomial %s not found in the trace", id)
		}
		com, err := dummycommitment.Commit(poly)
		if err != nil {
			return err
		}
		err = fs.Bind(challengeName, com.Marshal())
		if err != nil {
			return err
		}
		proof.OpeningProofs[id] = dummycommitment.PackedProof{Digest: com}
	}

	// 3. Bind the challenge to the other challenges it depends on
	for _, id := range round.DependenciesChallenges {
		c, ok := trace[id]
		if !ok {
			return fmt.Errorf("challenge %s not found in the trace", id)
		}
		cVal := c.EP.Coefficients[0]
		err = fs.Bind(challengeName, cVal.Marshal())
		if err != nil {
			return err
		}
	}

	// 5. Derive the challenge
	bc, err := fs.ComputeChallenge(challengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)

	// 6. add the challenge as a constant column, since it might appear in other constraints
	challengeColumn, err := univariate.NewConstantPolynomial(c)
	if err != nil {
		return err
	}
	return RegisterColumn(trace, challengeName, &challengeColumn)

}
