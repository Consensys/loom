package cs

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/giop/crypto/dummycommitment"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
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

// returns l1 \ l2
func removeFromList(l1, l2 []string) []string {
	res := make([]string, 0, len(l1))
	for i := 0; i < len(l1); i++ {
		isInL2 := false
		for j := 0; j < len(l2); j++ {
			if l1[i] == l2[j] {
				isInL2 = true
				break
			}
		}
		if !isInL2 {
			res = append(res, l1[i])
		}
	}
	return res
}

// ComputeChallenge type of ProverAction creates a challenge named GP[0] which is derived via FS
// from the commitments of all the leaves appearing in E.
func ComputeChallenge(trace trace.Trace, proof *Proof, E []sym.Expr, GP []string) error {

	if len(GP) == 0 {
		return fmt.Errorf("len(GP)=0, it must contain the name of the challenge")
	}
	challengeName := GP[0]

	// 1. the challenge dependencies are CommittedColumns AND challenges, otherwise
	// the prover<->verifier interactionit is oblivious of the FS order and gives security gaps. We don't take
	// the Computationable columns, because they are recomputed by the verifier.
	dependenciesCommittedColumns := GetColumnsId(E, sym.OnlyCommittedColumns...)
	dependenciesChallenges := GetColumnsId(E, sym.OnlyChallenges...)

	// 2. find on which commitments depend round.DependenciesChallenges, and remove them from round.DependenciesCommittedColumns
	// if they appear in it -> round.DependenciesChallenges already accout for them.
	deps := make([]string, 0, len(dependenciesChallenges))
	for _, c := range dependenciesChallenges {
		if _, ok := proof.cacheChallengeDependencies[c]; !ok {
			return fmt.Errorf("challenge %s not recorded in cacheChallengeDependencies", c)
		}
		cacheDeps := proof.cacheChallengeDependencies[c]
		deps = append(deps, cacheDeps...)
	}
	dependenciesCommittedColumns = removeFromList(dependenciesCommittedColumns, deps)

	// 3. record the round
	round := Round{
		ChallengeName:                challengeName,
		DependenciesCommittedColumns: dependenciesCommittedColumns,
		DependenciesChallenges:       dependenciesChallenges,
	}
	proof.Rounds = append(proof.Rounds, round)

	// 4. add the current challenge to the cacheChallengeDependencies map
	if _, ok := proof.cacheChallengeDependencies[challengeName]; ok {
		return fmt.Errorf("challenge %s is already recorded", challengeName)
	}
	proof.cacheChallengeDependencies[challengeName] = round.DependenciesCommittedColumns

	// 5. Commit to all the polynomials whose name matches leaves. Record the commitments in the proof, and update FS along the way
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

	// 6. Bind the challenge to the other challenges it depends on
	for _, id := range round.DependenciesChallenges {
		c, ok := trace[id]
		if !ok {
			return fmt.Errorf("challenge %s not found in the trace", id)
		}
		cVal := c[0]
		err = fs.Bind(challengeName, cVal.Marshal())
		if err != nil {
			return err
		}
	}

	// 7. Derive the challenge
	bc, err := fs.ComputeChallenge(challengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)

	// 8. add the challenge as a constant column, since it might appear in other constraints
	return RegisterColumn(trace, challengeName, []koalabear.Element{c})

}
