package proveractions

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/consensys/giop/crypto/dummycommitment"
	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/trace"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// GetCommittedColumnsID returns the list of the names appearing in E
func GetColumnsId(E []expr.Expr, opts ...expr.Option) []string {
	var ids []string
	for _, c := range E {
		n := c.Leaves(expr.NewConfig(opts...))
		expr.RemoveDuplicates(n) // avoid the expression to grow too big
		ids = append(ids, n...)
	}
	ids = expr.RemoveDuplicates(ids)
	return ids
}

// GetColumnsBaseId is like GetColumnsId but for RotatedColumn leaves it returns the
// base column name (e.g. "F1" instead of "F1_shift_-1"). Use this for dependency
// tracking in the Kahn scheduler, where the scheduler only needs to know that the
// underlying trace column is available, not a fictitious shifted-name column.
func GetColumnsBaseId(E []expr.Expr) []string {
	var ids []string
	for _, e := range E {
		for _, leaf := range e.LeavesFull(expr.NewConfig()) {
			ids = append(ids, leaf.Name)
		}
	}
	return expr.RemoveDuplicates(ids)
}

// GetChallengesID returns the list of the names of Challenges appearing in E
func GetChallengesID(E []expr.Expr) []string {
	var ids []string
	for _, c := range E {
		n := c.Leaves(expr.NewConfig(expr.WithoutVirtualColumns(), expr.WithoutCommittedColumns()))
		expr.RemoveDuplicates(n) // avoid the expression to grow too big
		ids = append(ids, n...)
	}
	ids = expr.RemoveDuplicates(ids)
	return ids
}

// returns l1 \ l2
func l1MinusL2(l1, l2 []string) []string {
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

// l1DisjointUnionL2 returns l1 U l2 without duplicates
func l1DisjointUnionL2(l1, l2 []string) []string {
	seen := make(map[string]struct{})
	res := make([]string, 0, len(l1)+len(l2))
	for _, l := range l1 {
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		res = append(res, l)
	}
	for _, l := range l2 {
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		res = append(res, l)
	}
	return res
}

// ComputeChallenge type of ProverAction creates a challenge named GP[0] which is derived via FS
// from the commitments of all the leaves appearing in E.
func ComputeChallenge(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []expr.Expr, GP []string, _ Ctx) error {
	if len(GP) == 0 {
		return fmt.Errorf("len(GP)=0, it must contain the name of the challenge")
	}
	challengeName := GP[0]

	// Steps 1-6 are protected by mu; use a closure so defer unlocks on all exit paths.
	fs, err := func() (*fiatshamir.Transcript, error) {
		mu.Lock()
		defer mu.Unlock()

		// 1. the challenge dependencies are CommittedColumns AND challenges, otherwise
		// the prover<->verifier interactionit is oblivious of the FS order and gives security gaps. We don't take
		// the Computationable columns, because they are recomputed by the verifier.
		dependenciesCommittedColumns := GetColumnsId(E, expr.OnlyCommittedColumns...)
		dependenciesChallenges := GetColumnsId(E, expr.OnlyChallenges...)

		// 2. find on which commitments depend dependenciesChallenges, and remove them from dependenciesCommittedColumns
		// if they appear in it -> round.DependenciesChallenges already accout for them.
		deps := make([]string, 0, len(dependenciesChallenges))
		for _, c := range dependenciesChallenges {
			if _, ok := proof.cacheChallengeDependencies[c]; !ok {
				return nil, fmt.Errorf("challenge %s not recorded in cacheChallengeDependencies", c)
			}
			cacheDeps := proof.cacheChallengeDependencies[c]
			deps = append(deps, cacheDeps...)
		}
		dependenciesCommittedColumns = l1MinusL2(dependenciesCommittedColumns, deps)

		// 3. record the round
		round := Round{
			ChallengeName:                challengeName,
			DependenciesCommittedColumns: dependenciesCommittedColumns,
			DependenciesChallenges:       dependenciesChallenges,
		}
		proof.Rounds = append(proof.Rounds, round)

		// 4. add the current challenge to the cacheChallengeDependencies map
		if _, ok := proof.cacheChallengeDependencies[challengeName]; ok {
			return nil, fmt.Errorf("challenge %s is already recorded", challengeName)
		}
		proof.cacheChallengeDependencies[challengeName] = l1DisjointUnionL2(round.DependenciesCommittedColumns, deps)

		// 5. Commit to all the polynomials whose name matches leaves. Record the commitments in the proof, and update FS along the way
		fs := fiatshamir.NewTranscript(sha256.New())
		if err := fs.NewChallenge(challengeName); err != nil {
			return nil, err
		}
		for _, id := range round.DependenciesCommittedColumns {

			// if the commitment exists, we bind it to challenge
			_, ok := proof.OpeningProofs[id]
			if ok {
				comPacked := proof.OpeningProofs[id]
				if err := fs.Bind(challengeName, comPacked.Digest.Marshal()); err != nil {
					return nil, err
				}
				continue
			}

			// if not, we commit, record the commitment, and bind it to challenge
			poly, ok := trace[id]
			if !ok {
				return nil, fmt.Errorf("polynomial %s not found in the trace", id)
			}
			com, err := dummycommitment.Commit(poly)
			if err != nil {
				return nil, err
			}
			if err := fs.Bind(challengeName, com.Marshal()); err != nil {
				return nil, err
			}
			proof.OpeningProofs[id] = dummycommitment.PackedProof{Digest: com}
		}

		// 6. Bind the challenge to the other challenges it depends on
		for _, id := range round.DependenciesChallenges {
			c, ok := trace[id]
			if !ok {
				return nil, fmt.Errorf("challenge %s not found in the trace", id)
			}
			cVal := c[0]
			if err := fs.Bind(challengeName, cVal.Marshal()); err != nil {
				return nil, err
			}
		}

		return fs, nil
	}()
	if err != nil {
		return err
	}

	// 7. Derive the challenge (no lock needed: fs is local, no shared state)
	bc, err := fs.ComputeChallenge(challengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)

	// 8. add the challenge as a constant column, since it might appear in other constraints
	return NewColumn(trace, challengeName, []koalabear.Element{c}, mu)

}
