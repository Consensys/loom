package derive

import (
	"crypto/sha256"
	"fmt"
	"sync"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

// FiatShamirContext contains the public inputs, to know which value to cancel
// when committing to a column containing public inputs
type FiatShamirContext struct {
	PublicInputs PublicInputs
}

func NewFiatShamirContext(publicInputs PublicInputs) FiatShamirContext {
	return FiatShamirContext{PublicInputs: publicInputs}
}

func (fs FiatShamirContext) String() string {
	return "fiat-shamir"
}

func (fs FiatShamirContext) GetID() StepKind {
	return FIAT_SHAMIR
}

func (fs FiatShamirContext) Key() string {
	return ""
}

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
		n := c.Leaves(expr.NewConfig(expr.WithoutVirtualumns(), expr.WithoutCommittedColumns()))
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

// ComputeChallenge derives a Fiat-Shamir challenge by batch-committing all new
// committed columns that appear in E at this level.  Instead of committing each
// column individually, all columns are committed together via CommitBatch, and the
// resulting batch digest is bound to the FS transcript.  Previously derived
// challenge values are also bound so that the ordering is enforced.
func ComputeChallenge(tr trace.Trace, proof *Proof, mu *sync.Mutex, E []expr.Expr, GP []string, ctx StepContext) error {
	if len(GP) == 0 {
		return fmt.Errorf("len(GP)=0, it must contain the name of the challenge")
	}
	challengeName := GP[0]

	fsContext, ok := ctx.(FiatShamirContext)
	if !ok {
		return fmt.Errorf("ctx should be of type FiatShamirContext")
	}

	// Steps 1-6 are protected by mu.
	fs, err := func() (*fiatshamir.Transcript, error) {
		mu.Lock()
		defer mu.Unlock()

		// 1. Collect committed-column and challenge-name dependencies.
		dependenciesCommittedColumns := GetColumnsId(E, expr.OnlyCommittedColumns...)
		dependenciesChallenges := GetColumnsId(E, expr.OnlyChallenges...)

		// 2. Remove columns already covered by a previously derived challenge.
		deps := make([]string, 0)
		for _, c := range dependenciesChallenges {
			cacheDeps, ok := proof.GetChallengeDeps(c)
			if !ok {
				return nil, fmt.Errorf("challenge %s not recorded in cacheChallengeDependencies", c)
			}
			deps = append(deps, cacheDeps...)
		}
		dependenciesCommittedColumns = l1MinusL2(dependenciesCommittedColumns, deps)

		// 3. Prevent double-registration.
		if _, ok := proof.GetChallengeDeps(challengeName); ok {
			return nil, fmt.Errorf("challenge %s is already recorded", challengeName)
		}

		// 4. Build the polynomial list for the batch commitment. Careful of zeroing
		// the public inputs
		polys := make([]poly.Polynomial, 0, len(dependenciesCommittedColumns))
		colNames := make([]string, 0, len(dependenciesCommittedColumns))
		for _, id := range dependenciesCommittedColumns {
			p, ok := tr[id]
			if !ok {
				return nil, fmt.Errorf("polynomial %s not found in the trace", id)
			}
			if publicInfo, ok := fsContext.PublicInputs[id]; ok {
				buf := make([]koalabear.Element, proof.N)
				copy(buf, p)
				for _, idx := range publicInfo.Idx {
					buf[idx].SetZero()
				}
				polys = append(polys, buf)
			} else {
				polys = append(polys, p)
			}
			colNames = append(colNames, id)
		}

		// 5. Batch-commit and record the batch.
		batch, err := commitment.CommitBatch(polys)
		if err != nil {
			return nil, err
		}
		batchIdx := len(proof.Batch)
		proof.Batch = append(proof.Batch, batch)
		proof.BatchColumns = append(proof.BatchColumns, colNames)

		// 6. Record the transcript round and update the dependency cache.
		proof.TranscriptRounds = append(proof.TranscriptRounds, TranscriptRound{
			ChallengeName:   challengeName,
			DependencyBatch: batchIdx,
		})
		proof.SetChallengeDeps(challengeName, l1DisjointUnionL2(dependenciesCommittedColumns, deps))

		// 7. Build the FS transcript: bind the batch digest, then all previous challenges.
		fs := fiatshamir.NewTranscript(sha256.New())
		if err := fs.NewChallenge(challengeName); err != nil {
			return nil, err
		}
		if err := fs.Bind(challengeName, batch.Marshal()); err != nil {
			return nil, err
		}
		// Bind all previously derived challenge values (all rounds except the current one).
		for _, prevRound := range proof.TranscriptRounds[:len(proof.TranscriptRounds)-1] {
			c, ok := tr[prevRound.ChallengeName]
			if !ok {
				return nil, fmt.Errorf("challenge %s not found in the trace", prevRound.ChallengeName)
			}
			if err := fs.Bind(challengeName, c[0].Marshal()); err != nil {
				return nil, err
			}
		}

		return fs, nil
	}()
	if err != nil {
		return err
	}

	// 8. Derive the challenge (no lock needed: fs is local).
	bc, err := fs.ComputeChallenge(challengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)

	return NewColumn(tr, challengeName, []koalabear.Element{c}, mu)
}
