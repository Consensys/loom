package derive

import (
	"sync"

	"github.com/consensys/loom/expr"
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

func (fs FiatShamirContext) GetKind() StepKind {
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

// ComputeChallenge populates the steps register, but does nothing, FS is handled externally by the prover.
func ComputeChallenge(tr trace.Trace, proof *Proof, mu *sync.Mutex, E []expr.Expr, GP []string, ctx StepContext) error {
	return nil
}
