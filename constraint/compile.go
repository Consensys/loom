package constraint

import (
	"fmt"

	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	derive "github.com/consensys/loom/internal/derive"
)

// Fold returns Σ_i αⁱE[i]
func Fold(E []expr.Expr, alpha expr.Expr) expr.Expr {
	res := E[len(E)-1]
	for i := len(E) - 2; i >= 0; i-- {
		res = res.Mul(alpha).Add(E[i])
		// res = res.Add(E[i].Mul(alpha.Pow(uint32(i))))
	}
	return res
}

// Program DAG containing all tha proverSteps, and the final constraint that must vanish
// on X^N-1
type Program struct {
	DerivationPlan    []derive.DerivationStep
	VanishingRelation dag.DAG
	Cache             map[string]int // not serialised, used for building the IOP only, used to track already registered prover actions which have no inputs (lagrange, permutation)
	N                 int
}

type Config struct {
	targetDegree int
}

type Option func(c *Config)

func WithTargetDegree(targetDegree int) Option {
	return func(c *Config) {
		c.targetDegree = targetDegree
	}
}

// canonicalChallengeName returns the shared challenge name for all Fiat-Shamir steps
// at a given BFS level in the challenge-dependency DAG.
func canonicalChallengeName(level int) string {
	return fmt.Sprintf("loom@challenge_%d", level)
}

// batchFiatShamir groups all FIAT_SHAMIR steps at the same "level" into one merged step.
//
// Level of a FIAT_SHAMIR step = max(level of challenge deps in its inputs) + 1, or 0 if
// the inputs contain no challenge leaves.  All steps at the same level see the same
// challenge, so per-argument challenge names are unified into "loom@challenge_k".
//
// Returns the rewritten derivation plan and a rename map (old name → canonical name)
// that callers must also apply to Relations.
func batchFiatShamir(plan []derive.DerivationStep, publicInputs derive.PublicInputs) ([]derive.DerivationStep, map[string]string) {

	// 1. Compute the level of every FIAT_SHAMIR step.
	challengeLevel := map[string]int{} // challenge name → its level
	stepLevel := make([]int, len(plan))
	for i, step := range plan {
		if step.StepContext.GetID() != derive.FIAT_SHAMIR {
			continue
		}
		level := 0
		for _, dep := range derive.GetChallengesID(step.Inputs) {
			if l, ok := challengeLevel[dep]; ok && l+1 > level {
				level = l + 1
			}
		}
		stepLevel[i] = level
		for _, out := range step.Outputs {
			challengeLevel[out] = level
		}
	}

	// 2. Group FS step indices by level and build the old-name → canonical-name map.
	fsByLevel := map[int][]int{}
	for i, step := range plan {
		if step.StepContext.GetID() == derive.FIAT_SHAMIR {
			fsByLevel[stepLevel[i]] = append(fsByLevel[stepLevel[i]], i)
		}
	}

	rename := map[string]string{}
	for level, indices := range fsByLevel {
		canonical := canonicalChallengeName(level)
		for _, idx := range indices {
			for _, out := range plan[idx].Outputs {
				rename[out] = canonical
			}
		}
	}

	// applyRename rewrites all old challenge names in e to their canonical names.
	applyRename := func(e expr.Expr) expr.Expr {
		for old, canonical := range rename {
			e = e.ReplaceLeafByExpression(old, expr.NewChallenge(canonical))
		}
		return e
	}

	// 3. Collect merged inputs per level (union of each level's FS-step inputs, renamed).
	batchInputs := map[int][]expr.Expr{}
	for level, indices := range fsByLevel {
		seen := map[string]bool{}
		for _, idx := range indices {
			for _, inp := range plan[idx].Inputs {
				renamed := applyRename(inp)
				key := renamed.String()
				if !seen[key] {
					seen[key] = true
					batchInputs[level] = append(batchInputs[level], renamed)
				}
			}
		}
	}

	// 4. Rebuild the plan: replace the first occurrence of each level's FS cluster with
	//    a single merged step; skip subsequent FS steps at the same level; rename inputs
	//    of all other steps.
	newPlan := make([]derive.DerivationStep, 0, len(plan))
	addedBatchAtLevel := map[int]bool{}

	for i, step := range plan {
		if step.StepContext.GetID() == derive.FIAT_SHAMIR {
			level := stepLevel[i]
			if addedBatchAtLevel[level] {
				continue
			}
			newPlan = append(newPlan, derive.DerivationStep{
				Inputs:      batchInputs[level],
				Outputs:     []string{canonicalChallengeName(level)},
				StepContext: derive.NewFiatShamirContext(publicInputs),
			})
			addedBatchAtLevel[level] = true
		} else {
			newInputs := make([]expr.Expr, len(step.Inputs))
			for j, inp := range step.Inputs {
				newInputs[j] = applyRename(inp)
			}
			step.Inputs = newInputs
			newPlan = append(newPlan, step)
		}
	}

	return newPlan, rename
}

// Compile folds all constraints, deriving a vanishing relation over X^N-1.
// It also applies batched Fiat-Shamir: all same-level challenge derivation steps are
// merged into one, so the proof has one transcript round per challenge level instead
// of one per sub-protocol.
func (system *Builder) Compile(opts ...Option) Program {

	var config Config
	for _, opt := range opts {
		opt(&config)
	}

	// 0. if config.targetDegree > 0 it means targetDegree is set: we reduce the constraints degree before folding them
	if config.targetDegree > 0 {
		reduceDegree(system, config.targetDegree)
	}

	// 1. Batch Fiat-Shamir: merge all same-level challenge derivation steps and
	//    compute the rename map (old challenge name → canonical "loom@challenge_k").
	plan, rename := batchFiatShamir(system.DerivationPlan, system.PublicInputs)

	// 2. Apply rename to relations in-place so that system.Relations and the compiled
	//    VanishingRelation both reference canonical challenge names.
	for i, rel := range system.Relations {
		r := rel
		for old, canonical := range rename {
			r = r.ReplaceLeafByExpression(old, expr.NewChallenge(canonical))
		}
		system.Relations[i] = r
	}

	// 3. Fold all the constraints using the folding challenge.
	C := Fold(system.Relations, expr.NewChallenge(constants.FINAL_FOLDING_CHALLENGE))
	CDag := dag.ExprToDAG(C)
	CDag = CDag.Flatten()
	return Program{
		DerivationPlan:    plan,
		VanishingRelation: *CDag,
		N:                 system.N,
	}
}
