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
	}
	return res
}

// Program DAG containing all that proverSteps, and the final constraint that must vanish
// on X^N-1
type Program struct {
	DerivationPlanScheduled [][]derive.DerivationStep
	Batches                 [][]string // Batches[i]-> names of columns on which loom@challenge_i depends
	VanishingRelation       dag.DAG
	N                       int
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
	// Iterate to a fixed point so that the result is correct regardless of
	// the order in which FS steps were registered.
	challengeLevel := map[string]int{} // challenge name → its level
	stepLevel := make([]int, len(plan))
	for i, step := range plan {
		if step.StepContext.GetKind() != derive.FIAT_SHAMIR {
			continue
		}
		stepLevel[i] = -1
	}
	for {
		changed := false
		for i, step := range plan {
			if step.StepContext.GetKind() != derive.FIAT_SHAMIR {
				continue
			}
			level := 0
			for _, dep := range derive.GetChallengesID(step.Inputs) {
				if l, ok := challengeLevel[dep]; ok && l+1 > level {
					level = l + 1
				}
			}
			if stepLevel[i] != level {
				stepLevel[i] = level
				changed = true
			}
			for _, out := range step.Outputs {
				challengeLevel[out] = level
			}
		}
		if !changed {
			break
		}
	}

	// 2. Group FS step indices by level and build the old-name → canonical-name map.
	fsByLevel := map[int][]int{}
	for i, step := range plan {
		if step.StepContext.GetKind() == derive.FIAT_SHAMIR {
			fsByLevel[stepLevel[i]] = append(fsByLevel[stepLevel[i]], i)
		}
	}

	rename := map[string]string{}
	for level, indices := range fsByLevel {
		canonical := constants.CanonicalChallengeName(level)
		for _, idx := range indices {
			for _, out := range plan[idx].Outputs {
				rename[out] = canonical
			}
		}
	}

	// Build a rename map of Expr values once so that ReplaceLeavesByMap can
	// rewrite all challenge names in a single tree traversal instead of one
	// traversal per rename entry.
	renameExprs := make(map[string]expr.Expr, len(rename))
	for old, canonical := range rename {
		renameExprs[old] = expr.NewChallenge(canonical)
	}
	applyRename := func(e expr.Expr) expr.Expr {
		return expr.ReplaceLeavesByMap(e, renameExprs)
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
		if step.StepContext.GetKind() == derive.FIAT_SHAMIR {
			level := stepLevel[i]
			if addedBatchAtLevel[level] {
				continue
			}
			newPlan = append(newPlan, derive.DerivationStep{
				Inputs:      batchInputs[level],
				Outputs:     []string{constants.CanonicalChallengeName(level)},
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

// ScheduleDerivationPlan partitions plan into alternating compute/challenge slots:
//
//	slot 0          – steps with no challenge dependency (if any)
//	slot 1          – FS step generating loom@challenge_0
//	slot 2          – steps that depend on loom@challenge_0 (but not _1)
//	slot 3          – FS step generating loom@challenge_1
//	…
//
// The slot index for a non-FS step whose highest challenge dependency is level k is
// 2*(k+1); for an FS step generating loom@challenge_k it is 2*k+1.
// Steps with no challenge dependency land in slot 0.
//
// plan must have already been processed by batchFiatShamir (one FS step per
// challenge level, canonical names "loom@challenge_k").
func (system *Builder) ScheduleDerivationPlan(plan []derive.DerivationStep) [][]derive.DerivationStep {

	// challengeLevelOf parses "loom@challenge_k" and returns k, or -1 for anything else.
	challengeLevelOf := func(name string) int {
		var level int
		if _, err := fmt.Sscanf(name, "loom@challenge_%d", &level); err == nil {
			return level
		}
		return -1
	}

	// maxInputChallengeLevel returns the highest challenge level referenced by
	// step.Inputs, or -1 if no challenge is referenced.
	maxInputChallengeLevel := func(step derive.DerivationStep) int {
		max := -1
		for _, name := range derive.GetChallengesID(step.Inputs) {
			if l := challengeLevelOf(name); l > max {
				max = l
			}
		}
		return max
	}

	// Determine the total number of challenge levels to size the slice.
	maxLevel := -1
	for _, step := range plan {
		if step.StepContext.GetKind() == derive.FIAT_SHAMIR {
			for _, out := range step.Outputs {
				if l := challengeLevelOf(out); l > maxLevel {
					maxLevel = l
				}
			}
		}
	}

	// One compute slot per challenge level (slot k holds steps that run before challenge k is derived),
	// plus one slot for steps that run after the last intermediate challenge (before the final fold).
	// FS steps are excluded — they are handled implicitly by the prover after each slot.
	// Layout: [compute_0, compute_1, ..., compute_maxLevel+1]
	nSlots := maxLevel + 2
	if nSlots < 1 {
		nSlots = 1
	}
	scheduled := make([][]derive.DerivationStep, nSlots)

	for _, step := range plan {
		if step.StepContext.GetKind() == derive.FIAT_SHAMIR {
			continue
		}
		slot := maxInputChallengeLevel(step) + 1
		scheduled[slot] = append(scheduled[slot], step)
	}

	return scheduled
}

// BuildBatches populates Program.Batches: for each canonical FS level k it
// records the base names of committed columns that are new at that level
// (i.e. not already covered by levels 0..k-1).
//
// "Base name" means the underlying column name without any shift suffix —
// Rot("F1", -1) and Col("F1") both contribute "F1".
//
// The returned cumColDeps accumulates the base names of every committed column
// seen across all canonical FS levels; the caller uses it to determine which
// columns still need to be committed in the final folding-challenge step.
// BuildBatches populates Program.Batches from the FS steps in plan: for each canonical
// FS level k it records the base names of committed columns that are new at that level
// (i.e. not already covered by levels 0..k-1).
func (system *Builder) BuildBatches(plan []derive.DerivationStep) ([][]string, map[string]bool) {
	cumColDeps := map[string]bool{}
	var batches [][]string

	for _, step := range plan {
		if step.StepContext.GetKind() != derive.FIAT_SHAMIR {
			continue
		}

		// Walk inputs in order; collect committed column base names at this level,
		// separating new ones (absent from cumColDeps) from already-covered ones.
		seenAtLevel := map[string]bool{}
		var newCols []string
		for _, inp := range step.Inputs {
			for _, leaf := range inp.LeavesFull(expr.NewConfig(expr.OnlyCommittedColumns...)) {
				col := leaf.Name // base name, shift stripped
				if seenAtLevel[col] {
					continue
				}
				seenAtLevel[col] = true
				if !cumColDeps[col] {
					newCols = append(newCols, col)
				}
			}
		}
		batches = append(batches, newCols)

		// Extend cumColDeps with ALL committed columns at this level so that
		// future levels can correctly subtract them.
		for col := range seenAtLevel {
			cumColDeps[col] = true
		}
	}

	return batches, cumColDeps
}

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

	// 3. Build DerivationPlanScheduled.
	scheduled := system.ScheduleDerivationPlan(plan)

	// 4. Build batches from the FS steps in plan (intermediate challenges).
	batches, cumColDeps := system.BuildBatches(plan)

	// 5. Build the final folding-challenge batch: every committed column appearing in the
	// relations that has not yet been covered by a previous FS step.
	// The final challenge name follows the canonical scheme at index len(batches).
	var finalBatchCols []string
	for _, col := range derive.GetColumnsId(system.Relations, expr.OnlyCommittedColumns...) {
		if !cumColDeps[col] {
			finalBatchCols = append(finalBatchCols, col)
		}
	}
	challengeName := constants.CanonicalChallengeName(len(batches))
	batches = append(batches, finalBatchCols)

	// 6. Fold all the constraints using the folding challenge.
	C := Fold(system.Relations, expr.NewChallenge(challengeName))
	CDag := dag.ExprToDAG(C)
	CDag = CDag.Flatten()
	return Program{
		DerivationPlanScheduled: scheduled,
		Batches:                 batches,
		VanishingRelation:       *CDag,
		N:                       system.N,
	}
}
