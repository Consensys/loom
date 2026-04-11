package board

import (
	"fmt"

	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	"github.com/consensys/loom/proof"
)

type LogupBus = proof.LogupBus
type LogupInfo = proof.LogupInfo

func NewLogupInfo(module, column string) LogupInfo {
	return LogupInfo{Module: module, Column: column}
}

func NewLogupBus(positive, negative LogupInfo) LogupBus {
	return LogupBus{
		Positive: []LogupInfo{positive},
		Negative: []LogupInfo{negative},
	}
}

func NewrossModulesLogupBusTuple(positive, negative []LogupInfo) LogupBus {
	return LogupBus{
		Positive: positive,
		Negative: negative,
	}
}

type Builder struct {
	Modules    map[string]*Module
	FiatShamir []FiatShamirStep
	LogupBus   []LogupBus
	Steps      []ProverStep
}

func NewBuilder() Builder {
	var res Builder
	res.Modules = make(map[string]*Module)
	// res.CountMultiplicity = make([]CountMultiplicityStep, 0)
	res.FiatShamir = make([]FiatShamirStep, 0)
	// res.GrandProduct = make([]GrandProductStep, 0)
	// res.Logup = make([]LogUpStep, 0)
	res.Steps = make([]ProverStep, 0)
	res.LogupBus = make([]LogupBus, 0)
	return res
}

func (b *Builder) AddModule(name string, m Module) {
	b.Modules[name] = &m
}

func (b *Builder) AddLogupBus(cm LogupBus) {
	b.LogupBus = append(b.LogupBus, cm)
}

func (b *Builder) AssertEqualAt(module string, A, B expr.Expr, i int) error {
	m, ok := b.Modules[module]
	if !ok {
		return fmt.Errorf("module %s not found in the list", module)
	}
	m.AssertEqualAt(A, B, i)
	b.Modules[module] = m
	return nil
}

func (b *Builder) AssertZero(module string, relation expr.Expr) error {
	m, ok := b.Modules[module]
	if !ok {
		return fmt.Errorf("module %s not found in the list", module)
	}
	m.AssertZero(relation)
	b.Modules[module] = m
	return nil
}

type Input struct {
	Module string
	In     expr.Expr
}

type Output struct {
	Module  string
	ColName string
}

type FiatShamirStep struct {
	Inputs []Input
	Output string
}

func (b *Builder) AddFiatShamirStep(inputs []Input, output string) {
	b.FiatShamir = append(
		b.FiatShamir,
		FiatShamirStep{
			Inputs: inputs,
			Output: output,
		},
	)
}

func (b *Builder) addPickValueConstraint(module string, E expr.Expr, output string, pos int) {
	m := b.Modules[module]
	v := expr.Value(output)
	m.AssertEqualAt(E, v, pos)
}

func (b *Builder) AddPickValueStep(module string, E expr.Expr, out string, pos int) {
	ctx := PickValueCtx{Pos: pos}
	pvStep := ProverStep{
		Ctx: ctx,

		Ins:  []expr.Expr{E},
		Out:  out,
		Step: PickValueStep,
	}
	b.Steps = append(b.Steps, pvStep)
	b.addPickValueConstraint(module, E, out, pos)
}

// S ⊂ T, the ouptut is in T's module
func (b *Builder) AddCountMultiplicityStep(S, T expr.Expr, output string) {
	cmStep := NewProverStep([]expr.Expr{S, T}, output, CountMultiplicityStep)
	b.Steps = append(b.Steps, cmStep)
}

func (b *Builder) addLogupConstraint(module string, E, M expr.Expr, output string) {

	m := b.Modules[module]

	// logup * E - logup-1*E - M = 0, except at 0
	recurrenceRelation := expr.Col(output).Mul(E).Sub(expr.Rot(output, -1).Mul(E)).Sub(M)
	m.AssertZeroExceptAt(recurrenceRelation, 0)

	// logup[0]*E[0] - M[0] = 0
	boundaryRelation := expr.Col(output).Mul(E).Sub(M)
	m.AssertZeroAt(boundaryRelation, 0)
}

// AddLogupStep register the action of computing the column interpolating the running sum
// \Sigma_j<=i M[i]/E[i]
func (b *Builder) AddLogupStep(module string, E, M expr.Expr, output string) {
	logupStep := NewProverStep([]expr.Expr{E, M}, output, LogUpStep)
	b.Steps = append(b.Steps, logupStep)
	b.addLogupConstraint(module, E, M, output)
}

func (b *Builder) addGrandProductConstraint(module string, N, D expr.Expr, output string) {
	m := b.Modules[module]
	gp := expr.Col(output)
	gpshifted := expr.Rot(output, 1)
	relation := gpshifted.Mul(D).Sub(gp.Mul(N))
	m.AssertZero(relation)
}

func (b *Builder) AddGrandProductStep(module string, N, D expr.Expr, output string) {
	gpStep := NewProverStep([]expr.Expr{N, D}, output, GrandProductStep)
	b.Steps = append(b.Steps, gpStep)
	b.addGrandProductConstraint(module, N, D, output)
}

// map module -> input (by name, not expr.Expr)
type RoundInputs = map[string][]string

// Program the double slice [][] means that the steps are scheduled:
// [0][] -> contains all steps that can be executed before FS
// [1][] -> contains all steps that can be executed after the first FS round
// [2][] -> contains all steps that can be executed after the second FS round
// etc
type Program struct {
	Modules    map[string]CompiledModule
	FiatShamir []RoundInputs
	LogupBus   []LogupBus
	Steps      [][]ProverStep
}

func Compile(b *Builder) (Program, error) {

	var res Program

	// --- Step 1: Compute the level of every FiatShamirStep. ---
	// Level = max(level of challenge deps in inputs) + 1, or 0 if no challenge deps.
	// Iterate to a fixed point so the result is correct regardless of registration order.

	challengeLevel := map[string]int{} // old challenge name → its level
	stepLevel := make([]int, len(b.FiatShamir))
	for i := range b.FiatShamir {
		stepLevel[i] = -1
	}

	onlyChallenges := expr.NewConfig(expr.OnlyChallenges...)

	for {
		changed := false
		for i, fs := range b.FiatShamir {
			level := 0
			for _, inp := range fs.Inputs {
				for _, name := range inp.In.Leaves(onlyChallenges) {
					if l, ok := challengeLevel[name]; ok && l+1 > level {
						level = l + 1
					}
				}
			}
			if stepLevel[i] != level {
				stepLevel[i] = level
				changed = true
			}
			challengeLevel[fs.Output] = level
		}
		if !changed {
			break
		}
	}

	// --- Step 2: Build rename map (old challenge name → canonical "loom@challenge_k"). ---

	fsByLevel := map[int][]int{}
	for i := range b.FiatShamir {
		fsByLevel[stepLevel[i]] = append(fsByLevel[stepLevel[i]], i)
	}

	maxLevel := -1
	for level := range fsByLevel {
		if level > maxLevel {
			maxLevel = level
		}
	}

	rename := map[string]string{}
	for level, indices := range fsByLevel {
		canonical := constants.CanonicalChallengeName(level)
		for _, idx := range indices {
			rename[b.FiatShamir[idx].Output] = canonical
		}
	}

	renameExprs := make(map[string]expr.Expr, len(rename))
	for old, canonical := range rename {
		renameExprs[old] = expr.Challenge(canonical)
	}
	applyRename := func(e expr.Expr) expr.Expr {
		return expr.ReplaceLeavesByMap(e, renameExprs)
	}

	// committedOrRotated: keep CommittedColumn and RotatedColumn leaves, drop everything else.
	// ConstantColumn is always excluded by LeavesFull; this config drops Lagrange and Challenge.
	// leaf.Name is the bare base column name for both CommittedColumn and RotatedColumn.
	committedOrRotated := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges())

	// Merge FiatShamirStep per level → RoundInputs (module → deduplicated bare column names).
	if maxLevel >= 0 {
		res.FiatShamir = make([]RoundInputs, maxLevel+1)
		for level := 0; level <= maxLevel; level++ {
			round := make(RoundInputs)
			seen := map[string]bool{}
			for _, idx := range fsByLevel[level] {
				for _, inp := range b.FiatShamir[idx].Inputs {
					for _, leaf := range applyRename(inp.In).LeavesFull(committedOrRotated) {
						if !seen[leaf.Name] {
							seen[leaf.Name] = true
							round[inp.Module] = append(round[inp.Module], leaf.Name)
						}
					}
				}
			}
			res.FiatShamir[level] = round
		}
	}

	// maxCanonicalChallengeLevel returns the highest k in any "loom@challenge_k" leaf of e, or -1.
	maxCanonicalChallengeLevel := func(e expr.Expr) int {
		max := -1
		for _, name := range e.Leaves(onlyChallenges) {
			var level int
			if _, err := fmt.Sscanf(name, "loom@challenge_%d", &level); err == nil && level > max {
				max = level
			}
		}
		return max
	}

	nSlots := maxLevel + 2
	if nSlots < 1 {
		nSlots = 1
	}

	// --- Step 3: Group Steps by level. ---

	res.Steps = make([][]ProverStep, nSlots)
	for _, s := range b.Steps {
		level := -1
		for k, e := range s.Ins {
			if e == nil {
				continue
			}
			s.Ins[k] = applyRename(e)
			if l := maxCanonicalChallengeLevel(s.Ins[k]); l > level {
				level = l
			}
		}
		slot := level + 1
		res.Steps[slot] = append(res.Steps[slot], s)
	}

	// --- Step 4: Append the folding-challenge round to res.FiatShamir.
	// Its inputs are committed/rotated columns from module relations (after rename)
	// not already covered by any previous round.

	prevCovered := map[string]bool{}
	for _, round := range res.FiatShamir {
		for _, cols := range round {
			for _, name := range cols {
				prevCovered[name] = true
			}
		}
	}

	foldingRound := make(RoundInputs)
	seenNew := map[string]bool{}
	for modName, module := range b.Modules {
		for _, rel := range module.Relations {
			for _, leaf := range applyRename(rel).LeavesFull(committedOrRotated) {
				if !prevCovered[leaf.Name] && !seenNew[leaf.Name] {
					seenNew[leaf.Name] = true
					foldingRound[modName] = append(foldingRound[modName], leaf.Name)
				}
			}
		}
	}

	foldingChallengeName := constants.CanonicalChallengeName(len(res.FiatShamir))
	res.FiatShamir = append(res.FiatShamir, foldingRound)

	// --- Step 5: fold each module's relations with the folding challenge and convert to a DAG.

	foldingChallenge := expr.Challenge(foldingChallengeName)
	res.Modules = make(map[string]CompiledModule, len(b.Modules))
	for modName, module := range b.Modules {
		rels := make([]expr.Expr, len(module.Relations))
		for i, rel := range module.Relations {
			rels[i] = applyRename(rel)
		}
		var folded expr.Expr
		switch len(rels) {
		case 0:
			continue
		case 1:
			folded = rels[0]
		default:
			folded = expr.Fold(foldingChallenge, rels)
		}
		d := dag.ExprToDAG(folded).Flatten()
		res.Modules[modName] = CompiledModule{
			VanishingRelation: *d,
			GenCol:            module.GenCol,
			N:                 module.N,
		}
	}

	res.LogupBus = b.LogupBus

	return res, nil
}
