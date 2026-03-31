package board

import (
	"fmt"

	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	"github.com/consensys/loom/proof"
)

type CrossModulesLogupBus = proof.CrossModulesLogupBus
type Logup = proof.Logup

func NewLogup(module, column string) Logup {
	return Logup{Module: module, Column: column}
}

func NewCrossModulesLogupBus(positive, negative Logup) CrossModulesLogupBus {
	return CrossModulesLogupBus{
		Positive: []Logup{positive},
		Negative: []Logup{negative},
	}
}

func NewrossModulesLogupBusTuple(positive, negative []Logup) CrossModulesLogupBus {
	return CrossModulesLogupBus{
		Positive: positive,
		Negative: negative,
	}
}

type Builder struct {
	Modules              map[string]*Module
	CountMultiplicity    []CountMultiplicityIO
	FiatShamir           []FiatShamirIO
	GrandProduct         []GrandProductIO // used for permutation within a module, it saves columns compared to logup
	Logup                []LogUpIO
	CrossModulesLogupBus []CrossModulesLogupBus
}

func NewBuilder() Builder {
	var res Builder
	res.Modules = make(map[string]*Module)
	res.CountMultiplicity = make([]CountMultiplicityIO, 0)
	res.FiatShamir = make([]FiatShamirIO, 0)
	res.GrandProduct = make([]GrandProductIO, 0)
	res.Logup = make([]LogUpIO, 0)
	res.CrossModulesLogupBus = make([]CrossModulesLogupBus, 0)
	return res
}

func (b *Builder) AddModule(name string, m Module) {
	b.Modules[name] = &m
}

func (b *Builder) AddCrossModulesLogupBus(cm CrossModulesLogupBus) {
	b.CrossModulesLogupBus = append(b.CrossModulesLogupBus, cm)
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

type FiatShamirIO struct {
	Inputs []Input
	Output string
}

type CountMultiplicityIO struct {
	S, T   expr.Expr
	Sel    expr.Expr // selector, might be nil
	Output string
}

type LogUpIO struct {
	Module string
	E, M   expr.Expr
	Output string
}

type GrandProductIO struct {
	Module string
	N, D   expr.Expr
	Output string
}

func (b *Builder) AddFiatShamirStep(inputs []Input, output string) {
	b.FiatShamir = append(
		b.FiatShamir,
		FiatShamirIO{
			Inputs: inputs,
			Output: output,
		},
	)
}

// S ⊂ T, the ouptut is in T's module
func (b *Builder) AddCountMultiplicityStep(S, T, Sel expr.Expr, output string) {
	countMultiplicityIO := CountMultiplicityIO{
		S:      S,
		T:      T,
		Sel:    Sel, // might be nil
		Output: output,
	}
	b.CountMultiplicity = append(b.CountMultiplicity, countMultiplicityIO)
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

	logupIO := LogUpIO{
		Module: module,
		E:      E,
		M:      M,
		Output: output,
	}
	b.Logup = append(b.Logup, logupIO)

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

	GrandProductIO := GrandProductIO{
		Module: module,
		N:      N,
		D:      D,
		Output: output,
	}
	b.GrandProduct = append(b.GrandProduct, GrandProductIO)

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
	Modules              map[string]CompiledModule
	CountMultiplicity    [][]CountMultiplicityIO
	FiatShamir           []RoundInputs
	GrandProduct         [][]GrandProductIO
	CrossModulesLogupBus []CrossModulesLogupBus
	Logup                [][]LogUpIO
}

func Compile(b *Builder) (Program, error) {

	var res Program

	// --- Step 1: Compute the level of every FiatShamirIO. ---
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
		renameExprs[old] = expr.NewChallenge(canonical)
	}
	applyRename := func(e expr.Expr) expr.Expr {
		return expr.ReplaceLeavesByMap(e, renameExprs)
	}

	// committedOrRotated: keep CommittedColumn and RotatedColumn leaves, drop everything else.
	// ConstantColumn is always excluded by LeavesFull; this config drops Lagrange and Challenge.
	// leaf.Name is the bare base column name for both CommittedColumn and RotatedColumn.
	committedOrRotated := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges())

	// Merge FiatShamirIO per level → RoundInputs (module → deduplicated bare column names).
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

	// --- Step 3: Group CountMultiplicity, Logup and grandProduct by level. ---

	res.CountMultiplicity = make([][]CountMultiplicityIO, nSlots)
	for _, cm := range b.CountMultiplicity {
		sIn := applyRename(cm.S)
		tIn := applyRename(cm.T)
		level := maxCanonicalChallengeLevel(sIn)
		if l := maxCanonicalChallengeLevel(tIn); l > level {
			level = l
		}
		slot := level + 1
		res.CountMultiplicity[slot] = append(res.CountMultiplicity[slot], CountMultiplicityIO{
			S:      sIn,
			T:      tIn,
			Output: cm.Output,
		})
	}

	res.Logup = make([][]LogUpIO, nSlots)
	for _, lu := range b.Logup {
		eIn := applyRename(lu.E)
		mIn := applyRename(lu.M)
		level := maxCanonicalChallengeLevel(eIn)
		if l := maxCanonicalChallengeLevel(mIn); l > level {
			level = l
		}
		slot := level + 1
		res.Logup[slot] = append(res.Logup[slot], LogUpIO{
			Module: lu.Module,
			E:      eIn,
			M:      mIn,
			Output: lu.Output,
		})
	}

	res.GrandProduct = make([][]GrandProductIO, nSlots)
	for _, gp := range b.GrandProduct {
		nIn := applyRename(gp.N)
		dIn := applyRename(gp.D)
		level := maxCanonicalChallengeLevel(nIn)
		if l := maxCanonicalChallengeLevel(dIn); l > level {
			level = l
		}
		slot := level + 1
		res.GrandProduct[slot] = append(res.GrandProduct[slot], GrandProductIO{
			Module: gp.Module,
			N:      nIn,
			D:      dIn,
			Output: gp.Output,
		})
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

	foldingChallenge := expr.NewChallenge(foldingChallengeName)
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

	res.CrossModulesLogupBus = b.CrossModulesLogupBus

	return res, nil
}
