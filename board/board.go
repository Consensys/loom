package board

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	"github.com/consensys/loom/proof"
)

type LogupBus = proof.LogupBus
type Proof = proof.Proof
type PublicEntry = proof.PublicEntry
type PublicInput = proof.PublicInput

func NewLogupBus(positive, negative []string) LogupBus {
	return LogupBus{
		Positive: positive,
		Negative: negative,
	}
}

type Builder struct {
	Modules       map[string]*Module
	LogupBus      []LogupBus
	Steps         []ProverStep
	PublicColumns []string // known columns, precommitted (ex: ql, qr, etc in plonk)
}

func NewBuilder() Builder {
	var res Builder
	res.Modules = make(map[string]*Module)
	res.Steps = make([]ProverStep, 0)
	res.LogupBus = make([]LogupBus, 0)
	return res
}

func (b *Builder) AddPublicColumn(name string) {
	b.PublicColumns = append(b.PublicColumns, name)
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

func (b *Builder) AddFiatShamirStep(E []expr.Expr, out string) {
	ctx := FSCtx{}
	pvStep := ProverStep{
		Ctx:  ctx,
		Ins:  E,
		Out:  out,
		Step: FSStep,
	}
	b.Steps = append(b.Steps, pvStep)
}

func (b *Builder) addMakeEntriesPublicConstraint(module string, E expr.Expr, sel, out string) {
	selExpr := expr.Col(sel)
	outExpr := expr.Public(out)
	rel := E.Mul(selExpr).Sub(outExpr)
	m := b.Modules[module]
	m.AssertZero(rel)
	b.Modules[module] = m
}

func (b *Builder) AddMakeEntriesPublicStep(module string, E expr.Expr, selector, out string, idx []int) {
	m := b.Modules[module]
	ctx := MakeEntriesPublicCtx{Idx: idx, N: m.N}
	pvStep := ProverStep{
		Ctx:  ctx,
		Ins:  []expr.Expr{E},
		Out:  out,
		Step: MakeEntriesPublicStep,
	}
	b.Steps = append(b.Steps, pvStep)

	genSel := SelectorGen{Idx: idx, Name: selector}
	m.GenCol = append(m.GenCol, genSel)
	b.Modules[module] = m
	b.addMakeEntriesPublicConstraint(module, E, selector, out)
}

func (b *Builder) addMakeIthValuePublicConstraint(module string, E expr.Expr, output string, pos int) {
	m := b.Modules[module]
	v := expr.Public(output)
	m.AssertEqualAt(E, v, pos)
}

// AddMakeIthValuePublicStep adds a constraint Lagrange_pos * (expr - expr[pos]), and stores expr[pos] in the proof so the verifier has access to it
// the 1 entry column expr[pos] is registered in the trace
func (b *Builder) AddMakeRelativeIthValuePublicStep(module string, E expr.Expr, out string, pos int) {
	ctx := MakeRelativeIthValuePublicCtx{Pos: pos}
	pvStep := ProverStep{
		Ctx:  ctx,
		Ins:  []expr.Expr{E},
		Out:  out,
		Step: MakeRelativeIthValuePublicStep,
	}
	b.Steps = append(b.Steps, pvStep)
	b.addMakeRelativeIthValuePublicConstraint(module, E, out, pos)
}

func (b *Builder) addMakeRelativeIthValuePublicConstraint(module string, E expr.Expr, output string, pos int) {
	m := b.Modules[module]
	v := expr.Public(output)
	m.AssertEqualRelativeAt(E, v, pos)
}

// AddMakeIthValuePublicStep adds a constraint Lagrange_pos * (expr - expr[pos]), and stores expr[pos] in the proof so the verifier has access to it
// the 1 entry column expr[pos] is registered in the trace
func (b *Builder) AddMakeIthValuePublicStep(module string, E expr.Expr, out string, pos int) {
	ctx := MakeIthValuePublicCtx{Pos: pos}
	pvStep := ProverStep{
		Ctx:  ctx,
		Ins:  []expr.Expr{E},
		Out:  out,
		Step: MakeIthValuePublicStep,
	}
	b.Steps = append(b.Steps, pvStep)
	b.addMakeIthValuePublicConstraint(module, E, out, pos)
}

// S ⊂ T for selS!=0, the ouptut is in T's module
func (b *Builder) AddCountWeightedMultiplicityStep(S, T, selS expr.Expr, output string) {
	cmStep := NewProverStep([]expr.Expr{S, T, selS}, output, CountWeightedMultiplicityStep, CMCtx{})
	b.Steps = append(b.Steps, cmStep)
}

// S ⊂ T, the ouptut is in T's module
func (b *Builder) AddCountMultiplicityStep(S, T expr.Expr, output string) {
	cmStep := NewProverStep([]expr.Expr{S, T}, output, CountMultiplicityStep, CMCtx{})
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
	logupStep := NewProverStep([]expr.Expr{E, M}, output, LogUpStep, LogUpCtx{})
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
	gpStep := NewProverStep([]expr.Expr{N, D}, output, GrandProductStep, GPCtx{})
	b.Steps = append(b.Steps, gpStep)
	b.addGrandProductConstraint(module, N, D, output)
}

// map module -> input (by name, not expr.Expr)
type RoundInputs = map[string][]string

// Program the double slice [][] means that the steps are scheduled
type Program struct {
	Modules               map[string]CompiledModule
	PublicColumns         []string // known columns, precommitted (ex: ql, qr, etc in plonk)
	FScolumnsDependencies [][]string
	LogupBus              []LogupBus
	Steps                 [][]ProverStep
}

func (pg *Program) SetSize(module string, size int) {
	_, ok := pg.Modules[module]
	if !ok {
		panic(fmt.Errorf("module %s not found in the trace", module))
	}
	m := pg.Modules[module]
	m.N = int(ecc.NextPowerOfTwo(uint64(size)))
	m.D = fft.NewDomain(uint64(m.N))
	pg.Modules[module] = m
}

func Compile(b *Builder) (Program, error) {

	config := expr.NewConfig()
	onlyChallenges := expr.NewConfig(expr.OnlyChallenges...)

	isFSStep := make([]bool, len(b.Steps))
	for i, step := range b.Steps {
		_, isFSStep[i] = step.Ctx.(FSCtx)
	}

	// --- Phase 1: Initial level computation via fixed-point. ---
	// level[i] = max(varLevel[dep]+1 for all deps in Ins) or 0 if no known deps.

	stepLevel := make([]int, len(b.Steps))
	varLevel := map[string]int{}
	for i := 0; i < len(b.Steps); i++ {
		stepLevel[i] = -1
	}
	for {
		changed := false
		for i, step := range b.Steps {
			lvl := 0
			for _, inp := range step.Ins {
				for _, leaf := range inp.LeavesFull(config) {
					if l, ok := varLevel[leaf.Name]; ok && l+1 > lvl {
						lvl = l + 1
					}
				}
			}
			if stepLevel[i] != lvl {
				stepLevel[i] = lvl
				changed = true
			}
			varLevel[step.Out] = lvl
		}
		if !changed {
			break
		}
	}

	// --- Phase 2: Assign each FS step a "round". ---
	// Two FS steps belong to the same round when neither's challenge feeds the
	// other's inputs (directly or transitively through FS outputs only).
	// round[i] = 1 + max round of any FS step whose challenge appears in step i's inputs.

	challengeProducer := map[string]int{} // challenge name → index of the FS step that outputs it
	for i, step := range b.Steps {
		if isFSStep[i] {
			challengeProducer[step.Out] = i
		}
	}

	fsRound := make([]int, len(b.Steps))
	for i := 0; i < len(b.Steps); i++ {
		fsRound[i] = -1
	}
	for {
		changed := false
		for i, step := range b.Steps {
			if !isFSStep[i] {
				continue
			}
			round := 0
			for _, inp := range step.Ins {
				for _, name := range inp.Leaves(onlyChallenges) {
					if j, ok := challengeProducer[name]; ok && fsRound[j]+1 > round {
						round = fsRound[j] + 1
					}
				}
			}
			if fsRound[i] != round {
				fsRound[i] = round
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// --- Phase 3: Sync FS steps in the same round to the max level in that round. ---

	maxLevelForRound := map[int]int{}
	for i := range b.Steps {
		if !isFSStep[i] {
			continue
		}
		r := fsRound[i]
		if l, ok := maxLevelForRound[r]; !ok || stepLevel[i] > l {
			maxLevelForRound[r] = stepLevel[i]
		}
	}
	for i, step := range b.Steps {
		if !isFSStep[i] {
			continue
		}
		stepLevel[i] = maxLevelForRound[fsRound[i]]
		varLevel[step.Out] = stepLevel[i]
	}

	// --- Phase 4: Re-propagate non-FS levels, skipping over FS levels. ---
	// FS steps are frozen; non-FS steps are recomputed from dependencies,
	// then bumped past any FS level they land on.

	fsLevelSet := map[int]bool{}
	for i := range b.Steps {
		if isFSStep[i] {
			fsLevelSet[stepLevel[i]] = true
		}
	}

	for {
		changed := false
		for i, step := range b.Steps {
			if isFSStep[i] {
				continue
			}
			lvl := 0
			for _, inp := range step.Ins {
				for _, leaf := range inp.LeavesFull(config) {
					if l, ok := varLevel[leaf.Name]; ok && l+1 > lvl {
						lvl = l + 1
					}
				}
			}
			for fsLevelSet[lvl] {
				lvl++
			}
			if stepLevel[i] != lvl {
				stepLevel[i] = lvl
				changed = true
			}
			varLevel[step.Out] = lvl
		}
		if !changed {
			break
		}
	}

	// --- Phase 5: Group steps by level. ---

	maxLevel := 0
	for _, l := range stepLevel {
		if l > maxLevel {
			maxLevel = l
		}
	}

	var res Program
	res.Steps = make([][]ProverStep, maxLevel+1)
	for i, step := range b.Steps {
		res.Steps[stepLevel[i]] = append(res.Steps[stepLevel[i]], step)
	}

	// --- Phase 6: Add a FiatShamir at the highest level, to sample the folding challenge ---

	res.Steps = append(res.Steps, make([]ProverStep, 1))
	foldingChallenge, err := constants.RandomString(10)
	if err != nil {
		return res, err
	}
	res.Steps[maxLevel+1][0] = NewProverStep(nil, foldingChallenge, FSStep, FSCtx{})

	// --- Phase 7: Collapse FS steps of the same round (level) into one canonical step. ---

	// Config: keep CommittedColumn and RotatedColumn; discard LagrangeColumn, ChallengeColumn and PublicColumns.
	noLagrangeNoChallengeNoPublicCols := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())

	// Step 7a: Identify which levels are FS steps and assign round indices in level order.
	// from the preivous Phase, a level either contains only FS, or no FS at all
	levelToRound := map[int]int{}
	roundIdx := 0
	for lvl := 0; lvl < len(res.Steps); lvl++ {
		for _, step := range res.Steps[lvl] {
			if _, ok := step.Ctx.(FSCtx); ok {
				levelToRound[lvl] = roundIdx
				roundIdx++
				break // only one round per FS level
			}
		}
	}
	numRounds := roundIdx

	// Step 7b: Build rename map: old FS output name → canonical "challenge@loom_<i>".
	renameExprs := make(map[string]expr.Expr, numRounds)
	for lvl, round := range levelToRound {
		canonical := constants.CanonicalChallengeName(round)
		for _, step := range res.Steps[lvl] {
			if _, ok := step.Ctx.(FSCtx); ok {
				renameExprs[step.Out] = expr.Challenge(canonical)
			}
		}
	}
	applyRename := func(e expr.Expr) expr.Expr {
		return expr.ReplaceLeavesByMap(e, renameExprs)
	}

	// Step 7c: Apply rename to module relations in the builder.
	for _, m := range b.Modules {
		for i, rel := range m.Relations {
			m.Relations[i] = applyRename(rel)
		}
	}

	// Step 7d: Apply rename to non-FS step Ins in res.Steps.
	for lvl := range res.Steps {
		for j := range res.Steps[lvl] {
			if _, ok := res.Steps[lvl][j].Ctx.(FSCtx); ok {
				continue
			}
			for k, inp := range res.Steps[lvl][j].Ins {
				res.Steps[lvl][j].Ins[k] = applyRename(inp)
			}
		}
	}

	// Step 7e: Build res.FiatShamir and replace per-round FS steps with a single canonical one.
	res.PublicColumns = make([]string, len(b.PublicColumns))
	copy(res.PublicColumns, b.PublicColumns)
	res.FScolumnsDependencies = make([][]string, numRounds)
	prevCovered := map[string]bool{}
	for _, n := range res.PublicColumns {
		prevCovered[n] = true
	}
	for lvl := 0; lvl < len(res.Steps); lvl++ {
		round, ok := levelToRound[lvl]
		if !ok {
			continue
		}
		canonical := constants.CanonicalChallengeName(round)

		// Collect input column names for this round (disjoint from all previous rounds).
		for _, step := range res.Steps[lvl] {
			if _, ok := step.Ctx.(FSCtx); !ok {
				continue
			}
			for _, inp := range step.Ins {
				for _, leaf := range inp.LeavesFull(noLagrangeNoChallengeNoPublicCols) {
					if !prevCovered[leaf.Name] {
						prevCovered[leaf.Name] = true
						res.FScolumnsDependencies[round] = append(res.FScolumnsDependencies[round], leaf.Name)
					}
				}
			}
		}

		// Replace all FS steps at this level with one canonical step (Ins is nil;
		// callers use res.FiatShamir[round] for the committed column list).
		newSteps := make([]ProverStep, 0, len(res.Steps[lvl]))
		for _, step := range res.Steps[lvl] {
			if _, ok := step.Ctx.(FSCtx); !ok {
				newSteps = append(newSteps, step)
			}
		}
		newSteps = append(newSteps, NewProverStep(nil, canonical, FSStep, FSCtx{}))
		res.Steps[lvl] = newSteps
	}

	// --- Phase 8: Extend the last FiatShamir entry (folding round) with all
	// module-relation columns not yet covered by any earlier round. ---
	// The last canonical FS step already has Ins=nil (set in phase 7e).

	lastRound := numRounds - 1
	for _, m := range b.Modules {
		for _, rel := range m.Relations {
			for _, leaf := range rel.LeavesFull(noLagrangeNoChallengeNoPublicCols) {
				if !prevCovered[leaf.Name] {
					prevCovered[leaf.Name] = true
					res.FScolumnsDependencies[lastRound] = append(res.FScolumnsDependencies[lastRound], leaf.Name)
				}
			}
		}
	}

	// --- Phase 9: create the compiled module. Fold the relations in each module,
	// and create a domain of the module.N for each module
	res.Modules = map[string]CompiledModule{}
	lastChallenge := expr.Challenge(fmt.Sprintf("challenge@loom_%d", lastRound))
	for k, m := range b.Modules {
		var cm CompiledModule
		cm.Name = m.Name
		cm.GenCol = make([]Gen, len(m.GenCol))
		copy(cm.GenCol, m.GenCol)
		cm.N = m.N
		cm.D = fft.NewDomain(uint64(m.N))
		foldedRelation := expr.Fold(lastChallenge, m.Relations)
		cm.VanishingRelation = dag.ExprToDAG(foldedRelation)
		res.Modules[k] = cm
	}

	// get the logup bus
	res.LogupBus = make([]LogupBus, len(b.LogupBus))
	copy(res.LogupBus, b.LogupBus)

	return res, nil
}
