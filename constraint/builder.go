package constraint

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/utils"
	"github.com/consensys/loom/proof"
)

type Relation = expr.Expr

// Builder defines a list of constraints and a list of solver functions form a DAG, need to build extra columns appearing in the
// different constraints (for instance a solver might tell how to compute a grand product column, grand sum column, etc).
type Builder struct {
	Relations      Relations
	DerivationPlan []derive.DerivationStep
	Cache          map[string]int // cache storing already regisetered prover actions. The value is an entry in DerivationPlan
	PublicInputs   proof.PublicInputs
	N              int
}

// NewBuilder creates a new system, consisting of constraints vanishing on X^N-1
func NewBuilder(N int, publicInputs proof.PublicInputs) Builder {
	res := Builder{
		Relations:      make(Relations, 0),
		DerivationPlan: make(derive.DerivationPlan, 0),
		Cache:          make(map[string]int),
		N:              N,
		PublicInputs:   publicInputs,
	}
	if res.PublicInputs == nil {
		res.PublicInputs = make(proof.PublicInputs)
	}
	return res
}

func (system *Builder) registerDerivationStep(inputs []expr.Expr, outputs []string, ctx derive.StepContext) {
	system.DerivationPlan = append(system.DerivationPlan, derive.DerivationStep{
		Inputs:      inputs,
		Outputs:     outputs,
		StepContext: ctx,
	})
}

// AddChallengeStep registers a Fiat-Shamir challenge derivation: the challenge named output
// is bound to all columns in inputs.
func (system *Builder) AddChallengeStep(inputs []expr.Expr, output string) {
	system.registerDerivationStep(inputs, []string{output}, derive.NewFiatShamirContext(system.PublicInputs))
}

// AddGrandProductStep registers a grand product column derivation.
// inputs must be [E1, E2]; the column named output satisfies R[0]=1, R[i+1]=R[i]·E1[i]/E2[i].
func (system *Builder) AddGrandProductStep(inputs []expr.Expr, output string) {
	system.registerDerivationStep(inputs, []string{output}, derive.NewIOPStepContext(derive.GRAND_PRODUCT))
}

// AddGrandSumStep registers a grand sum column derivation.
// inputs must be [M, E]; the column named output satisfies R[i] = Σ_{j≤i} M[j]/E[j].
func (system *Builder) AddGrandSumStep(inputs []expr.Expr, output string) {
	system.registerDerivationStep(inputs, []string{output}, derive.NewIOPStepContext(derive.GRAND_SUM))
}

// AddMultiplicityStep registers a multiplicity column derivation.
// inputs must be [S, T]; the column named output satisfies M[i] = #{j | S[j]=T[i]}.
func (system *Builder) AddMultiplicityStep(inputs []expr.Expr, output string) {
	system.registerDerivationStep(inputs, []string{output}, derive.NewIOPStepContext(derive.MULTIPLICITY))
}

// AddFilteredAccStep registers a filtered accumulator column derivation.
// inputs must be [E, F, alpha] where F is a binary filter column.
func (system *Builder) AddFilteredAccStep(inputs []expr.Expr, output string) {
	system.registerDerivationStep(inputs, []string{output}, derive.NewIOPStepContext(derive.FITLERED_ACC_POLY))
}

// AddComputeColumnStep registers a pointwise column computation: output[i] = input(trace[i]).
func (system *Builder) AddComputeColumnStep(input expr.Expr, output string) {
	system.registerDerivationStep([]expr.Expr{input}, []string{output}, derive.NewIOPStepContext(derive.COMPUTE_COL))
}

// Relations list of constraints, that the Columns in a trace must fulfil. The constraints
// are algebraic expression, which evaluted on columns of a trace.Trace of size N mut vanish on X^N-1.
type Relations = []Relation

// AssertZero asserts that C vanishes on the domain
func (system *Builder) AssertZero(C Relation) {
	system.Relations = append(system.Relations, C)
}

// AssertAllZero asserts that all C's vanish on the domain
func (system *Builder) AssertAllZero(C []Relation) {
	system.Relations = append(system.Relations, C...)
}

// AssertEqualAt assert that at row i, E1 and E2 are equal
func (system *Builder) AssertEqualAt(E1, E2 Relation, i int) {
	lagrangeID := derive.GetLagrangeID(i, system.N)
	localRelation := expr.Virtual(lagrangeID).Mul(E1.Sub(E2))
	system.AssertZero(localRelation)
	system.AddLagrangeColumn(i)
}

// AssertEqualAt assert that E1=E2 on the domain, except at row i
func (system *Builder) AssertZeroExceptAt(E1, E2 Relation, i int) {
	system.AddLagrangeColumn(i)
	lagrangeID := derive.GetLagrangeID(i, system.N)
	localRelation := expr.Virtual(lagrangeID).Sub(expr.Const(koalabear.One())).Mul(E1.Sub(E2))
	system.AssertZero(localRelation)
}

func (system *Builder) AddColumn(name string, content []koalabear.Element) {
	system.registerDerivationStep(nil, []string{"F1"}, derive.NewBuilderContext(content))
}

// AddLagrangeColumn syntactic sugar to add a prover action for creating the i-th lagrange column
// by checking if the action is not already recorded in the cache
func (system *Builder) AddLagrangeColumn(i int) {
	ctx := derive.NewLagrangeContext(i, system.N)
	k := ctx.Key()
	if _, ok := system.Cache[k]; ok {
		return
	}
	system.Cache[k] = len(system.DerivationPlan)
	system.registerDerivationStep(nil, []string{derive.GetLagrangeID(i, system.N)}, derive.NewLagrangeContext(i, system.N))
}

// AddPermutationColumns syntactic sugar to add a prover action for registering the columns
// encoding a fixed permutation given by S. The output is
// output[:N] = [ID_0, ID_1, ..] -> support of the permutation
// output[N:] = [S_0, S_1, ..] -> interpolation of S permuted entries of [ID_0, ID_1, ..]
// We check if the permutation is not already recorded in the trace
func (system *Builder) AddPermutationColumns(S []int64) ([]string, error) {

	permutationContext := derive.NewPermutationContext(S)

	// if the permutation is already registered, we reuse it
	k := permutationContext.Key()
	if _, ok := system.Cache[k]; ok {
		idx := system.Cache[k]
		return system.DerivationPlan[idx].Outputs, nil
	}

	// otherwise we register it
	if len(S)%system.N != 0 {
		return nil, fmt.Errorf("size of permutation must be a multiple of %d, got %d", system.N, len(S))
	}
	nbChunks := len(S) / system.N
	IDid := make([]string, nbChunks)
	SId := make([]string, nbChunks)
	pid, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return nil, err
	}
	for i := 0; i < nbChunks; i++ {
		IDid[i] = derive.GetPermutationSupportID(i)
		SId[i] = fmt.Sprintf("%s_%d", pid, i)
	}
	allOutputs := append(IDid, SId...)
	system.Cache[k] = len(system.DerivationPlan)
	system.registerDerivationStep(nil, allOutputs, permutationContext)

	return allOutputs, nil
}

// BuildCorrectConstructionRelation adds a constraint idRes - E=0, to ensure that IdRes is correcly
// constructed with E
func BuildCorrectConstructionRelation(E expr.Expr, IdRes string) Relation {
	res := expr.Col(IdRes)
	E = E.Sub(res)
	return E
}
