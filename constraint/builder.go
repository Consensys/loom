package constraint

import (
	"fmt"

	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/utils"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

type Relation = expr.Expr

// Builder defines a list of constraints and a list of solver functions form a DAG, need to build extra columns appearing in the
// different constraints (for instance a solver might tell how to compute a grand product column, grand sum column, etc).
type Builder struct {
	Relations      Relations
	DerivationPlan []derive.DerivationStep
	Cache          map[string]int // cache storing already regisetered prover actions. The value is an entry in DerivationPlan
	N              int
}

// NewBuilder creates a new system, consisting of constraints vanishing on X^N-1
func NewBuilder(N int) Builder {
	return Builder{
		Relations:      make(Relations, 0),
		DerivationPlan: make(derive.DerivationPlan, 0),
		Cache:          make(map[string]int),
		N:              N,
	}
}

// RegisterDerivationStep adds a prover action to the underlying Builder
func (system *Builder) RegisterDerivationStep(inputs []expr.Expr, outputs []string, ctx derive.StepContext) {

	pa := derive.DerivationStep{
		Inputs:      inputs,
		Outputs:     outputs,
		StepContext: ctx,
	}
	system.DerivationPlan = append(system.DerivationPlan, pa)
}

// Relations list of constraints, that the Columns in a trace must fulfil. The constraints
// are algebraic expression, which evaluted on columns of a trace.Trace of size N mut vanish on X^N-1.
type Relations = []Relation

func (system *Builder) AssertZero(C Relation) {
	system.Relations = append(system.Relations, C)
}

func (system *Builder) AssertAllZero(C []Relation) {
	system.Relations = append(system.Relations, C...)
}

func (system *Builder) AddColumn(name string, content []koalabear.Element) {
	system.RegisterDerivationStep(nil, []string{"F1"}, derive.NewBuilderContext(content))
}

// AddLagrangeColumn syntactic sugar to add a prover action for creating the i-th lagrange column
// by checking if the action is not already recorded in the cache
func (system *Builder) AddLagrangeColumn(i int) {
	ctx := derive.NewLagrangeContext(i, system.N)
	k := ctx.Key()
	if _, ok := system.Cache[k]; ok {
		return
	}
	// TODO this should be in RegisterDerivationStep.
	// Pb:
	// 1. key depends only on ctx atm and not on ProverAciont
	// 2. if the action already exists, we should return the output to reuse them and change the api
	system.Cache[k] = len(system.DerivationPlan)
	system.RegisterDerivationStep(nil, []string{derive.GetLagrangeID(i, system.N)}, derive.NewLagrangeContext(i, system.N))
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
	system.RegisterDerivationStep(nil, allOutputs, permutationContext)

	return allOutputs, nil
}
