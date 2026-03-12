package cs

import (
	"fmt"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/pas/sym"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/giop/utils"
)

type Relation = sym.Expr

// System defines a list of constraints and a list of solver functions form a DAG, need to build extra columns appearing in the
// different constraints (for instance a solver might tell how to compute a grand product column, grand sum column, etc).
type System struct {
	Relations   Relations
	ProverActions []proveractions.ProverAction
	Cache         map[string]int // cache storing already regisetered prover actions. The value is an entry in ProverActions
	N             int
}

// NewSystem creates a new system, consisting of constraints vanishing on X^N-1
func NewSystem(N int) System {
	return System{
		Relations:   make(Relations, 0),
		ProverActions: make(proveractions.ProverActions, 0),
		Cache:         make(map[string]int),
		N:             N,
	}
}

// RegisterProverAction adds a prover action to the underlying System
func (system *System) RegisterProverAction(inputs []sym.Expr, outputs []string, ctx proveractions.Ctx) {

	pa := proveractions.ProverAction{
		Inputs:  inputs,
		Outputs: outputs,
		Ctx:     ctx,
	}
	system.ProverActions = append(system.ProverActions, pa)
}

// Relations list of constraints, that the Columns in a trace must fulfil. The constraints
// are algebraic expression, which evaluted on columns of a trace.Trace of size N mut vanish on X^N-1.
type Relations = []Relation

func (system *System) AssertZero(C Relation) {
	system.Relations = append(system.Relations, C)
}

func (system *System) AssertZeros(C []Relation) {
	system.Relations = append(system.Relations, C...)
}

// RegisterithLagrangeColumn syntactic sugar to add a prover action for creating the i-th lagrange column
// by checking if the action is not already recorded in the cache
func (system *System) RegisterithLagrangeColumn(i int) {
	ctx := proveractions.NewLagrangeContext(i, system.N)
	k := ctx.Key()
	if _, ok := system.Cache[k]; ok {
		return
	}
	// TODO this should be in RegisterProverAction.
	// Pb:
	// 1. key depends only on ctx atm and not on ProverAciont
	// 2. if the action already exists, we should return the output to reuse them and change the api
	system.Cache[k] = len(system.ProverActions)
	system.RegisterProverAction(nil, []string{proveractions.GetLagrangeID(i, system.N)}, proveractions.NewLagrangeContext(i, system.N))
}

// RegisterPermutation syntactic sugar to add a prover action for registering the columns
// encoding a fixed permutation given by S. The output is
// output[:N] = [ID_0, ID_1, ..] -> support of the permutation
// output[N:] = [S_0, S_1, ..] -> interpolation of S permuted entries of [ID_0, ID_1, ..]
// We check if the permutation is not already recorded in the trace
func (system *System) RegisterPermutation(S []int64) ([]string, error) {

	permutationContext := proveractions.NewPermutationContext(S)

	// if the permutation is already registered, we reuse it
	k := permutationContext.Key()
	if _, ok := system.Cache[k]; ok {
		idx := system.Cache[k]
		return system.ProverActions[idx].Outputs, nil
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
		IDid[i] = proveractions.GetPermutationSupportID(i)
		SId[i] = fmt.Sprintf("%s_%d", pid, i)
	}
	allOutputs := append(IDid, SId...)
	system.Cache[k] = len(system.ProverActions)
	system.RegisterProverAction(nil, allOutputs, permutationContext)

	return allOutputs, nil
}
