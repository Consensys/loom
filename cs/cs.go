package cs

import (
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
)

type Constraint = sym.Expr

// Constraints list of constraints, that the Columns in a trace must fulfil. The constraints
// are algebraic expression, which evaluted on columns of a trace.Trace of size N mut vanish on X^N-1.
type Constraints = []Constraint

type Action = func(trace.Trace, *Proof, []sym.Expr, []string) error

// ProverAction functions telling how to solve for intermediate columns in a list of constraints
type ProverAction struct {
	Inputs  []sym.Expr
	Outputs []string
	Exec    Action
}

func (system *System) RegisterConstraint(C Constraint) {
	system.Constraints = append(system.Constraints, C)
}

func (system *System) RegisterConstraints(C []Constraint) {
	system.Constraints = append(system.Constraints, C...)
}

// RegisterithLagrangeColumn syntactic sugar to add a prover action for creating the i-th lagrange column
func (system *System) RegisterithLagrangeColumn(i int) {
	system.RegisterProverAction(nil, []string{GetLagrangeID(i, system.N)}, AddComputableColumn)
}

// RegisterProverAction adds a prover action to the underlying System
func (system *System) RegisterProverAction(inputs []sym.Expr, outputs []string, exec Action) {
	pa := ProverAction{
		Inputs:  inputs,
		Outputs: outputs,
		Exec:    exec,
	}
	system.ProverActions = append(system.ProverActions, pa)
}

func (proverAction ProverAction) Execute(trace trace.Trace, proof *Proof) error {
	return proverAction.Exec(trace, proof, proverAction.Inputs, proverAction.Outputs)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type ProverActions = []ProverAction

// System defines a list of constraints and a list of solver functions form a DAG, need to build extra columns appearing in the
// different constraints (for instance a solver might tell how to compute a grand product column, grand sum column, etc).
type System struct {
	Constraints   Constraints
	ProverActions ProverActions
	N             int
}

// NewSystem creates a new system, consisting of constraints vanishing on X^N-1
func NewSystem(N int) System {
	return System{
		Constraints:   make(Constraints, 0),
		ProverActions: make(ProverActions, 0),
		N:             N,
	}
}
