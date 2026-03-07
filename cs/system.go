package cs

import (
	"github.com/consensys/giop/pas/sym"
)

type Constraint = sym.Expr

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

// RegisterProverAction adds a prover action to the underlying System
func (system *System) RegisterProverAction(inputs []sym.Expr, outputs []string, exec Action) {
	pa := ProverAction{
		Inputs:  inputs,
		Outputs: outputs,
		Exec:    exec,
	}
	system.ProverActions = append(system.ProverActions, pa)
}

// Constraints list of constraints, that the Columns in a trace must fulfil. The constraints
// are algebraic expression, which evaluted on columns of a trace.Trace of size N mut vanish on X^N-1.
type Constraints = []Constraint

func (system *System) RegisterConstraint(C Constraint) {
	system.Constraints = append(system.Constraints, C)
}

func (system *System) RegisterConstraints(C []Constraint) {
	system.Constraints = append(system.Constraints, C...)
}

// RegisterithLagrangeColumn syntactic sugar to add a prover action for creating the i-th lagrange column
func (system *System) RegisterithLagrangeColumn(i int) {
	system.RegisterProverAction(nil, []string{GetLagrangeID(i, system.N)}, ComputeLagrangeColumn)
}
