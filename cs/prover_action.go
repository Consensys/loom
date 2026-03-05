package cs

import (
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
)

type Action = func(trace.Trace, *Proof, []sym.Expr, []string) error

// ProverAction functions telling how to solve for intermediate columns in a list of constraints
type ProverAction struct {
	Inputs  []sym.Expr
	Outputs []string
	Exec    Action
}

func (proverAction ProverAction) Execute(trace trace.Trace, proof *Proof) error {
	return proverAction.Exec(trace, proof, proverAction.Inputs, proverAction.Outputs)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type ProverActions = []ProverAction

// RegisterProverAction adds a prover action to the underlying System
func (system *System) RegisterProverAction(inputs []sym.Expr, outputs []string, exec Action) {
	pa := ProverAction{
		Inputs:  inputs,
		Outputs: outputs,
		Exec:    exec,
	}
	system.ProverActions = append(system.ProverActions, pa)
}
