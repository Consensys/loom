package proveractions

import (
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
)

type Action = func(trace.Trace, *Proof, *sync.Mutex, []sym.Expr, []string) error

// ProverAction functions telling how to solve for intermediate columns in a list of constraints
type ProverAction struct {
	Inputs  []sym.Expr
	Outputs []string
	Exec    Action
}

func (proverAction ProverAction) Execute(trace trace.Trace, proof *Proof, mu *sync.Mutex) error {
	return proverAction.Exec(trace, proof, mu, proverAction.Inputs, proverAction.Outputs)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type ProverActions = []ProverAction
