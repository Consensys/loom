package proveractions

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/trace"
)

var PARegister map[PAIdentifier]Step

type PAIdentifier int

type Step = func(trace.Trace, *Proof, *sync.Mutex, []expr.Expr, []string, Ctx) error

type Ctx interface {
	String() string
	GetID() PAIdentifier
	Key() string
}

// DerivationStep functions telling how to solve for intermediate columns in a list of constraints
type DerivationStep struct {
	Inputs  []expr.Expr
	Outputs []string
	Ctx     Ctx // additional context needed in certain case (e.g. building columns representing a permutation)
}

func (pa DerivationStep) Execute(trace trace.Trace, proof *Proof, mu *sync.Mutex) error {
	if _, ok := PARegister[pa.Ctx.GetID()]; !ok {
		return fmt.Errorf("prover action not found")
	}
	F := PARegister[pa.Ctx.GetID()]
	return F(trace, proof, mu, pa.Inputs, pa.Outputs, pa.Ctx)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type DerivationPlan = []DerivationStep
