package derive

import (
	"fmt"
	"sync"

	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/trace"
)

var StepRegistry map[StepKind]Step

type StepKind int

type Step = func(trace.Trace, *Proof, *sync.Mutex, []expr.Expr, []string, StepContext) error

type StepContext interface {
	String() string
	GetID() StepKind
	Key() string
}

// DerivationStep functions telling how to solve for intermediate columns in a list of constraints
type DerivationStep struct {
	Inputs      []expr.Expr
	Outputs     []string
	StepContext StepContext // additional context needed in certain case (e.g. building columns representing a permutation)
}

func (pa DerivationStep) Execute(trace trace.Trace, proof *Proof, mu *sync.Mutex) error {
	if _, ok := StepRegistry[pa.StepContext.GetID()]; !ok {
		return fmt.Errorf("prover action not found")
	}
	F := StepRegistry[pa.StepContext.GetID()]
	return F(trace, proof, mu, pa.Inputs, pa.Outputs, pa.StepContext)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type DerivationPlan = []DerivationStep
