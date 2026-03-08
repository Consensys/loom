package cs

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
)

// GetComputationableColumn atm there is only one type of computableColumns, but when there will be more
// we need to switch on the id to know which type is it, and return the correct colum
func GetComputationableColumn(id string) (ComputableColumn, error) {

	// TODO when there is more than one type of computable column, switch on id to know which type is it
	// atm there only one type, LagrangeColumn
	return NewLagrangeColumn(id)
}

// ComputeColumn simplest prover action: build a new column whose name is output[0] and whose computation
// requires executing E on trace
// ComputeColumn computes a new polynomial Q (new column in the trace) such that ith that Q =E(IDs)
// Returns the constraint Q-E(IDs), but does not record it. It is up to the caller to record it in the system.
// func ComputeColumn(S *System, E sym.Expr, IDresult string) (Constraint, error) {
func ComputeColumn(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, output []string) error {

	if len(output) == 0 {
		return fmt.Errorf("output needs to contain at list a name")
	}
	if len(E) == 0 {
		return fmt.Errorf("E needs to contain at list an expression")
	}
	sum, err := univariate.BuildPointwiseEvaluation(trace, E[0], proof.N, mu)
	if err != nil {
		return err
	}
	// record the result polynomial
	err = RegisterColumn(trace, output[0], sum, mu)

	return err
}

// BuildCorrectConstructionConstraint adds a constraint idRes - E=0, to ensure that IdRes is correcly
// constructed with E
func BuildCorrectConstructionConstraint(E sym.Expr, IdRes string) Constraint {
	res := sym.NewCommittedColumn(IdRes)
	E = E.Sub(res)
	return E
}
