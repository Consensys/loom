package cs

import (
	"fmt"

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

// ComputeLagrangeColumn prover action to build a computable column, that is a column encoded by a formula.
// If it exists, we don't throw an error, as the column might be generated from different IOPs.
func ComputeLagrangeColumn(trace trace.Trace, _ *Proof, _ []sym.Expr, output []string) error {
	id := output[0]
	cc, err := GetComputationableColumn(output[0])
	if err != nil {
		return err
	}
	if _, ok := trace[output[0]]; ok {
		return nil
	}
	trace[id] = cc.Gen()
	return nil
}

// ComputeColumn simplest prover action: build a new column whose name is output[0] and whose computation
// requires executing E on trace
// ComputeColumn computes a new polynomial Q (new column in the trace) such that ith that Q =E(IDs)
// Returns the constraint Q-E(IDs), but does not record it. It is up to the caller to record it in the system.
// func ComputeColumn(S *System, E sym.Expr, IDresult string) (Constraint, error) {
func ComputeColumn(trace trace.Trace, proof *Proof, E []sym.Expr, output []string) error {

	if len(output) == 0 {
		return fmt.Errorf("output needs to contain at list a name")
	}
	if len(E) == 0 {
		return fmt.Errorf("E needs to contain at list an expression")
	}
	sum, err := univariate.EvalPointWise(trace, E[0], proof.N)
	if err != nil {
		return err
	}
	// record the result polynomial
	err = RegisterColumn(trace, output[0], sum)

	return err
}

// EnforceCorrectConstruction adds a constraint idRes - E=0, to ensure that IdRes is correcly
// constructed with E
func EnforceCorrectConstruction(system *System, E sym.Expr, IdRes string) {
	res := sym.NewCommittedColumn(IdRes)
	E = E.Sub(res)
	system.RegisterConstraint(E)
}
