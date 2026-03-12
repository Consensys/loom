package cs

import (
	"sync"
	"testing"

	"github.com/consensys/giop/expr"
	proveractions "github.com/consensys/giop/prover_actions"
)

func TestGrandSumRelation(t *testing.T) {

	size := 16

	trace := BuildRandomTrace(t, size)
	system := NewBuilder(size)
	constraints := BuildGrandSumRelations(expr.Col("M"), expr.Col("E"), "GrandSum", size)
	system.AssertAllZero(constraints)
	proof := proveractions.NewProof(size)
	E := expr.Col("E")
	M := expr.Col("M")
	var mu sync.Mutex
	err := proveractions.ComputeGrandSum(trace, &proof, &mu, []expr.Expr{M, E}, []string{"GrandSum"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	proveractions.ComputeLagrangeColumn(trace, nil, &mu, nil, []string{proveractions.GetLagrangeID(0, size)}, nil)

	err = BruteForceChecker(trace, system.Relations, system.N)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(trace, system.Relations, system.N)
	if err != nil {
		t.Fatal(err)
	}

}
