package constraint

import (
	"sync"
	"testing"

	"github.com/consensys/loom/expr"
	derive "github.com/consensys/loom/internal/derive"
)

func TestGrandSumRelation(t *testing.T) {

	size := 16

	trace := BuildRandomTrace(t, size)
	system := NewBuilder(size, nil)
	constraints := BuildGrandSumRelations(expr.Col("M"), expr.Col("E"), "GrandSum", size)
	system.AssertAllZero(constraints)
	proof := derive.NewProof(size)
	E := expr.Col("E")
	M := expr.Col("M")
	var mu sync.Mutex
	err := derive.ComputeGrandSum(trace, &proof, &mu, []expr.Expr{M, E}, []string{"GrandSum"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	derive.ComputeLagrangeColumn(trace, nil, &mu, nil, []string{derive.GetLagrangeID(0, size)}, nil)

	err = BruteForceChecker(trace, system.Relations, system.N)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(trace, system.Relations, system.N)
	if err != nil {
		t.Fatal(err)
	}

}
