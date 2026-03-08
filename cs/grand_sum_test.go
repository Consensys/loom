package cs

import (
	"sync"
	"testing"

	"github.com/consensys/giop/pas/sym"
	proveractions "github.com/consensys/giop/prover_actions"
)

func TestGrandSumConstraint(t *testing.T) {

	size := 16

	trace := BuildRandomTrace(t, size)
	system := NewSystem(size)
	constraints := BuildGrandSumConstraints(sym.NewCommittedColumn("M"), sym.NewCommittedColumn("E"), "GrandSum", size)
	system.RegisterConstraints(constraints)
	proof := proveractions.NewProof(size)
	E := sym.NewCommittedColumn("E")
	M := sym.NewCommittedColumn("M")
	var mu sync.Mutex
	err := proveractions.ComputeGrandSum(trace, &proof, &mu, []sym.Expr{M, E}, []string{"GrandSum"})
	if err != nil {
		t.Fatal(err)
	}
	proveractions.ComputeLagrangeColumn(trace, nil, &mu, nil, []string{proveractions.GetLagrangeID(0, size)})

	err = BruteForceChecker(trace, system.Constraints, system.N)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(trace, system.Constraints, system.N)
	if err != nil {
		t.Fatal(err)
	}

}
