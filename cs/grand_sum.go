package cs

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// BuildGrandSumConstraints :
// 1. (1-Lagrange_0) * ( (IDGrandSum - IDGrandSum(w^1 X))*E - M)=0 -> ensures that IDGrandSum[i] = IDGrandSum[i-1]+M[i]/E[i]
// 2. Lagrange_0*( IDGrandSum*E-M)=0 -> ensures IDGrandSum[0] = M[0]/E[0]
func BuildGrandSumConstraints(M, E sym.Expr, grandSum string, N int) []Constraint {

	// 1. (1-Lagrange_0) * ( (IDGrandSum - IDGrandSum(w^1 X))*E - M)=0
	lagrange := sym.NewComputableColumn(GetLagrangeID(0, N))
	p1 := sym.NewConst(koalabear.One()).Sub(lagrange)
	diffGrandSum := sym.NewCommittedColumn(grandSum).Sub(sym.NewShiftedColumn(grandSum, -1))
	p2 := diffGrandSum.Mul(E).Sub(M)
	recurrenceRelation := p1.Mul(p2)

	// 2. Lagrange_0*( IDGrandSum*E-M)=0
	grandSumTimesE := sym.NewCommittedColumn(grandSum).Mul(E)
	localConstraint := BuildLocalConstraint(grandSumTimesE, M, 0, N)

	return []Constraint{recurrenceRelation, localConstraint}
	// EnforceLocalConstraintAndRegisterLagrangeColumn(system, grandSumTimesE, M, 0)
}

// ComputeGrandSum builds the "grand sum" polynomial between E0:=E[0] and E1:=E[1], that
// is a polnyomial GS such that GS[i]=Σ_{j⩽i}E0[j]/E1[j]
func ComputeGrandSum(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, GP []string) error {

	if len(E) != 2 {
		return fmt.Errorf("len(E)=%d, expected 2", len(E))
	}
	if len(GP) != 1 {
		return fmt.Errorf("len(GP)=%d, expected 1", len(GP))
	}

	// build the polynomials R
	grandSum, err := univariate.BuildGrandSum(trace, E[1], E[0], proof.N, mu)
	if err != nil {
		return err
	}
	grandSumID := GP[0]

	// register the R in the trace
	err = RegisterColumn(trace, grandSumID, grandSum, mu)
	if err != nil {
		return err
	}

	return nil
}
