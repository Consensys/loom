package cs

import (
	"fmt"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// EnforceGrandProductConstraint IDGrandProductShifted*E2-IDGrandProduct*E1=0
func EnforceGrandProductConstraint(system *System, E1, E2 sym.Expr, IDGrandProduct string, N int) {

	// build the symbolic expression of the constraint
	IDGrandProductShifted := IDGrandProduct + GetShiftSuffix(1)
	A := sym.NewCommittedColumn(IDGrandProductShifted).Mul(E2)
	B := sym.NewCommittedColumn(IDGrandProduct).Mul(E1)
	GPConstraint := A.Sub(B)
	system.RegisterConstraint(GPConstraint)
}

// ComputeGrandProduct build the "grand product" polynomial between E0:=E[0] and E1:=E[1], that is it creates
// a polynomial (=column) R such that R[0]=1, R[i+1]=R[i]E0[i]/E1[i], where E0[i] means the i-th entry of E0 evaluated on prot.trace.Trace
// (same for E1). The relation R(wX)E1-RE0 mut vanish on X^N-1 iff E1[i] and E0[i] are permutated versions of each other
func ComputeGrandProduct(trace trace.Trace, proof *Proof, E []sym.Expr, GP []string) error {

	if len(E) != 2 {
		return fmt.Errorf("E must have size 2, got %d", len(E))
	}

	// build the polynomials R, R(wX)
	R, err := univariate.BuildGrandProduct(trace, E[0], E[1], proof.N)
	if err != nil {
		return err
	}
	RID := GP[0]
	RsID := GP[0] + GetShiftSuffix(1)
	RSCoeffs := make([]koalabear.Element, proof.N)
	for i := 0; i < proof.N; i++ {
		RSCoeffs[i] = R.GetCoefficient((i + 1) % proof.N)
	}
	RS, err := univariate.NewPolynomial(RSCoeffs, univariate.WithBasis(univariate.Lagrange), univariate.WithLayout(univariate.Normal))
	if err != nil {
		return err
	}

	// register the R, R(wX) in the trace
	err = RegisterColumn(trace, RID, &R)
	if err != nil {
		return err
	}
	err = RegisterColumn(trace, RsID, &RS)
	if err != nil {
		return err
	}

	return nil
}
