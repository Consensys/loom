package cs

import (
	"fmt"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
)

// ComputeMultiplicity prover action that counts the multiplicity of E[0] in E[1] and record the
// corresponding columnin in the trace with id GP[0]
// Example: E[0]="S", E[1]="T", GP[0]="M" -> computes M such that
// M[i] = #{j | j S[j]=T[i]}
func ComputeMultiplicity(trace trace.Trace, proof *Proof, E []sym.Expr, GP []string) error {
	if len(E) != 2 {
		return fmt.Errorf("len(E)=%d, expected 2", len(E))
	}
	if len(GP) != 1 {
		return fmt.Errorf("len(GP)=%d, expected 1", len(GP))
	}
	S, err := univariate.EvalPointWise(trace, E[0], proof.N)
	if err != nil {
		return err
	}
	T, err := univariate.EvalPointWise(trace, E[1], proof.N)
	if err != nil {
		return err
	}
	M, err := univariate.BuildMultiplicityPolynomial(S, T)
	if err != nil {
		return err
	}
	err = RegisterColumn(trace, GP[0], M)
	if err != nil {
		return err
	}
	return nil
}
