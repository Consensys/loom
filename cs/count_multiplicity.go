package cs

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
)

// ComputeMultiplicity prover action that counts the multiplicity of E[0] in E[1] and record the
// corresponding columnin in the trace with id GP[0]
// Example: E[0]="S", E[1]="T", GP[0]="M" -> computes M such that
// M[i] = #{j | j S[j]=T[i]}
func ComputeMultiplicity(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, GP []string) error {
	if len(E) != 2 {
		return fmt.Errorf("len(E)=%d, expected 2", len(E))
	}
	if len(GP) != 1 {
		return fmt.Errorf("len(GP)=%d, expected 1", len(GP))
	}
	S := E[0]
	T := E[1]
	M, err := univariate.BuildMultiplicityPolynomial(trace, S, T, proof.N, mu)
	if err != nil {
		return err
	}
	err = RegisterColumn(trace, GP[0], M, mu)
	if err != nil {
		return err
	}
	return nil
}
