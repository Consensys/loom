package proveractions

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
)

// RegisterColumn registers P, whose id is ID, in T. Returns an error if the trace already exists
func RegisterColumn(trace trace.Trace, ID string, P univariate.Polynomial, mu *sync.Mutex) error {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := trace[ID]; ok {
		return fmt.Errorf("column %s already registered in the trace", ID)
	}
	trace[ID] = P
	return nil
}

// ComputeGrandSum builds the "grand sum" polynomial between E0:=E[0] and E1:=E[1], that
// is a polnyomial GS such that GS[i]=Σ_{j⩽i}E0[j]/E1[j]
func ComputeGrandSum(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, GP []string, _ Ctx) error {

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
	return RegisterColumn(trace, grandSumID, grandSum, mu)

}

// ComputeGrandProduct build the "grand product" polynomial between E0:=E[0] and E1:=E[1], that is it creates
// a polynomial (=column) R such that R[0]=1, R[i+1]=R[i]E0[i]/E1[i], where E0[i] means the i-th entry of E0 evaluated on prot.trace.Trace
// (same for E1). The relation R(wX)E1-RE0 mut vanish on X^N-1 iff E1[i] and E0[i] are permutated versions of each other
func ComputeGrandProduct(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, GP []string, _ Ctx) error {

	if len(E) != 2 {
		return fmt.Errorf("E must have size 2, got %d", len(E))
	}

	// build the polynomials R, R(wX)
	R, err := univariate.BuildGrandProduct(trace, E[0], E[1], proof.N, mu)
	if err != nil {
		return err
	}
	RID := GP[0]

	// register the R, R(wX) in the trace
	return RegisterColumn(trace, RID, R, mu)

}

// ComputeLagrangeColumn prover action to build a computable column, that is a column encoded by a formula.
// If it exists, we don't throw an error, as the column might be generated from different IOPs.
func ComputeLagrangeColumn(trace trace.Trace, _ *Proof, mu *sync.Mutex, _ []sym.Expr, output []string, _ Ctx) error {
	id := output[0]
	cc, err := GetComputationableColumn(output[0])
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
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
func ComputeColumn(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, output []string, _ Ctx) error {

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
	return RegisterColumn(trace, output[0], sum, mu)

}

// ComputeMultiplicity prover action that counts the multiplicity of E[0] in E[1] and record the
// corresponding columnin in the trace with id GP[0]
// Example: E[0]="S", E[1]="T", GP[0]="M" -> computes M such that
// M[i] = #{j | j S[j]=T[i]}
func ComputeMultiplicity(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, M []string, _ Ctx) error {
	if len(E) != 2 {
		return fmt.Errorf("len(E)=%d, expected 2", len(E))
	}
	if len(M) != 1 {
		return fmt.Errorf("len(GP)=%d, expected 1", len(M))
	}
	S := E[0]
	T := E[1]
	_M, err := univariate.BuildMultiplicityPolynomial(trace, S, T, proof.N, mu)
	if err != nil {
		return err
	}
	return RegisterColumn(trace, M[0], _M, mu)

}

// ComputeFilteredAccPolynomial filters E[0] by E[1], using the challenge E[2]
// example: put E:=E[0], F:=E[1], α:=E[2], R:=output[0] (F stands for Filter)
// E = [1, 7, 9, 10, 6, 12]
// F = [0, 1, 0, 0, 1, 1]
// E filtered by F is E_F = [0, 7, 0, 0, 6, 12]
// R is built such R[N-1] is the evaluation of E_F at alpha, when we discard the non selected elements in E_F.
// After discarding non selected elmts in E_F we get [7, 6, 12], so R[N-1]=7α²+6α+12. R is subject to the following relations:
// * R[0] = F[0]*E[0]
// *  R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
func ComputeFilteredAccPolynomial(trace trace.Trace, proof *Proof, mu *sync.Mutex, E []sym.Expr, output []string, _ Ctx) error {

	if len(E) != 3 {
		return fmt.Errorf("len(E)=%d, expected 3", len(E))
	}
	if len(output) != 1 {
		return fmt.Errorf("len(output)=%d, expected 1", len(output))
	}

	R, err := univariate.BuildFilteredAccPolynomial(trace, E[0], E[1], E[2], proof.N, mu)
	if err != nil {
		return err
	}

	return RegisterColumn(trace, output[0], R, mu)
}
