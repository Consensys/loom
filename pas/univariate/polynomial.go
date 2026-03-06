// /!\ In this package, every inputs polynomials must be in lagrange basis (the inputs come from columns of a trace).

package univariate

import (
	"fmt"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// Polynomial is a wrapper around EPolynomial that includes additional metadata such as shift.
type Polynomial = []koalabear.Element

// EvalPointWise eval point wise E on Pi, by picking the coefficient direclty (no conversion, no copies).
// internal function only.
// N is the size of the polynomials in Pi, assumed to have all the same size, except the constant (size 1)
// nbCommittedColumns is the number of variables in E
func EvalPointWise(Pi map[string]Polynomial, E sym.Expr, N int) ([]koalabear.Element, error) {

	// query the leaves (without constants), deduplicate by (Name, Shift), and index them.
	// CommittedColumn "col" and ShiftedColumn "col" shift=1 are distinct variables and
	// need different Idx values; both share the same base polynomial (keyed by l.Name).
	type varKey struct {
		name  string
		shift int
	}
	varToIdx := make(map[varKey]int)
	allLeaves := E.LeavesFull(sym.NewConfig())
	leaves := make([]*sym.Leaf, 0, len(allLeaves))
	for _, l := range allLeaves {
		key := varKey{l.Name, l.Shift}
		if idx, ok := varToIdx[key]; ok {
			l.Idx = idx
		} else {
			l.Idx = len(leaves)
			varToIdx[key] = l.Idx
			leaves = append(leaves, l)
		}
	}

	// fetch the subtrace indexed by l.Idx; for ShiftedColumn, l.Name is the base column.
	_Pi := make([]Polynomial, len(leaves))
	for _, l := range leaves {
		_Pi[l.Idx] = Pi[l.Name]
	}

	resultCoeffs := make([]koalabear.Element, N)
	vals := make([]koalabear.Element, len(leaves))
	for i := 0; i < N; i++ {
		for _, l := range leaves {
			if len(_Pi[l.Idx]) == 1 {
				vals[l.Idx] = _Pi[l.Idx][0]
				continue
			}
			if l.Type == sym.ShiftedColumn {
				vals[l.Idx] = _Pi[l.Idx][(i+N+l.Shift)%N]
				continue
			}
			vals[l.Idx] = _Pi[l.Idx][i]
		}
		resultCoeffs[i] = E.EvaluateWithIdx(vals)
	}
	return resultCoeffs, nil
}

// DivPointWise computes the resulting polynomial from dividing pointwise.
// N = size of polynomials. All polynomials must be of the same size, same basis, same layout
func DivPointWise(P1, P2 Polynomial, N int) (Polynomial, error) {

	for i := 0; i < len(P2); i++ {
		if P2[i].IsZero() {
			return Polynomial{}, fmt.Errorf("division by zero")
		}
	}
	res := koalabear.BatchInvert(P2)

	// Build result polynomial pointwise: R[i] = P_1[i] / P_2[i]
	for i := 0; i < N; i++ {
		res[i].Mul(&P1[i], &res[i])
	}
	return res, nil
}

// BuildMultiplicityPolynomial returns P such that:
// P[i] is the number of times T[i] appears in S.
// S, T are assumed to be in Lagrange basis
// S and T must be of the same size
func BuildMultiplicityPolynomial(S, T Polynomial) (Polynomial, error) {

	if len(S) != len(T) {
		return Polynomial{}, fmt.Errorf("S and T don't have equal size: len(S)%d, len(T)=%d", len(S), len(T))
	}

	n := len(S)
	res := make(Polynomial, n)

	one := koalabear.One()

	// we can probably do better :/
	for i := 0; i < n; i++ {
		ct := T[i]
		for j := 0; j < n; j++ {
			cd := S[j]
			if cd.Equal(&ct) {
				res[i].Add(&res[i], &one)
			}
		}
	}

	return res, nil

}

// InvertPointWiseInPlace inverts in place P
func InvertPointWiseInPlace(P Polynomial) {
	for i := 0; i < len(P); i++ {
		P[i].Inverse(&P[i])
	}
}

// accumulateSums returns R such that R[0] = P[0], R[i] = R[i-1] + P[i]
// N = size of P
func accumulateSums(P Polynomial, N int) (Polynomial, error) {

	// build the result R in lagrange basis of size targetSize such that:
	// R[0] = P[0], R[i] = R[i-1] + P[i] for i>0
	result := make(Polynomial, N)
	c := P[0]
	result[0].Set(&c)
	for i := 1; i < N; i++ {
		c = P[i]
		result[i].Add(&result[i-1], &c)
	}

	return result, nil
}

// BuildGrandSum returns R such that
// R[i] = \Sigma_{j<=i}M[j]/E[j]
// The notation E[i] means the i-th entry of E evaluated on P (same for M).
func BuildGrandSum(P map[string]Polynomial, E, M sym.Expr, N int) (Polynomial, error) {

	// D stores the denominators 1/E(P)
	D, err := EvalPointWise(P, E, N)
	if err != nil {
		return Polynomial{}, err
	}
	InvertPointWiseInPlace(D)

	// multiply by M(P) to get M(P)/E(P)
	Mp, err := EvalPointWise(P, M, N)
	if err != nil {
		return Polynomial{}, err
	}
	for i := 0; i < N; i++ {
		di := D[i]
		mi := Mp[i]
		D[i].Mul(&di, &mi)
	}

	return accumulateSums(D, N)
}

// accumulateProducts returns R such that R[i+1] = R[i]*P[i], R[0]=1
// N = size of P
func accumulateProducts(P Polynomial, N int) (Polynomial, error) {

	// build the result R in lagrange basis of size targetSize such that:
	// R[0] = 1
	// R[i] = R[i-1]*P[i-1] for i > 0
	result := make([]koalabear.Element, N)
	result[0].SetOne()
	for i := 1; i < N; i++ {
		pi := P[i-1]
		result[i].Mul(&result[i-1], &pi)
	}
	return result, nil
}

// BuildGrandProduct returns R such that R[0]=1, R[i+1] = R[i] * E1(P[i]) / E2(P[i])
// N = size of the polynomials in P
// Polynomials in P must have the same basis, same layout
func BuildGrandProduct(P map[string]Polynomial, E1, E2 sym.Expr, N int) (Polynomial, error) {

	Q0, err := EvalPointWise(P, E1, N)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to evaluate numerator expression: %w", err)
	}

	Q1, err := EvalPointWise(P, E2, N)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to evaluate denominator expression: %w", err)
	}

	// Div is not allowed in the AST (TODO should I allow it?)
	ratio, err := DivPointWise(Q0, Q1, N)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to compute pointwise ratio: %w", err)
	}

	return accumulateProducts(ratio, N)
}
