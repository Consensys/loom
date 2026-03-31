package poly

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
)

// BuildPointwiseEvaluation evaluates E point-wise over Pi and returns the N results as a
// freshly allocated slice. N is the size of the polynomials in Pi (all must
// have the same size, except constants which have size 1).
func BuildPointwiseEvaluation(Pi map[string]Polynomial, E expr.Expr, N int, mu *sync.Mutex) ([]koalabear.Element, error) {
	dst := make([]koalabear.Element, N)
	return dst, evalPointWiseInto(Pi, E, N, mu, dst)
}

type MultiplicityConfig struct {
	Selector expr.Expr
}

type MultiplicityOption func(mc *MultiplicityConfig) error

func WithSelector(selector expr.Expr) MultiplicityOption {
	return func(mc *MultiplicityConfig) error {
		mc.Selector = selector
		return nil
	}
}

// BuildMultiplicityPolynomial returns P such that:
// P[i] = #{ j | S[j] = T[i] and Sel[j]!=0 if Sel!=nil }
func BuildMultiplicityPolynomial(Pi map[string]Polynomial, S, T, Sel expr.Expr, mu *sync.Mutex) (Polynomial, error) {

	// evaluate S and T on P
	sLeaves := S.LeavesFull(expr.NewConfig(expr.WithoutChallenges()))
	tLeaves := T.LeavesFull(expr.NewConfig(expr.WithoutChallenges()))
	_s := Pi[sLeaves[0].Name]
	_t := Pi[tLeaves[0].Name]
	ns := len(_s)
	nt := len(_t)
	_S := getBuf(ns)
	_T := getBuf(nt)
	if err := evalPointWiseInto(Pi, S, ns, mu, _S); err != nil {
		putBuf(_S)
		return Polynomial{}, err
	}
	if err := evalPointWiseInto(Pi, T, nt, mu, _T); err != nil {
		putBuf(_S)
		return Polynomial{}, err
	}

	if Sel != nil {
		selLeaves := Sel.LeavesFull(expr.NewConfig(expr.WithoutChallenges()))
		_sl := Pi[selLeaves[0].Name]
		nsl := len(_sl)
		_SEL := getBuf(nsl)
		if err := evalPointWiseInto(Pi, S, ns, mu, _SEL); err != nil {
			putBuf(_SEL)
			return Polynomial{}, err
		}
		res := countMultiplicityWithSelector(_S, _T, _SEL)
		putBuf(_S)
		putBuf(_T)
		putBuf(_SEL)
		return res, nil
	} else {
		res := countMultiplicity(_S, _T)
		putBuf(_S)
		putBuf(_T)
		return res, nil
	}
}

// BuildGrandSum returns R such that
// R[i] = Σ_{j⩽i}M[j]/E[j]
// The notation E[i] means the i-th entry of E evaluated on P (same for M).
func BuildLogup(P map[string]Polynomial, E, M expr.Expr, N int, mu *sync.Mutex) (Polynomial, error) {

	// D stores the denominators 1/E(P); pooled because it is only needed until accumulateSums copies it.
	D := getBuf(N)
	if err := evalPointWiseInto(P, E, N, mu, D); err != nil {
		putBuf(D)
		return Polynomial{}, err
	}
	invertPointwiseInPlace(D)

	// Mp is pooled: it is multiplied into D and then discarded.
	Mp := getBuf(N)
	if err := evalPointWiseInto(P, M, N, mu, Mp); err != nil {
		putBuf(D)
		putBuf(Mp)
		return Polynomial{}, err
	}
	for i := 0; i < N; i++ {
		di := D[i]
		mi := Mp[i]
		D[i].Mul(&di, &mi)
	}
	putBuf(Mp)

	result, err := accumulateSums(D, N)
	putBuf(D)
	return result, err
}

// BuildGrandProduct returns R such that R[0]=1, R[i+1] = R[i] * E1(P[i]) / E2(P[i])
// N = size of the polynomials in P
// Polynomials in P must have the same basis, same layout
func BuildGrandProduct(P map[string]Polynomial, E1, E2 expr.Expr, N int, mu *sync.Mutex) (Polynomial, error) {

	// Q0 and Q1 are intermediate buffers: pooled because they are fully consumed by divPointwise.
	Q0 := getBuf(N)
	if err := evalPointWiseInto(P, E1, N, mu, Q0); err != nil {
		putBuf(Q0)
		return Polynomial{}, fmt.Errorf("failed to evaluate numerator expression: %w", err)
	}

	Q1 := getBuf(N)
	if err := evalPointWiseInto(P, E2, N, mu, Q1); err != nil {
		putBuf(Q0)
		putBuf(Q1)
		return Polynomial{}, fmt.Errorf("failed to evaluate denominator expression: %w", err)
	}

	ratio, err := divPointwise(Q0, Q1, N)
	putBuf(Q0)
	putBuf(Q1)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to compute pointwise ratio: %w", err)
	}

	return accumulateProducts(ratio, N)
}

// BuildFilteredAccPolynomial builds a polynomial R such that:
// * R[0] = F[0]*E[0]
// *  R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
// F is a an expression whose evaluation is a binary column (contains only 0 and 1s), it acts as a filter.
// It is up to the caller to ensure that F evaluations contain only 0 and 1.
// alpha is a challenge in the trace. R represents the evaluation of E filtered by F, with coeff ordering
// on par with the filter.
//
// example:
// E = [1, 7, 9, 10, 6, 12]
// F = [0, 1, 0, 0, 1, 1]
// E filter by F is E_F = [0, 7, 0, 0, 6, 12]
// R is built such R[N-1] is the evaluation of E_F at alpha, when we discard the non selected elements in E_F.
// After discarding non selected elmts in E_F we get [7, 6, 12], so R[N-1]=7α²+6α+12. This is what the formula
//
//	R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1]
//
// encodes.
// func BuildFilteredAccPolynomial(P map[string]Polynomial, E, F, alpha expr.Expr, N int, mu *sync.Mutex) (Polynomial, error) {

// 	_E := getBuf(N)
// 	_F := getBuf(N)
// 	if err := evalPointWiseInto(P, E, N, mu, _E); err != nil {
// 		putBuf(_E)
// 		putBuf(_F)
// 		return Polynomial{}, err
// 	}
// 	if err := evalPointWiseInto(P, F, N, mu, _F); err != nil {
// 		putBuf(_E)
// 		putBuf(_F)
// 		return Polynomial{}, err
// 	}
// 	res := make(Polynomial, N)
// 	if _, ok := alpha.(*expr.Leaf); !ok {
// 		return Polynomial{}, fmt.Errorf("alpha must be a leaf")
// 	}
// 	alphaExpr := alpha.(*expr.Leaf)
// 	if alphaExpr.Type != expr.ChallengeColumn {
// 		return Polynomial{}, fmt.Errorf("alpha must be a challenge")
// 	}
// 	_alpha := P[alpha.String()]
// 	a := _alpha[0]

// 	// R[0] = F[0]*E[0]
// 	res[0].Mul(&_E[0], &_F[0])

// 	// R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1]
// 	var path1, path2, one koalabear.Element
// 	one = koalabear.One()
// 	for i := 1; i < N; i++ {
// 		path1.Sub(&one, &_F[i]).Mul(&path1, &res[i-1])                   // (1-F[i])R[i-1]
// 		path2.Mul(&a, &res[i-1]).Add(&path2, &_E[i]).Mul(&path2, &_F[i]) // F[i]*(α*R[i-1]+E[i])
// 		res[i].Add(&path1, &path2)
// 	}

// 	putBuf(_E)
// 	putBuf(_F)

// 	return res, nil
// }
