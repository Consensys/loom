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

func PickIthValue(Pi map[string]Polynomial, E expr.Expr, pos int, mu *sync.Mutex) (koalabear.Element, error) {

	eLeaves := E.LeavesFull(expr.NewConfig(expr.WithoutChallenges()))
	_n := Pi[eLeaves[0].Name]
	n := len(_n)
	_C := getBuf(n)
	if err := evalPointWiseInto(Pi, E, n, mu, _C); err != nil {
		putBuf(_C)
		return _C[pos], err
	}
	putBuf(_C)
	return _C[pos], nil
}

// BuildMultiplicityPolynomial returns P such that:
// P[i] = #{ j | S[j] = T[i] and Sel[j]!=0 if Sel!=nil }
func BuildMultiplicityPolynomial(Pi map[string]Polynomial, S, T expr.Expr, mu *sync.Mutex) (Polynomial, error) {

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

	res := countMultiplicity(_S, _T)
	putBuf(_S)
	putBuf(_T)
	return res, nil
}

// inferN returns the length of the first polynomial in P whose leaf (non-challenge, non-constant)
// has length != 1. Constants and challenges have length 1 and are skipped.
func inferN(P map[string]Polynomial, exprs ...expr.Expr) (int, error) {
	noChallenge := expr.NewConfig(expr.WithoutChallenges())
	for _, e := range exprs {
		if e == nil {
			continue
		}
		for _, leaf := range e.LeavesFull(noChallenge) {
			if p, ok := P[leaf.Name]; ok && len(p) != 1 {
				return len(p), nil
			}
		}
	}
	return 0, fmt.Errorf("inferN: could not determine N — all leaves are constant or missing from trace")
}

// BuildGrandSum returns R such that
// R[i] = Σ_{j⩽i}M[j]/E[j]
// The notation E[i] means the i-th entry of E evaluated on P (same for M).
func BuildLogup(P map[string]Polynomial, E, M expr.Expr, mu *sync.Mutex) (Polynomial, error) {

	// pick first non length(1) entry of one of the leafs of type Col of E or M, let N be that value
	N, err := inferN(P, E, M)
	if err != nil {
		return Polynomial{}, err
	}

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
func BuildGrandProduct(P map[string]Polynomial, E1, E2 expr.Expr, mu *sync.Mutex) (Polynomial, error) {

	// pick first non length(1) entry of one of the leafs of type Col of E1 or E2, let N be that value
	N, err := inferN(P, E1, E2)
	if err != nil {
		return Polynomial{}, fmt.Errorf("BuildGrandProduct: %w", err)
	}

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
