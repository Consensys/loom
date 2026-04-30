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
func BuildPointwiseEvaluation(Pi map[string]Polynomial, E expr.Expr, mu *sync.Mutex) ([]koalabear.Element, error) {
	leaves := E.LeavesFull(expr.NewConfig(expr.WithoutChallenges()))
	_c := Pi[leaves[0].Name]
	N := len(_c)
	dst := make([]koalabear.Element, N)
	return dst, evalPointWiseInto(Pi, E, N, mu, dst)
}

// BuildWeightedMultiplicityPolynomial same as BuildMultiplicityPolynomials, but selectors and
// target and source are split
func BuildWeightedMultiplicityPolynomial(Pi map[string]Polynomial, selS, S, T []expr.Expr, mu *sync.Mutex) ([]Polynomial, error) {

	// 1 - ensure len(selS)=len(S)
	if len(selS) != len(S) {
		return nil, fmt.Errorf("BuildUnionWeightedMultiplicityPolynomial: len(selS)=%d != len(S)=%d", len(selS), len(S))
	}

	// 2 - build joinedSelS, joinedS, joinedT -> concatenations of selS, S, T

	// Evaluate all S and selS expressions into pooled buffers (same size per index).
	sPolys := make([]Polynomial, len(S))
	selPolys := make([]Polynomial, len(selS))
	for i, s := range S {
		ns, err := inferN(Pi, s)
		if err != nil {
			for j := 0; j < i; j++ {
				putBuf(sPolys[j])
				putBuf(selPolys[j])
			}
			return nil, fmt.Errorf("BuildUnionWeightedMultiplicityPolynomial: S[%d]: %w", i, err)
		}
		sBuf := getBuf(ns)
		if err := evalPointWiseInto(Pi, s, ns, mu, sBuf); err != nil {
			putBuf(sBuf)
			for j := 0; j < i; j++ {
				putBuf(sPolys[j])
				putBuf(selPolys[j])
			}
			return nil, err
		}
		selBuf := getBuf(ns)
		if err := evalPointWiseInto(Pi, selS[i], ns, mu, selBuf); err != nil {
			putBuf(sBuf)
			putBuf(selBuf)
			for j := 0; j < i; j++ {
				putBuf(sPolys[j])
				putBuf(selPolys[j])
			}
			return nil, err
		}
		sPolys[i] = sBuf
		selPolys[i] = selBuf
	}

	// Evaluate all T expressions into pooled buffers, recording sizes.
	tPolys := make([]Polynomial, len(T))
	tSizes := make([]int, len(T))
	for i, t := range T {
		nt, err := inferN(Pi, t)
		if err != nil {
			for j := range sPolys {
				putBuf(sPolys[j])
				putBuf(selPolys[j])
			}
			for j := 0; j < i; j++ {
				putBuf(tPolys[j])
			}
			return nil, fmt.Errorf("BuildUnionWeightedMultiplicityPolynomial: T[%d]: %w", i, err)
		}
		buf := getBuf(nt)
		if err := evalPointWiseInto(Pi, t, nt, mu, buf); err != nil {
			putBuf(buf)
			for j := range sPolys {
				putBuf(sPolys[j])
				putBuf(selPolys[j])
			}
			for j := 0; j < i; j++ {
				putBuf(tPolys[j])
			}
			return nil, err
		}
		tPolys[i] = buf
		tSizes[i] = nt
	}

	totalS := 0
	for _, sp := range sPolys {
		totalS += len(sp)
	}
	joinedS := getBuf(totalS)
	joinedSelS := getBuf(totalS)
	off := 0
	for i, sp := range sPolys {
		copy(joinedS[off:], sp)
		copy(joinedSelS[off:], selPolys[i])
		off += len(sp)
		putBuf(sp)
		putBuf(selPolys[i])
	}

	totalT := 0
	for _, tp := range tPolys {
		totalT += len(tp)
	}
	joinedT := getBuf(totalT)
	off = 0
	for _, tp := range tPolys {
		copy(joinedT[off:], tp)
		off += len(tp)
		putBuf(tp)
	}

	// 3 - call countWeightedMultiplicityWithSelector on joinedS, joinedT, joinedSelS
	result := countWeightedMultiplicityWithSelector(joinedS, joinedT, joinedSelS)
	putBuf(joinedS)
	putBuf(joinedT)
	putBuf(joinedSelS)

	// 4 - split result into len(T) chunks, chunk i of size tSizes[i]
	chunks := make([]Polynomial, len(T))
	off = 0
	for i, sz := range tSizes {
		chunks[i] = result[off : off+sz]
		off += sz
	}

	return chunks, nil
}

// BuildMultiplicityPolynomials returns one multiplicity polynomial per
// target column such that chunks[k][i] = total number of times T[k][i] appears
// across all source columns S[0], ..., S[len(S)-1].
func BuildMultiplicityPolynomials(Pi map[string]Polynomial, S, T []expr.Expr, mu *sync.Mutex) ([]Polynomial, error) {

	// Evaluate all S expressions into pooled buffers.
	sPolys := make([]Polynomial, len(S))
	for i, s := range S {
		ns, err := inferN(Pi, s)
		if err != nil {
			for j := 0; j < i; j++ {
				putBuf(sPolys[j])
			}
			return nil, fmt.Errorf("BuildMultiplicityPolynomials: S[%d]: %w", i, err)
		}
		buf := getBuf(ns)
		if err := evalPointWiseInto(Pi, s, ns, mu, buf); err != nil {
			putBuf(buf)
			for j := 0; j < i; j++ {
				putBuf(sPolys[j])
			}
			return nil, err
		}
		sPolys[i] = buf
	}

	// Evaluate all T expressions into pooled buffers, recording sizes.
	tPolys := make([]Polynomial, len(T))
	tSizes := make([]int, len(T))
	for i, t := range T {
		nt, err := inferN(Pi, t)
		if err != nil {
			for j := range sPolys {
				putBuf(sPolys[j])
			}
			for j := 0; j < i; j++ {
				putBuf(tPolys[j])
			}
			return nil, fmt.Errorf("BuildMultiplicityPolynomials: T[%d]: %w", i, err)
		}
		buf := getBuf(nt)
		if err := evalPointWiseInto(Pi, t, nt, mu, buf); err != nil {
			putBuf(buf)
			for j := range sPolys {
				putBuf(sPolys[j])
			}
			for j := 0; j < i; j++ {
				putBuf(tPolys[j])
			}
			return nil, err
		}
		tPolys[i] = buf
		tSizes[i] = nt
	}

	// Concatenate all S evaluations into a single polynomial.
	totalS := 0
	for _, sp := range sPolys {
		totalS += len(sp)
	}
	_S := getBuf(totalS)
	off := 0
	for _, sp := range sPolys {
		copy(_S[off:], sp)
		off += len(sp)
		putBuf(sp)
	}

	// Concatenate all T evaluations into a single polynomial.
	totalT := 0
	for _, tp := range tPolys {
		totalT += len(tp)
	}
	_T := getBuf(totalT)
	off = 0
	for _, tp := range tPolys {
		copy(_T[off:], tp)
		off += len(tp)
		putBuf(tp)
	}

	// Count how many times each concatenated T value appears across all sources.
	result := countMultiplicity(_S, _T)
	putBuf(_S)
	putBuf(_T)

	// Split result into per-target chunks.
	chunks := make([]Polynomial, len(T))
	off = 0
	for i, sz := range tSizes {
		chunks[i] = result[off : off+sz]
		off += sz
	}

	return chunks, nil
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
