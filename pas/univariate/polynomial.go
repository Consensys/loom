// /!\ In this package, every inputs polynomials must be in lagrange basis (the inputs come from columns of a trace).

package univariate

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// Polynomial is a wrapper around EPolynomial that includes additional metadata such as shift.
type Polynomial = []koalabear.Element

// evalBufPool pools []koalabear.Element slices used as temporary buffers inside
// BuildGrandProduct and BuildGrandSum. koalabear.Element contains no pointers,
// so pooled slices do not prevent GC of other objects.
var evalBufPool sync.Pool

func getBuf(n int) []koalabear.Element {
	if v := evalBufPool.Get(); v != nil {
		if b := v.([]koalabear.Element); cap(b) >= n {
			return b[:n]
		}
	}
	return make([]koalabear.Element, n)
}

func putBuf(b []koalabear.Element) {
	evalBufPool.Put(b[:cap(b)])
}

// evalPointWiseInto is the core implementation: it evaluates E point-wise over
// Pi and writes the N results into dst (which must have length N).
func evalPointWiseInto(Pi map[string]Polynomial, E sym.Expr, N int, mu *sync.Mutex, dst []koalabear.Element) error {
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

	if mu != nil {
		mu.Lock()
	}
	_Pi := make([]Polynomial, len(leaves))
	for _, l := range leaves {
		_Pi[l.Idx] = Pi[l.Name]
	}
	if mu != nil {
		mu.Unlock()
	}

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
		dst[i] = E.EvaluateWithIdx(vals)
	}
	return nil
}

// EvalPointWise evaluates E point-wise over Pi and returns the N results as a
// freshly allocated slice. N is the size of the polynomials in Pi (all must
// have the same size, except constants which have size 1).
func EvalPointWise(Pi map[string]Polynomial, E sym.Expr, N int, mu *sync.Mutex) ([]koalabear.Element, error) {
	dst := make([]koalabear.Element, N)
	return dst, evalPointWiseInto(Pi, E, N, mu, dst)
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

func countMultiplicity(S, T Polynomial, N int) Polynomial {
	res := make(Polynomial, N)
	var one koalabear.Element
	one.SetOne()
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			if T[i].Equal(&S[j]) {
				res[i].Add(&res[i], &one)
			}
		}
	}
	return res
}

// BuildMultiplicityPolynomial returns P such that:
// P[i] is the number of times T[i] appears in S.
// S, T are assumed to be in Lagrange basis
// S and T must be of the same size
func BuildMultiplicityPolynomial(Pi map[string]Polynomial, S, T sym.Expr, N int, mu *sync.Mutex) (Polynomial, error) {

	// evaluate S and T on P
	_S := getBuf(N)
	_T := getBuf(N)
	if err := evalPointWiseInto(Pi, S, N, mu, _S); err != nil {
		putBuf(_S)
		return Polynomial{}, err
	}
	if err := evalPointWiseInto(Pi, T, N, mu, _T); err != nil {
		putBuf(_S)
		return Polynomial{}, err
	}

	res := countMultiplicity(_S, _T, N)
	putBuf(_S)
	putBuf(_T)
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
func BuildGrandSum(P map[string]Polynomial, E, M sym.Expr, N int, mu *sync.Mutex) (Polynomial, error) {

	// D stores the denominators 1/E(P); pooled because it is only needed until accumulateSums copies it.
	D := getBuf(N)
	if err := evalPointWiseInto(P, E, N, mu, D); err != nil {
		putBuf(D)
		return Polynomial{}, err
	}
	InvertPointWiseInPlace(D)

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
func BuildGrandProduct(P map[string]Polynomial, E1, E2 sym.Expr, N int, mu *sync.Mutex) (Polynomial, error) {

	// Q0 and Q1 are intermediate buffers: pooled because they are fully consumed by DivPointWise.
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

	ratio, err := DivPointWise(Q0, Q1, N)
	putBuf(Q0)
	putBuf(Q1)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to compute pointwise ratio: %w", err)
	}

	return accumulateProducts(ratio, N)
}
