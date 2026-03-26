// /!\ In this package, every inputs polynomials must be in lagrange basis (the inputs come from columns of a trace).

package poly

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
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
func evalPointWiseInto(Pi map[string]Polynomial, E expr.Expr, N int, mu *sync.Mutex, dst []koalabear.Element) error {
	type varKey struct {
		name  string
		shift int
	}
	varToIdx := make(map[string]int)
	allLeaves := E.LeavesFull(expr.NewConfig())
	leaves := make([]*expr.Leaf, 0, len(allLeaves))
	for _, l := range allLeaves {
		if idx, ok := varToIdx[l.Name]; ok {
			l.Idx = idx
		} else {
			l.Idx = len(leaves)
			varToIdx[l.Name] = l.Idx
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

	for i := 0; i < N; i++ {
		dst[i] = E.EvaluateOnIthEntry(_Pi, i)
	}
	return nil
}

// divPointwise computes the resulting polynomial from dividing pointwise.
// N = size of polynomials. All polynomials must be of the same size, same basis, same layout
func divPointwise(P1, P2 Polynomial, N int) (Polynomial, error) {

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
	freq := make(map[[1]uint32]uint64, N)
	for j := 0; j < N; j++ {
		freq[S[j].Bits()]++
	}
	res := make(Polynomial, N)
	for i := 0; i < N; i++ {
		res[i].SetUint64(freq[T[i].Bits()])
	}
	return res
}

// invertPointwiseInPlace inverts in place P
func invertPointwiseInPlace(P Polynomial) {
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
