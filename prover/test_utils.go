package prover

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/trace"
)

func MergeTrace(t1 trace.Trace, t2 ...trace.Trace) trace.Trace {
	res := t1
	for _, t := range t2 {
		for k, v := range t {
			res[k] = v
		}
	}
	return res
}

// TraceFibonacci traces a Fibonacci sequence, encoded with 3 columns
// A, B, C subject to the following constraints:
// C = A + B
// A_shifted = B, except at the last entry
// B_shifted = C, except at the last entry
// with A[0]=a, B[0]=b
func TraceFibonacci(n int, a, b koalabear.Element) trace.Trace {

	n = int(ecc.NextPowerOfTwo(uint64(n)))

	res := make(trace.Trace)
	A := make([]koalabear.Element, n)
	B := make([]koalabear.Element, n)
	C := make([]koalabear.Element, n)

	A[0].Set(&a)
	B[0].Set(&b)
	for i := range n {
		C[i].Add(&A[i], &B[i])
		if i < n-1 {
			A[i+1].Set(&B[i])
			B[i+1].Set(&C[i])
		}
	}
	res["A"] = A
	res["B"] = B
	res["C"] = C

	return res
}

func TraceRange(n int) trace.Trace {
	n = int(ecc.NextPowerOfTwo(uint64(n)))
	res := make(trace.Trace)
	col := make([]koalabear.Element, 2*n) // to handle modules of different size
	for i := range 2 * n {
		col[i].SetUint64(uint64(i))
	}
	res["Lookup"] = col
	return res
}
