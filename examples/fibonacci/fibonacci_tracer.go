package fibonacci

import (
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// GetFibonacciTrace generates a trace containing 3 columns P1, P2, P3
// subject to the following conditions:
// P3 - P1 - P2 = 0
// P1[0]=0
// P2[0]=1
// P1[i] = P3[i-1] for i>0
func GetFibonacciTrace(n int, A, B, C string) trace.Trace {
	res := make([][]koalabear.Element, 3)
	for i := 0; i < 3; i++ {
		res[i] = make([]koalabear.Element, n)
	}
	res[1][0].SetOne()
	res[2][0].SetOne()
	for i := 1; i < n; i++ {
		res[0][i].Set(&res[1][i-1])
		res[1][i].Set(&res[2][i-1])
		res[2][i].Add(&res[0][i], &res[1][i])
	}
	t := make(trace.Trace)
	t[A] = res[0]
	t[B] = res[1]
	t[C] = res[2]

	return t
}
