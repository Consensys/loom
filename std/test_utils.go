package std

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/trace"
)

// ID1: subsets {A0,A1} and {B0,B1}
// ID2: subsets {C0,C1} and {D0,D1}
func BuildPermutationMultiSet(t *testing.T, size int) trace.Trace {

	// Build 2 subsets on each side, each with 2 columns.
	// ID1: subsets {A0,A1} and {B0,B1}
	// ID2: subsets {C0,C1} and {D0,D1}
	// (Cx[j], Cy[j]) = (Ax[(j+1)%N], Ay[(j+1)%N]) — cyclic row-shift preserves the tuple multiset.
	makeRandom := func(name string) (univariate.Polynomial, []koalabear.Element) {
		coeffs := make([]koalabear.Element, size)
		for i := range coeffs {
			coeffs[i].SetRandom()
		}
		p, err := univariate.NewInterpolatedPolynomial(coeffs, name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return p, coeffs
	}
	makeShifted := func(name string, src []koalabear.Element) univariate.Polynomial {
		coeffs := make([]koalabear.Element, size)
		for i := range coeffs {
			coeffs[i] = src[(i+1)%size]
		}
		p, err := univariate.NewInterpolatedPolynomial(coeffs, name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return p
	}

	A0, rawA0 := makeRandom("A0")
	A1, rawA1 := makeRandom("A1")
	B0, rawB0 := makeRandom("B0")
	B1, rawB1 := makeRandom("B1")
	C0 := makeShifted("C0", rawA0)
	C1 := makeShifted("C1", rawA1)
	D0 := makeShifted("D0", rawB0)
	D1 := makeShifted("D1", rawB1)

	return trace.Trace{
		"A0": &A0, "A1": &A1,
		"B0": &B0, "B1": &B1,
		"C0": &C0, "C1": &C1,
		"D0": &D0, "D1": &D1,
	}
}
