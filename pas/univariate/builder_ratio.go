package univariate

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
)

// BuildRatio builds the ratio polynomial R such that R[1]=1, R[w^i+1]=R[w]*Q1(P1[1][w^i], .., P1[n][w^i])/Q2(P2[1][w^i], .., P2[m][w^i]) for i=1..n-1 where w is the generator of the FFT domain of size n. The ratio polynomial is returned in Lagrange form, Normal layout.
func BuildRatio(C1, C2 sym.Expr, P1, P2 []Polynomial, opts ...BuilderOption) (Polynomial, error) {

	config := NewBuilderConfig()
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return Polynomial{}, nil
		}
	}

	varindex1 := make(sym.VarIndex)
	varindex2 := make(sym.VarIndex)
	for i := 0; i < len(P1); i++ {
		varindex1[P1[i].ID] = i
	}
	for i := 0; i < len(P2); i++ {
		varindex2[P2[i].ID] = i
	}

	// Convert C1 and C2 to Horner form
	Q1 := sym.ToHorner(sym.Convert(C1, varindex1, len(P1)))
	Q2 := sym.ToHorner(sym.Convert(C2, varindex2, len(P2)))

	// ensure that the polynomials are of the same degree
	if len(P1) == 0 {
		return Polynomial{}, fmt.Errorf("P1 cannot be empty")
	}
	if len(P2) == 0 {
		return Polynomial{}, fmt.Errorf("P2 cannot be empty")
	}

	// find a non zero poly to get the degree (the constant polynomials are treated separately from the rest)
	var targetDegree int
	for i := 0; i < len(P1); i++ {
		if !P1[i].IsConstant() {
			targetDegree = P1[i].Degree()
			break
		}
	}
	for i := 1; i < len(P1); i++ {
		if P1[i].Degree() != targetDegree && !P1[i].IsConstant() {
			return Polynomial{}, fmt.Errorf("P1[%d] has degree %d, expected %d", i, P1[i].Degree(), targetDegree)
		}
	}
	for i := 0; i < len(P2); i++ {
		if P2[i].Degree() != targetDegree && !P2[i].IsConstant() {
			return Polynomial{}, fmt.Errorf("P2[%d] has degree %d, expected %d", i, P2[i].Degree(), targetDegree)
		}
	}

	// Put all polynomials in P1 and P2 in Lagrange form, with an fft domain of size nextpowerOfTwo(P1[0].Degree()+1)
	domainSize := NextPowerOfTwo(targetDegree + 1)
	domain := fft.NewDomain(uint64(domainSize))

	// Make copies and convert to Lagrange form
	P1Copies := make([]Polynomial, len(P1))
	for i := 0; i < len(P1); i++ {
		P1Copies[i] = Polynomial{
			EP: &EPolynomial{},
		}
		Copy(&P1Copies[i], &P1[i])
		if err := P1Copies[i].ToBasis(domain, Lagrange); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert P1[%d] to Lagrange: %w", i, err)
		}
		P1Copies[i].ToLayout(Normal)
	}

	P2Copies := make([]Polynomial, len(P2))
	for i := 0; i < len(P2); i++ {
		P2Copies[i] = Polynomial{
			EP: &EPolynomial{},
		}
		Copy(&P2Copies[i], &P2[i])
		if err := P2Copies[i].ToBasis(domain, Lagrange); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert P2[%d] to Lagrange: %w", i, err)
		}
		P2Copies[i].ToLayout(Normal)
	}

	// Create the ratio polynomial R in Lagrange form
	// * R is of size domainSize
	// * R[0] = 1
	// * R[i+1] = R[i]*Q1(P1[0][i], .., P1[n-1][i])/Q2(P2[0][i], .., P2[m-1][i]) for i=0..domainSize-2
	coeffs := make([]koalabear.Element, domainSize)

	var one koalabear.Element
	one.SetOne()
	coeffs[0] = one

	// Prepare value arrays for Q1 and Q2 evaluation
	values1 := make([]koalabear.Element, len(P1Copies))
	values2 := make([]koalabear.Element, len(P2Copies))

	for i := 0; i < domainSize-1; i++ {
		// Gather values from P1 at point i
		for j := 0; j < len(P1Copies); j++ {
			values1[varindex1[P1Copies[j].ID]] = P1Copies[j].GetCoefficient(i)
		}

		// Gather values from P2 at point i
		for j := 0; j < len(P2Copies); j++ {
			values2[varindex2[P2Copies[j].ID]] = P2Copies[j].GetCoefficient(i)
		}

		// Evaluate Q1 and Q2
		q1Val := Q1.Eval(values1)
		q2Val := Q2.Eval(values2)

		// Check that q2Val is not zero (avoid division by zero)
		if q2Val.IsZero() {
			return Polynomial{}, fmt.Errorf("division by zero at index %d: Q2 evaluated to zero", i)
		}

		// Compute R[i+1] = R[i] * Q1 / Q2
		var ratio koalabear.Element
		ratio.Inverse(&q2Val)
		ratio.Mul(&ratio, &q1Val)
		coeffs[i+1].Mul(&coeffs[i], &ratio)
	}

	// Return R in Lagrange form, Normal layout
	return NewInterpolatedPolynomial(coeffs, config.OutputName)
}
