package univariate

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
)

func TestComputeQuotientTrivial(t *testing.T) {
	// Test with a simple case where we can verify the result
	// Let P0(x) = x and P1(x) = x
	// Let Q = x0^2 - x1^2 = (x0 - x1)(x0 + x1)
	// Then Q(P0, P1) = x^2 - x^2 = 0
	// So Q(P0, P1) = 0 * (X^n - 1) for any n
	// The quotient should be 0

	var one koalabear.Element
	one.SetUint64(1)

	// Create P0(x) = x (degree 1)
	coeffs0 := make([]koalabear.Element, 8)
	coeffs0[1] = one
	P0, err := NewPolynomial(coeffs0, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1(x) = x (degree 1)
	coeffs1 := make([]koalabear.Element, 8)
	coeffs1[1] = one
	P1, err := NewPolynomial(coeffs1, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Create Q = x0^2 - x1^2
	var minusOne koalabear.Element
	minusOne.SetInt64(-1)
	Q := sym.NewVar("x0").Pow(2).Add(sym.NewVar("x1").Pow(2).Mul(sym.NewConst(minusOne)))

	// Compute the quotient
	Pi := []Polynomial{P0, P1}
	quotient, err := ComputeQuotient(Pi, Q, WithOutputName("quotient"))
	if err != nil {
		t.Fatalf("ComputeQuotient failed: %v", err)
	}

	// The quotient should be zero (or very close to zero)
	// Check that all coefficients are zero
	for i, coeff := range quotient.EP.Coefficients {
		if !coeff.IsZero() {
			t.Errorf("Expected zero coefficient at index %d, got %s", i, coeff.String())
		}
	}
}

func TestComputeQuotientBasic(t *testing.T) {
	// Basic test: just verify ComputeQuotient runs without errors
	// and returns a polynomial with the correct properties

	var one, two koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)

	// Create P0(x) = x (degree 1)
	coeffs0 := make([]koalabear.Element, 8)
	coeffs0[1] = one
	P0, err := NewPolynomial(coeffs0, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1(x) = 2x (degree 1)
	coeffs1 := make([]koalabear.Element, 8)
	coeffs1[1] = two
	P1, err := NewPolynomial(coeffs1, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Create Q = x0^2 - 2*x1
	// Q(P0, P1) = x^2 - 2*2x = x^2 - 4x
	// This is not necessarily 0 mod X^8-1, but we can still compute the quotient
	var negOne koalabear.Element
	negOne.SetInt64(-1)
	Q := sym.NewVar("x0").Pow(2).Add(sym.NewVar("x1").Mul(sym.NewConst(two)).Mul(sym.NewConst(negOne)))

	// Compute the quotient
	Pi := []Polynomial{P0, P1}
	quotient, err := ComputeQuotient(Pi, Q, WithOutputName("quotient"))
	if err != nil {
		t.Fatalf("ComputeQuotient failed: %v", err)
	}

	// Verify basic properties
	if quotient.EP == nil {
		t.Fatal("Quotient is nil")
	}

	if quotient.EP.Basis != Canonical {
		t.Errorf("Expected Canonical basis, got %v", quotient.EP.Basis)
	}

	if quotient.EP.Layout != Normal {
		t.Errorf("Expected Normal layout, got %v", quotient.EP.Layout)
	}

	if len(quotient.EP.Coefficients) != 8 {
		t.Errorf("Expected 8 coefficients, got %d", len(quotient.EP.Coefficients))
	}
}

func TestComputeQuotient(t *testing.T) {

	// create an expression Q(P_0, .., P_n) which is divisible by X^n - 1, for some n

	varindexQ := make(sym.VarIndex)
	varindexQ["x0"] = 0
	varindexQ["x1"] = 1
	varindexQ["x2"] = 2
	varindexQ["x3"] = 3

	varindexQpartial := make(sym.VarIndex)
	varindexQpartial["x0"] = 0
	varindexQpartial["x1"] = 1
	varindexQpartial["x2"] = 2

	// Q = X0^3 + X1 * X2 + X3
	Q := sym.NewVar("x0").Pow(3).Add(sym.NewVar("x1").Mul(sym.NewVar("x2"))).Add(sym.NewVar("x3"))

	size := 16
	numVars := Q.NumVars()
	Pi := make([]Polynomial, numVars)
	for i := 0; i < numVars; i++ {
		coeffs := make([]koalabear.Element, size)
		varName := fmt.Sprintf("x%d", i)
		Pi[i], _ = NewInterpolatedPolynomial(coeffs, varName)
	}

	// set the first numVars-1 variables randomly
	for i := 0; i < numVars-1; i++ {
		for j := 0; j < size; j++ {
			Pi[i].EP.Coefficients[j].SetRandom()
		}
	}

	// set the last variable x3= -(x0^3 + x1*x2) to ensure Q(Pi) = 0 mod X^n - 1
	// QTruncated := Q -X3 = X0^3 + X1 * X2
	QTruncated := sym.NewVar("x0").Pow(3).Add(sym.NewVar("x1").Mul(sym.NewVar("x2")))
	QTruncatedHorner := sym.ToHorner(sym.Convert(QTruncated, varindexQpartial, 3))
	for i := 0; i < size; i++ {
		Pi[numVars-1].EP.Coefficients[i] = QTruncatedHorner.Eval([]koalabear.Element{Pi[0].EP.Coefficients[i], Pi[1].EP.Coefficients[i], Pi[2].EP.Coefficients[i]})
		Pi[numVars-1].EP.Coefficients[i].Neg(&Pi[numVars-1].EP.Coefficients[i])
	}

	// check that Q(Pi) = 0 on the zeroes of X^n - 1
	QHorner := sym.ToHorner(sym.Convert(Q, varindexQ, numVars))
	xi := make([]koalabear.Element, numVars)
	for i := 0; i < size; i++ {
		for j := 0; j < numVars; j++ {
			xi[j].Set(&Pi[j].EP.Coefficients[i])
		}
		z := QHorner.Eval(xi)
		if !z.IsZero() {
			t.Fatalf("Q(Pi) is not zero at index %d: got %s", i, z.String())
		}
	}

	// convert the Pi in canonical basis
	d := fft.NewDomain(uint64(size))
	for i := 0; i < numVars; i++ {
		Pi[i].ToBasis(d, Canonical)
	}

	// check that Q(Pi) = 0 on the zeroes of X^n - 1 again, now that the Pi are in canonical basis
	var acc koalabear.Element
	acc.SetOne()
	for i := 0; i < size; i++ {
		for j := 0; j < numVars; j++ {
			xi[j], _ = Pi[j].Evaluate(acc) // the Pi are in canonical basis, so we can evaluate them at the generator directly
		}
		z := QHorner.Eval(xi)
		if !z.IsZero() {
			t.Fatalf("Q(Pi) is not zero at index %d after converting to canonical basis: got %s", i, z.String())
		}
		acc.Mul(&acc, &d.Generator) // move to the next evaluation point
	}

	// now Pi verify Q(Pi) = 0 mod X^n - 1, so we can compute the quotient
	quotient, err := ComputeQuotient(Pi, Q, WithOutputName("quotient"), WithResultBasis(Canonical), WithResultLayout(Normal))
	if err != nil {
		t.Fatalf("ComputeQuotient failed: %v", err)
	}

	// Verify that Q(Pi) = quotient * (X^n - 1) where n is the size of the original polynomials
	// Compute Q(Pi) using ComputeSym to get the full polynomial composition
	QPi, err := ComputeSym(Pi, Q, WithOutputName("QPi"), WithResultBasis(Canonical), WithResultLayout(Normal))
	if err != nil {
		t.Fatalf("ComputeSym for verification failed: %v", err)
	}

	// QPi should equal quotient * (X^size - 1) as polynomials
	// We can verify this by evaluating both sides at a random point
	var x koalabear.Element
	x.SetRandom()

	QPix, err := QPi.Evaluate(x)
	if err != nil {
		t.Fatalf("Failed to evaluate QPi: %v", err)
	}

	quotientx, err := quotient.Evaluate(x)
	if err != nil {
		t.Fatalf("Failed to evaluate quotient: %v", err)
	}

	// Use the original polynomial size for X^n - 1
	var xnMinusOne, one koalabear.Element
	one.SetOne()
	xnMinusOne.Exp(x, big.NewInt(int64(size))) // x^n where n is the original domain size
	xnMinusOne.Sub(&xnMinusOne, &one)          // x^n - 1

	var expected koalabear.Element
	expected.Mul(&quotientx, &xnMinusOne)

	if !expected.Equal(&QPix) {
		t.Errorf("Expected Q(Pi)(x) = quotient(x) * (x^%d - 1): got Q(Pi)(x) = %s, quotient(x) * (x^%d - 1) = %s",
			size, QPix.String(), size, expected.String())
	}
}
