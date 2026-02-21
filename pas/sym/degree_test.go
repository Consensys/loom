package sym

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestPolynomialDegree(t *testing.T) {
	var one, two koalabear.Element
	one.SetOne()
	two.SetUint64(2)

	// Test zero polynomial
	zeroPoly := ConstPoly(3, koalabear.Element{})
	if deg := zeroPoly.Degree(); deg != NegInf {
		t.Errorf("Zero polynomial degree: got %d, expected %d (NegInf)", deg, NegInf)
	}

	// Test constant polynomial
	constPoly := ConstPoly(3, one)
	if deg := constPoly.Degree(); deg != 0 {
		t.Errorf("Constant polynomial degree: got %d, expected 0", deg)
	}

	// Test linear polynomial: x0
	linearPoly := VarPoly(3, 0)
	if deg := linearPoly.Degree(); deg != 1 {
		t.Errorf("Linear polynomial degree: got %d, expected 1", deg)
	}

	// Test x0 * x1 (degree 2)
	x0 := VarPoly(3, 0)
	x1 := VarPoly(3, 1)
	quadPoly := x0.Mul(x1)
	if deg := quadPoly.Degree(); deg != 2 {
		t.Errorf("x0*x1 polynomial degree: got %d, expected 2", deg)
	}

	// Test x0^2 + x1 (degree 2)
	x0Squared := x0.Pow(2)
	sumPoly := x0Squared.Add(x1)
	if deg := sumPoly.Degree(); deg != 2 {
		t.Errorf("x0^2 + x1 polynomial degree: got %d, expected 2", deg)
	}

	// Test x0^3 * x1^2 (degree 5)
	x0Cubed := x0.Pow(3)
	x1Squared := x1.Pow(2)
	highDegPoly := x0Cubed.Mul(x1Squared)
	if deg := highDegPoly.Degree(); deg != 5 {
		t.Errorf("x0^3 * x1^2 polynomial degree: got %d, expected 5", deg)
	}
}

func TestHornerDegree(t *testing.T) {
	var one, two koalabear.Element
	one.SetOne()
	two.SetUint64(2)

	// Test zero polynomial
	zeroPoly := ConstPoly(3, koalabear.Element{})
	zeroHorner := ToHorner(zeroPoly)
	if deg := zeroHorner.Degree(); deg != NegInf {
		t.Errorf("Zero Horner degree: got %d, expected %d (NegInf)", deg, NegInf)
	}

	// Test constant polynomial
	constPoly := ConstPoly(3, one)
	constHorner := ToHorner(constPoly)
	if deg := constHorner.Degree(); deg != 0 {
		t.Errorf("Constant Horner degree: got %d, expected 0", deg)
	}

	// Test linear polynomial: x0
	linearPoly := VarPoly(3, 0)
	linearHorner := ToHorner(linearPoly)
	if deg := linearHorner.Degree(); deg != 1 {
		t.Errorf("Linear Horner degree: got %d, expected 1", deg)
	}

	// Test x0 * x1 (degree 2)
	x0 := VarPoly(3, 0)
	x1 := VarPoly(3, 1)
	quadPoly := x0.Mul(x1)
	quadHorner := ToHorner(quadPoly)
	if deg := quadHorner.Degree(); deg != 2 {
		t.Errorf("x0*x1 Horner degree: got %d, expected 2", deg)
	}

	// Test x0^2 + x1 (degree 2)
	x0Squared := x0.Pow(2)
	sumPoly := x0Squared.Add(x1)
	sumHorner := ToHorner(sumPoly)
	if deg := sumHorner.Degree(); deg != 2 {
		t.Errorf("x0^2 + x1 Horner degree: got %d, expected 2", deg)
	}

	// Test x0^3 * x1^2 (degree 5)
	x0Cubed := x0.Pow(3)
	x1Squared := x1.Pow(2)
	highDegPoly := x0Cubed.Mul(x1Squared)
	highDegHorner := ToHorner(highDegPoly)
	if deg := highDegHorner.Degree(); deg != 5 {
		t.Errorf("x0^3 * x1^2 Horner degree: got %d, expected 5", deg)
	}
}

func TestDegreeConsistency(t *testing.T) {
	// Verify that Polynomial.Degree() == Horner.Degree() for the same polynomial
	var one koalabear.Element
	one.SetOne()

	testCases := []struct {
		name string
		poly Polynomial
	}{
		{"zero", ConstPoly(3, koalabear.Element{})},
		{"constant", ConstPoly(3, one)},
		{"x0", VarPoly(3, 0)},
		{"x0*x1", VarPoly(3, 0).Mul(VarPoly(3, 1))},
		{"x0^2 + x1", VarPoly(3, 0).Pow(2).Add(VarPoly(3, 1))},
		{"x0^3 * x1^2", VarPoly(3, 0).Pow(3).Mul(VarPoly(3, 1).Pow(2))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			polyDeg := tc.poly.Degree()
			hornerDeg := ToHorner(tc.poly).Degree()
			if polyDeg != hornerDeg {
				t.Errorf("%s: Polynomial degree %d != Horner degree %d",
					tc.name, polyDeg, hornerDeg)
			}
		})
	}
}
