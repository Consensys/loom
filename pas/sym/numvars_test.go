package sym

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestExprNumVars(t *testing.T) {
	var one koalabear.Element
	one.SetOne()

	testCases := []struct {
		name     string
		expr     Expr
		expected int
	}{
		{"constant", NewConst(one), 0},
		{"single var", NewVar("X"), 1},
		{"two vars", NewVar("X").Add(NewVar("Y")), 2},
		{"three vars", NewVar("X").Mul(NewVar("Y")).Add(NewVar("Z")), 3},
		{"repeated var", NewVar("X").Add(NewVar("X")), 1},
		{"x^2 + y", NewVar("X").Pow(2).Add(NewVar("Y")), 2},
		{"x*y*z", Prod(NewVar("X"), NewVar("Y"), NewVar("Z")), 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.expr.NumVars()
			if result != tc.expected {
				t.Errorf("%s: got %d variables, expected %d", tc.name, result, tc.expected)
			}
		})
	}
}

func TestPolynomialNumVars(t *testing.T) {
	testCases := []struct {
		name     string
		numVars  int
		expected int
	}{
		{"0 vars", 0, 0},
		{"1 var", 1, 1},
		{"2 vars", 2, 2},
		{"3 vars", 3, 3},
		{"10 vars", 10, 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var one koalabear.Element
			one.SetOne()
			poly := ConstPoly(tc.numVars, one)
			result := poly.NumVars()
			if result != tc.expected {
				t.Errorf("%s: got %d variables, expected %d", tc.name, result, tc.expected)
			}
		})
	}
}

func TestHornerNumVars(t *testing.T) {
	testCases := []struct {
		name     string
		numVars  int
		expected int
	}{
		{"0 vars constant", 0, 0},
		{"1 var", 1, 1},
		{"2 vars", 2, 2},
		{"3 vars", 3, 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var one koalabear.Element
			one.SetOne()

			// Create a polynomial with the specified number of variables
			var poly Polynomial
			if tc.numVars == 0 {
				poly = ConstPoly(0, one)
			} else {
				poly = VarPoly(tc.numVars, 0) // Use first variable
			}

			horner := ToHorner(poly)
			result := horner.NumVars()
			if result != tc.expected {
				t.Errorf("%s: got %d variables, expected %d", tc.name, result, tc.expected)
			}
		})
	}
}

func TestNumVarsConsistency(t *testing.T) {
	var one koalabear.Element
	one.SetOne()

	// Create variables
	x0 := NewVar("X0")
	x1 := NewVar("X1")
	x2 := NewVar("X2")

	testCases := []struct {
		name    string
		expr    Expr
		numVars int
	}{
		{"constant", NewConst(one), 1},
		{"x0", x0, 2},
		{"x0 + x1", x0.Add(x1), 2},
		{"x0 * x1", x0.Mul(x1), 2},
		{"x0^2", x0.Pow(2), 2},
		{"x0^2 + x1", x0.Pow(2).Add(x1), 2},
		{"x0 * x1 + x2", x0.Mul(x1).Add(x2), 3},
		{"x0^3 * x1^2", x0.Pow(3).Mul(x1.Pow(2)), 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get number of variables from expression
			exprVars := tc.expr.NumVars()

			// Create varindex mapping
			varindex := make(VarIndex)
			varindex["X0"] = 0
			varindex["X1"] = 1
			varindex["X2"] = 2

			// Convert to polynomial
			poly := Convert(tc.expr, varindex, tc.numVars)
			polyVars := poly.NumVars()

			// Convert to Horner
			horner := ToHorner(poly)
			hornerVars := horner.NumVars()

			// Verify consistency
			if polyVars != tc.numVars {
				t.Errorf("%s: Polynomial.NumVars() = %d, expected %d",
					tc.name, polyVars, tc.numVars)
			}

			if hornerVars != tc.numVars {
				t.Errorf("%s: Horner.NumVars() = %d, expected %d",
					tc.name, hornerVars, tc.numVars)
			}

			// Expr.NumVars() might be less than or equal to the polynomial space size
			// since the polynomial space size is determined by the varindex
			if exprVars > tc.numVars {
				t.Errorf("%s: Expr.NumVars() = %d > polynomial space size %d",
					tc.name, exprVars, tc.numVars)
			}

			t.Logf("%s: Expr.NumVars()=%d, Polynomial.NumVars()=%d, Horner.NumVars()=%d",
				tc.name, exprVars, polyVars, hornerVars)
		})
	}
}
