package sym

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestExprNumCommittedColumns(t *testing.T) {
	var one koalabear.Element
	one.SetOne()

	testCases := []struct {
		name     string
		expr     Expr
		expected int
	}{
		{"constant", NewConst(one), 0},
		{"single var", NewCommittedColumn("X"), 1},
		{"two vars", NewCommittedColumn("X").Add(NewCommittedColumn("Y")), 2},
		{"three vars", NewCommittedColumn("X").Mul(NewCommittedColumn("Y")).Add(NewCommittedColumn("Z")), 3},
		{"repeated var", NewCommittedColumn("X").Add(NewCommittedColumn("X")), 1},
		{"x^2 + y", NewCommittedColumn("X").Pow(2).Add(NewCommittedColumn("Y")), 2},
		{"x*y*z", Prod(NewCommittedColumn("X"), NewCommittedColumn("Y"), NewCommittedColumn("Z")), 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.expr.NumCommittedColumns()
			if result != tc.expected {
				t.Errorf("%s: got %d variables, expected %d", tc.name, result, tc.expected)
			}
		})
	}
}

func TestPolynomialNumCommittedColumns(t *testing.T) {
	testCases := []struct {
		name     string
		numCommittedColumns  int
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
			poly := ConstPoly(tc.numCommittedColumns, one)
			result := poly.NumCommittedColumns()
			if result != tc.expected {
				t.Errorf("%s: got %d variables, expected %d", tc.name, result, tc.expected)
			}
		})
	}
}

func TestHornerNumCommittedColumns(t *testing.T) {
	testCases := []struct {
		name     string
		numCommittedColumns  int
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
			if tc.numCommittedColumns == 0 {
				poly = ConstPoly(0, one)
			} else {
				poly = VarPoly(tc.numCommittedColumns, 0) // Use first variable
			}

			horner := ToHorner(poly)
			result := horner.NumCommittedColumns()
			if result != tc.expected {
				t.Errorf("%s: got %d variables, expected %d", tc.name, result, tc.expected)
			}
		})
	}
}

func TestNumCommittedColumnsConsistency(t *testing.T) {
	var one koalabear.Element
	one.SetOne()

	// Create variables
	x0 := NewCommittedColumn("X0")
	x1 := NewCommittedColumn("X1")
	x2 := NewCommittedColumn("X2")

	testCases := []struct {
		name    string
		expr    Expr
		numCommittedColumns int
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
			exprCommittedColumns := tc.expr.NumCommittedColumns()

			// Create varindex mapping
			varindex := make(VarIndex)
			varindex["X0"] = 0
			varindex["X1"] = 1
			varindex["X2"] = 2

			// Convert to polynomial
			poly := Convert(tc.expr, varindex, tc.numCommittedColumns)
			polyCommittedColumns := poly.NumCommittedColumns()

			// Convert to Horner
			horner := ToHorner(poly)
			hornerCommittedColumns := horner.NumCommittedColumns()

			// Verify consistency
			if polyCommittedColumns != tc.numCommittedColumns {
				t.Errorf("%s: Polynomial.NumCommittedColumns() = %d, expected %d",
					tc.name, polyCommittedColumns, tc.numCommittedColumns)
			}

			if hornerCommittedColumns != tc.numCommittedColumns {
				t.Errorf("%s: Horner.NumCommittedColumns() = %d, expected %d",
					tc.name, hornerCommittedColumns, tc.numCommittedColumns)
			}

			// Expr.NumCommittedColumns() might be less than or equal to the polynomial space size
			// since the polynomial space size is determined by the varindex
			if exprCommittedColumns > tc.numCommittedColumns {
				t.Errorf("%s: Expr.NumCommittedColumns() = %d > polynomial space size %d",
					tc.name, exprCommittedColumns, tc.numCommittedColumns)
			}

			t.Logf("%s: Expr.NumCommittedColumns()=%d, Polynomial.NumCommittedColumns()=%d, Horner.NumCommittedColumns()=%d",
				tc.name, exprCommittedColumns, polyCommittedColumns, hornerCommittedColumns)
		})
	}
}
