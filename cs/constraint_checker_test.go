package cs

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

func TestTraceTrivialQuotient(t *testing.T) {

	// create a constraint x0 + x1 - x2 = 0
	P, C, N := GetTrivialVanishingConstraint(t)

	S := System{Trace: P, Constraint: C, N: N}
	if err := QuotientChecker(S); err != nil {
		t.Fatalf("Trace does not satisfy the constraint: %v", err)
	}

}

func TestTraceNonTrivialQuotient(t *testing.T) {

	P, C, N := GetNonTrivialVanishingConstraint(t)
	S := System{Trace: P, Constraint: C, N: N}

	// At this stage, the trace T statisfies C on the domain mod X^16-1.
	err := QuotientChecker(S)
	if err != nil {
		t.Fatal(err)
	}

}

func TestBruteForceChecker(t *testing.T) {

	t.Run("ValidSystem", func(t *testing.T) {
		// Create a constraint x0 + x1 - x2 = 0
		C := sym.NewVar("x0").Add(sym.NewVar("x1")).Sub(sym.NewVar("x2"))

		// Create a trace matching the constraint
		size := 16
		nbColumns := 3
		columns := make([]univariate.Polynomial, nbColumns)
		for i := 0; i < nbColumns-1; i++ {
			coeffs := make([]koalabear.Element, size)
			for j := 0; j < size; j++ {
				coeffs[j].SetUint64(uint64(i*size + j + 1))
			}
			var err error
			columns[i], err = univariate.NewInterpolatedPolynomial(coeffs, fmt.Sprintf("x%d", i))
			if err != nil {
				t.Fatalf("Failed to create column %d: %v", i, err)
			}
		}
		// Set x2 = x0 + x1 to satisfy the constraint
		coeffs := make([]koalabear.Element, size)
		for j := 0; j < size; j++ {
			for i := 0; i < nbColumns-1; i++ {
				c := columns[i].GetCoefficient(j)
				coeffs[j].Add(&coeffs[j], &c)
			}
		}
		columns[nbColumns-1], _ = univariate.NewInterpolatedPolynomial(coeffs, fmt.Sprintf("x%d", nbColumns-1))

		S := System{Trace: columns, Constraint: C, N: size}

		// Test BruteForceChecker
		if err := BruteForceChecker(S); err != nil {
			t.Fatalf("BruteForceChecker failed on valid system: %v", err)
		}
	})

	t.Run("InvalidSystem", func(t *testing.T) {
		// Create a constraint x0 + x1 - x2 = 0
		C := sym.NewVar("x0").Add(sym.NewVar("x1")).Sub(sym.NewVar("x2"))

		// Create a trace that does NOT match the constraint
		size := 16
		nbColumns := 3
		columns := make([]univariate.Polynomial, nbColumns)
		for i := 0; i < nbColumns; i++ {
			coeffs := make([]koalabear.Element, size)
			for j := 0; j < size; j++ {
				// Set random values that don't satisfy the constraint
				coeffs[j].SetUint64(uint64(i*size + j + 1))
			}
			var err error
			columns[i], err = univariate.NewInterpolatedPolynomial(coeffs, fmt.Sprintf("x%d", i))
			if err != nil {
				t.Fatalf("Failed to create column %d: %v", i, err)
			}
		}

		S := System{Trace: columns, Constraint: C, N: size}

		// Test BruteForceChecker - should fail
		err := BruteForceChecker(S)
		if err == nil {
			t.Fatal("BruteForceChecker should have failed on invalid system, but passed")
		}
		t.Logf("Expected error: %v", err)
	})

	t.Run("SquareConstraint", func(t *testing.T) {
		// Create a constraint x0^2 - x1 = 0
		C := sym.NewVar("x0").Pow(2).Sub(sym.NewVar("x1"))

		// Generate a trace T such that x1 = x0^2 at all points
		size := 16
		coeffs := make([][]koalabear.Element, 2)
		coeffs[0] = make([]koalabear.Element, size)
		coeffs[1] = make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			coeffs[0][i].SetUint64(uint64(i + 1))
			coeffs[1][i].Square(&coeffs[0][i])
		}

		T := make([]univariate.Polynomial, 2)
		var err error
		for i := 0; i < 2; i++ {
			T[i], err = univariate.NewInterpolatedPolynomial(coeffs[i], fmt.Sprintf("x%d", i))
			if err != nil {
				t.Fatal(err)
			}
		}

		S := System{Trace: T, Constraint: C, N: size}

		// Test BruteForceChecker
		if err := BruteForceChecker(S); err != nil {
			t.Fatalf("BruteForceChecker failed on valid square constraint system: %v", err)
		}
	})
}
