package univariate

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

func TestBuildLinComb(t *testing.T) {
	// Test basic linear combination
	t.Run("BasicLinearCombination", func(t *testing.T) {
		// Create three polynomials in Canonical basis
		// P0(x) = 1 + 2x + 3x^2 + 4x^3
		// P1(x) = 5 + 6x + 7x^2 + 8x^3
		// P2(x) = 9 + 10x + 11x^2 + 12x^3

		coeffs0 := []koalabear.Element{}
		coeffs1 := []koalabear.Element{}
		coeffs2 := []koalabear.Element{}
		for i := 0; i < 4; i++ {
			var c0, c1, c2 koalabear.Element
			c0.SetUint64(uint64(i + 1))
			c1.SetUint64(uint64(i + 5))
			c2.SetUint64(uint64(i + 9))
			coeffs0 = append(coeffs0, c0)
			coeffs1 = append(coeffs1, c1)
			coeffs2 = append(coeffs2, c2)
		}

		P0, err := NewPolynomial(coeffs0, WithID("P0"))
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		P1, err := NewPolynomial(coeffs1, WithID("P1"))
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}
		P2, err := NewPolynomial(coeffs2, WithID("P2"))
		if err != nil {
			t.Fatalf("Failed to create P2: %v", err)
		}

		// Set alpha = 3
		var alpha koalabear.Element
		alpha.SetUint64(3)

		// Compute R = P0 + 3*P1 + 9*P2
		P := []Polynomial{P0, P1, P2}
		R, err := BuildLinComb(P, alpha, WithOutputName("R"))
		if err != nil {
			t.Fatalf("BuildLinComb failed: %v", err)
		}

		// Verify the result
		// R(x) = (1 + 3*5 + 9*9) + (2 + 3*6 + 9*10)x + (3 + 3*7 + 9*11)x^2 + (4 + 3*8 + 9*12)x^3
		//      = (1 + 15 + 81) + (2 + 18 + 90)x + (3 + 21 + 99)x^2 + (4 + 24 + 108)x^3
		//      = 97 + 110x + 123x^2 + 136x^3

		expected := []uint64{97, 110, 123, 136}
		for i := 0; i < 4; i++ {
			var expectedVal koalabear.Element
			expectedVal.SetUint64(expected[i])
			actualVal := R.EP.Coefficients[i]
			if !actualVal.Equal(&expectedVal) {
				t.Errorf("Coefficient %d: expected %s, got %s", i, expectedVal.String(), actualVal.String())
			}
		}
		if R.EP.Basis != Canonical {
			t.Errorf("Expected Canonical basis, got %v", R.EP.Basis)
		}
		if R.EP.Layout != Normal {
			t.Errorf("Expected Normal layout, got %v", R.EP.Layout)
		}
	})

	// Test with Lagrange basis
	t.Run("LagrangeBasis", func(t *testing.T) {
		// Create polynomials in Lagrange basis
		size := 8
		evals0 := make([]koalabear.Element, size)
		evals1 := make([]koalabear.Element, size)

		for i := 0; i < size; i++ {
			evals0[i].SetUint64(uint64(i + 1))
			evals1[i].SetUint64(uint64(i + 10))
		}

		P0, err := NewInterpolatedPolynomial(evals0, "P0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		P1, err := NewInterpolatedPolynomial(evals1, "P1")
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}

		// Set alpha = 2
		var alpha koalabear.Element
		alpha.SetUint64(2)

		// Compute R = P0 + 2*P1
		P := []Polynomial{P0, P1}
		R, err := BuildLinComb(P, alpha)
		if err != nil {
			t.Fatalf("BuildLinComb failed: %v", err)
		}

		// Verify the result
		// In Lagrange basis, R[i] = P0[i] + 2*P1[i]
		for i := 0; i < size; i++ {
			var expected koalabear.Element
			expected.SetUint64(uint64(i + 1))
			var term koalabear.Element
			term.SetUint64(uint64(2 * (i + 10)))
			expected.Add(&expected, &term)

			actualVal := R.GetCoefficient(i)
			if !actualVal.Equal(&expected) {
				t.Errorf("Coefficient %d: expected %s, got %s", i, expected.String(), actualVal.String())
			}
		}

		// Verify basis is preserved
		if R.EP.Basis != Lagrange {
			t.Errorf("Expected Lagrange basis, got %v", R.EP.Basis)
		}
	})

	// Test with BitReversed layout
	t.Run("BitReversedLayout", func(t *testing.T) {
		// Create polynomials in Lagrange basis with BitReversed layout
		size := 8
		coeffs0 := make([]koalabear.Element, size)
		coeffs1 := make([]koalabear.Element, size)

		for i := 0; i < size; i++ {
			coeffs0[i].SetUint64(uint64(i + 1))
			coeffs1[i].SetUint64(uint64(i + 10))
		}

		P0, err := NewInterpolatedPolynomial(coeffs0, "P0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		P1, err := NewInterpolatedPolynomial(coeffs1, "P1")
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}

		// Convert to BitReversed layout
		domain := fft.NewDomain(uint64(size))
		P0.ToBasis(domain, Lagrange)
		P1.ToBasis(domain, Lagrange)
		P0.ToLayout(BitReversed)
		P1.ToLayout(BitReversed)

		// Set alpha = 5
		var alpha koalabear.Element
		alpha.SetUint64(5)

		// Compute R = P0 + 5*P1
		P := []Polynomial{P0, P1}
		R, err := BuildLinComb(P, alpha)
		if err != nil {
			t.Fatalf("BuildLinComb failed: %v", err)
		}

		// Verify layout is preserved
		if R.EP.Layout != BitReversed {
			t.Errorf("Expected BitReversed layout, got %v", R.EP.Layout)
		}

		// Verify the coefficients (coefficient-wise operation)
		for i := 0; i < size; i++ {
			var expected koalabear.Element
			expected.Set(&P0.EP.Coefficients[i])
			var term koalabear.Element
			term.Mul(&alpha, &P1.EP.Coefficients[i])
			expected.Add(&expected, &term)

			if !R.EP.Coefficients[i].Equal(&expected) {
				t.Errorf("Coefficient %d: expected %s, got %s", i, expected.String(), R.EP.Coefficients[i].String())
			}
		}
	})

	// Test error: empty input
	t.Run("ErrorEmptyInput", func(t *testing.T) {
		var alpha koalabear.Element
		alpha.SetUint64(2)

		P := []Polynomial{}
		_, err := BuildLinComb(P, alpha)
		if err == nil {
			t.Fatal("Expected error for empty input, got nil")
		}
	})

	// Test error: single polynomial
	t.Run("ErrorSinglePolynomial", func(t *testing.T) {
		coeffs := []koalabear.Element{}
		for i := 0; i < 4; i++ {
			var c koalabear.Element
			c.SetUint64(uint64(i + 1))
			coeffs = append(coeffs, c)
		}

		P0, err := NewPolynomial(coeffs, WithID("P0"))
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}

		var alpha koalabear.Element
		alpha.SetUint64(2)

		P := []Polynomial{P0}
		_, err = BuildLinComb(P, alpha)
		if err == nil {
			t.Fatal("Expected error for single polynomial, got nil")
		}
	})

	// Test error: mismatched sizes
	t.Run("ErrorMismatchedSizes", func(t *testing.T) {
		coeffs0 := []koalabear.Element{}
		coeffs1 := []koalabear.Element{}
		for i := 0; i < 4; i++ {
			var c0 koalabear.Element
			c0.SetUint64(uint64(i + 1))
			coeffs0 = append(coeffs0, c0)
		}
		for i := 0; i < 8; i++ {
			var c1 koalabear.Element
			c1.SetUint64(uint64(i + 5))
			coeffs1 = append(coeffs1, c1)
		}

		P0, err := NewPolynomial(coeffs0, WithID("P0"))
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		P1, err := NewPolynomial(coeffs1, WithID("P1"))
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}

		var alpha koalabear.Element
		alpha.SetUint64(2)

		P := []Polynomial{P0, P1}
		_, err = BuildLinComb(P, alpha)
		if err == nil {
			t.Fatal("Expected error for mismatched sizes, got nil")
		}
	})

	// Test error: mismatched basis
	t.Run("ErrorMismatchedBasis", func(t *testing.T) {
		coeffs0 := []koalabear.Element{}
		coeffs1 := []koalabear.Element{}
		for i := 0; i < 4; i++ {
			var c0, c1 koalabear.Element
			c0.SetUint64(uint64(i + 1))
			c1.SetUint64(uint64(i + 5))
			coeffs0 = append(coeffs0, c0)
			coeffs1 = append(coeffs1, c1)
		}

		P0, err := NewPolynomial(coeffs0, WithID("P0"))
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		P1, err := NewInterpolatedPolynomial(coeffs1, "P1")
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}

		var alpha koalabear.Element
		alpha.SetUint64(2)

		P := []Polynomial{P0, P1}
		_, err = BuildLinComb(P, alpha)
		if err == nil {
			t.Fatal("Expected error for mismatched basis, got nil")
		}
	})

	// Test error: mismatched layout
	t.Run("ErrorMismatchedLayout", func(t *testing.T) {
		size := 8
		coeffs0 := make([]koalabear.Element, size)
		coeffs1 := make([]koalabear.Element, size)

		for i := 0; i < size; i++ {
			coeffs0[i].SetUint64(uint64(i + 1))
			coeffs1[i].SetUint64(uint64(i + 10))
		}

		P0, err := NewInterpolatedPolynomial(coeffs0, "P0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		P1, err := NewInterpolatedPolynomial(coeffs1, "P1")
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}

		// Convert P1 to BitReversed layout
		P1.ToLayout(BitReversed)

		var alpha koalabear.Element
		alpha.SetUint64(2)

		P := []Polynomial{P0, P1}
		_, err = BuildLinComb(P, alpha)
		if err == nil {
			t.Fatal("Expected error for mismatched layout, got nil")
		}
	})
}
