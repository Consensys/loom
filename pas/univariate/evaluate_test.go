package univariate

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

func TestEPolynomialEvaluate(t *testing.T) {
	// Test constant polynomial: p(x) = 5
	t.Run("constant polynomial", func(t *testing.T) {
		var five koalabear.Element
		five.SetUint64(5)

		coeffs := []koalabear.Element{five}
		p, err := NewEPolynomial(coeffs, "test")
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		var x koalabear.Element
		x.SetUint64(10) // Evaluate at x=10

		result, err := p.Evaluate(x)
		if err != nil {
			t.Fatalf("Evaluation failed: %v", err)
		}

		if !result.Equal(&five) {
			t.Errorf("Expected %s, got %s", five.String(), result.String())
		}
	})

	// Test cubic polynomial: p(x) = x^3 - 2x^2 + 3x - 4
	t.Run("cubic polynomial", func(t *testing.T) {
		var one, two, three, four koalabear.Element
		one.SetUint64(1)
		two.SetUint64(2)
		three.SetUint64(3)
		four.SetUint64(4)

		var negTwo, negFour koalabear.Element
		negTwo.Neg(&two)
		negFour.Neg(&four)

		coeffs := []koalabear.Element{negFour, three, negTwo, one} // -4 + 3x - 2x^2 + x^3
		p, err := NewEPolynomial(coeffs, "test")
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		var x koalabear.Element
		x.SetUint64(2) // Evaluate at x=2, expect 8 - 8 + 6 - 4 = 2

		result, err := p.Evaluate(x)
		if err != nil {
			t.Fatalf("Evaluation failed: %v", err)
		}

		var expected koalabear.Element
		expected.SetUint64(2)

		if !result.Equal(&expected) {
			t.Errorf("Expected %s, got %s", expected.String(), result.String())
		}
	})

	// Test evaluation at zero
	t.Run("evaluate at zero", func(t *testing.T) {
		var one, two, three koalabear.Element
		one.SetUint64(1)
		two.SetUint64(2)
		three.SetUint64(3)

		coeffs := []koalabear.Element{three, two, one} // 3 + 2x + x^2
		p, err := NewEPolynomial(coeffs, "test")
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		var x koalabear.Element // x = 0

		result, err := p.Evaluate(x)
		if err != nil {
			t.Fatalf("Evaluation failed: %v", err)
		}

		// Should return the constant term (3)
		if !result.Equal(&three) {
			t.Errorf("Expected %s, got %s", three.String(), result.String())
		}
	})

	// Test error when not in canonical basis
	t.Run("error on non-canonical basis", func(t *testing.T) {
		var one koalabear.Element
		one.SetUint64(1)

		coeffs := []koalabear.Element{one, one}
		p, err := NewEPolynomial(coeffs, "test")
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		// Change basis to Lagrange (simulate)
		p.Basis = Lagrange

		var x koalabear.Element
		x.SetUint64(5)

		_, err = p.Evaluate(x)
		if err == nil {
			t.Error("Expected error when evaluating polynomial not in canonical basis")
		}
	})

	// Test that layout (Normal vs BitReversed) doesn't affect evaluation result
	t.Run("layout independence", func(t *testing.T) {
		var one, two, three, four koalabear.Element
		one.SetUint64(1)
		two.SetUint64(2)
		three.SetUint64(3)
		four.SetUint64(4)

		// Create p(x) = 1 + 2x + 3x^2 + 4x^3
		coeffs := []koalabear.Element{one, two, three, four}
		p, err := NewEPolynomial(coeffs, "test")
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		// Verify it's in Normal layout
		if p.Layout != Normal {
			t.Fatalf("Expected Normal layout, got %v", p.Layout)
		}

		// Evaluate at x = 5
		var x koalabear.Element
		x.SetUint64(5)

		resultNormal, err := p.Evaluate(x)
		if err != nil {
			t.Fatalf("Evaluation failed in Normal layout: %v", err)
		}

		// Convert to BitReversed layout
		p.toBitReversed()
		if p.Layout != BitReversed {
			t.Fatalf("Expected BitReversed layout after conversion, got %v", p.Layout)
		}

		// Evaluate at the same point
		resultBitReversed, err := p.Evaluate(x)
		if err != nil {
			t.Fatalf("Evaluation failed in BitReversed layout: %v", err)
		}

		// Results should be identical
		if !resultNormal.Equal(&resultBitReversed) {
			t.Errorf("Evaluation results differ by layout: Normal gave %s, BitReversed gave %s",
				resultNormal.String(), resultBitReversed.String())
		}

		// Expected value: 1 + 2*5 + 3*25 + 4*125 = 1 + 10 + 75 + 500 = 586
		var expected koalabear.Element
		expected.SetUint64(586)

		if !resultNormal.Equal(&expected) {
			t.Errorf("Expected %s, got %s", expected.String(), resultNormal.String())
		}
	})
}

// func TestShiftedPolynomial(t *testing.T) {

// 	size := 8
// 	coeffs0 := make([]koalabear.Element, size)
// 	refCoeffs := make([]koalabear.Element, size)
// 	refCoeffsLagrangeCoset := make([]koalabear.Element, size)
// 	for i := 0; i < size; i++ {
// 		coeffs0[i].SetRandom()
// 		refCoeffs[i].Set(&coeffs0[i])
// 	}
// 	d := fft.NewDomain(8)
// 	copy(refCoeffsLagrangeCoset, refCoeffs)
// 	d.FFTInverse(refCoeffsLagrangeCoset, fft.DIF)
// 	d.FFT(refCoeffsLagrangeCoset, fft.DIT, fft.OnCoset())

// 	P0, err := NewInterpolatedPolynomial(coeffs0, "x0")
// 	if err != nil {
// 		t.Fatalf("Failed to create P0: %v", err)
// 	}

// 	// P0 is in Lagrange form, Normal layout
// 	t.Run("Lagrange, Normal layout", func(t *testing.T) {
// 		for i := 0; i < size; i++ {
// 			P0.SetShift(i)
// 			for j := 0; j < size; j++ {
// 				expected := refCoeffs[(j+i)%size]
// 				actual := P0.GetCoefficient(j)
// 				if !actual.Equal(&expected) {
// 					t.Errorf("Shift %d: expected coefficient at index %d to be %s, got %s", i, j, expected.String(), actual.String())
// 				}
// 			}
// 		}
// 	})

// 	P0.SetShift(0)
// 	P0.ToLayout(BitReversed)

// 	// P0 is in Lagrange form, BitReversed layout
// 	t.Run("Lagrange, BitReversed layout", func(t *testing.T) {
// 		for i := 0; i < size; i++ {
// 			P0.SetShift(i)
// 			for j := 0; j < size; j++ {
// 				expected := refCoeffs[(j+i)%size]
// 				actual := P0.GetCoefficient(j)
// 				if !actual.Equal(&expected) {
// 					t.Errorf("Shift %d: expected coefficient at index %d to be %s, got %s", i, j, expected.String(), actual.String())
// 				}
// 			}
// 		}
// 	})

// 	P0.SetShift(0)
// 	P0.ToBasis(d, LagrangeShifted)
// 	P0.ToLayout(Normal)

// 	// P0 is in Lagrange shifted form, Normal layout
// 	t.Run("Lagrange shifted, Normal layout", func(t *testing.T) {
// 		for i := 0; i < size; i++ {
// 			P0.SetShift(i)
// 			for j := 0; j < size; j++ {
// 				expected := refCoeffsLagrangeCoset[(j+i)%size]
// 				actual := P0.GetCoefficient(j)
// 				if !actual.Equal(&expected) {
// 					t.Errorf("Shift %d: expected coefficient at index %d to be %s, got %s", i, j, expected.String(), actual.String())
// 				}
// 			}
// 		}
// 	})

// 	P0.SetShift(0)
// 	P0.ToLayout(BitReversed)
// 	// P0 is in Lagrange shifted form, BitReversed layout
// 	t.Run("Lagrange shifted, BitReversed layout", func(t *testing.T) {
// 		for i := 0; i < size; i++ {
// 			P0.SetShift(i)
// 			for j := 0; j < size; j++ {
// 				expected := refCoeffsLagrangeCoset[(j+i)%size]
// 				actual := P0.GetCoefficient(j)
// 				if !actual.Equal(&expected) {
// 					t.Errorf("Shift %d: expected coefficient at index %d to be %s, got %s", i, j, expected.String(), actual.String())
// 				}
// 			}
// 		}
// 	})

// }

func TestShallowCopy(t *testing.T) {

	size := 8
	coeffs0 := make([]koalabear.Element, size)
	refCoeffs := make([]koalabear.Element, size)
	for i := 0; i < size; i++ {
		coeffs0[i].SetRandom()
	}
	copy(refCoeffs, coeffs0)
	d := fft.NewDomain(8)

	compareCoeffs := func(a, b []koalabear.Element) bool {
		if len(a) != len(b) {
			return false
		}
		for i := 0; i < len(a); i++ {
			if !a[i].Equal(&b[i]) {
				return false
			}
		}
		return true
	}

	t.Run("shift should not affect the original polynomial", func(t *testing.T) {
		var P0, P1, P2 Polynomial
		var err error
		P0, err = NewInterpolatedPolynomial(coeffs0, "x0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		ShallowCopy(&P1, &P0)
		Copy(&P2, &P0)

		for i := 0; i < size; i++ {
			P1.SetShift(i)
			if P0.Shift != 0 {
				t.Errorf("Set Shift on shallow copy not should modify the original polynomial")
			}

			P1.SetShift(0)
			P2.SetShift(i)
			if P0.Shift != 0 {
				t.Errorf("Set Shift on copy should not modify the original polynomial")
			}

		}
	})

	t.Run("change of layout on shallow copy should modify the original polynomial", func(t *testing.T) {
		var P0, P1, P2 Polynomial
		var err error
		P0, err = NewInterpolatedPolynomial(coeffs0, "x0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		ShallowCopy(&P1, &P0)
		Copy(&P2, &P0)

		P0.ToLayout(BitReversed)
		c := compareCoeffs(P0.EP.Coefficients, P0.EP.Coefficients)
		if !c {
			t.Errorf("shallow copy and original should share the same coefficients")
		}
		c = compareCoeffs(P0.EP.Coefficients, P2.EP.Coefficients)
		if c {
			t.Errorf("copy and original should have different coefficients")
		}
	})

	t.Run("change of basis on shallow copy should modify the original polynomial", func(t *testing.T) {
		var P0, P1, P2 Polynomial
		var err error
		P0, err = NewInterpolatedPolynomial(coeffs0, "x0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}
		ShallowCopy(&P1, &P0)
		Copy(&P2, &P0)

		P0.ToBasis(d, LagrangeShifted)
		c := compareCoeffs(P0.EP.Coefficients, P0.EP.Coefficients)
		if !c {
			t.Errorf("shallow copy and original should share the same coefficients")
		}
		c = compareCoeffs(P0.EP.Coefficients, P2.EP.Coefficients)
		if c {
			t.Errorf("copy and original should have different coefficients")
		}
	})

}

func TestShiftedPolynomial(t *testing.T) {

	// the the evaluation of a shifted polynomial in canonical form
	{
		size := 8
		coeffs := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			coeffs[i].SetRandom()
		}
		P, err := NewPolynomial(coeffs, WithID("P"))
		var Q Polynomial
		ShallowCopy(&Q, &P)
		if err != nil {
			t.Fatal("err")
		}

		w, err := koalabear.Generator(uint64(size))
		if err != nil {
			t.Fatal("err")
		}
		var x, wx koalabear.Element
		x.SetRandom()
		wx.Set(&x)
		for i := 0; i < size; i++ {
			Q.SetShift(i)
			Qx, err := Q.Evaluate(x)
			if err != nil {
				t.Fatal("err")
			}

			Pwx, err := P.Evaluate(wx)
			if err != nil {
				t.Fatal("err")
			}

			if !Qx.Equal(&Pwx) {
				t.Errorf("P(w^%d x)!=Q(x) where Q is P shifted by %d", i, i)
			}

			wx.Mul(&wx, &w)
		}
	}

	// check coefficients access with change of basis, layout, with size=degree+1
	{
		size := 8
		coeffs0 := make([]koalabear.Element, size)
		refCoeffs := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			coeffs0[i].SetRandom()
		}
		copy(refCoeffs, coeffs0)
		d := fft.NewDomain(uint64(size))

		// P0 is the reference polynomial
		P0, err := NewInterpolatedPolynomial(coeffs0, "x0")
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}

		// P2 is a copy of P0, which will be shifted for the tests
		var P1 Polynomial
		Copy(&P1, &P0)

		// P1 is in Lagrange form, Normal layout
		t.Run("Lagrange, Normal layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < size; j++ {
					expected := P0.GetCoefficient((j + i) % size)
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})

		P1.SetShift(0)
		P1.ToLayout(BitReversed)

		// P1 is in Lagrange form, BitReversed layout
		t.Run("Lagrange, BitReversed layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < size; j++ {
					expected := P0.GetCoefficient((j + i) % size)
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})

		P0.SetShift(0)
		P0.ToBasis(d, LagrangeShifted)
		P0.ToLayout(Normal)

		P1.SetShift(0)
		P1.ToLayout(Normal)

		P1.ToBasis(d, LagrangeShifted)

		// P0 is in Lagrange shifted form, Normal layout
		t.Run("Lagrange shifted, Normal layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < size; j++ {
					expected := P0.GetCoefficient((j + i) % size)
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})

		P1.SetShift(0)
		P1.ToLayout(BitReversed)

		// P0 is in Lagrange shifted form, BitReversed layout
		t.Run("Lagrange shifted, BitReversed layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < size; j++ {
					expected := P0.GetCoefficient((j + i) % size)
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})
	}

	// check coefficients access with change of basis, layout, with size=4*(degree+1)
	{
		size := 8
		ratio := 4
		// Create a polynomial of degree size-1 (degree 7) in Canonical basis
		// The coefficient array should have size elements, then we'll work with it in a larger domain
		coeffsSmall := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			coeffsSmall[i].SetRandom()
		}

		// Create polynomial in Canonical basis with degree size-1
		P0Small, err := NewPolynomial(coeffsSmall, WithID("x0"))
		if err != nil {
			t.Fatalf("Failed to create P0Small: %v", err)
		}

		// Convert to Lagrange basis in the larger domain
		d := fft.NewDomain(uint64(ratio * size))
		P0Small.ToBasis(d, Lagrange)

		// Create P0 and P1 as copies
		var P0, P1 Polynomial
		Copy(&P0, &P0Small)
		Copy(&P1, &P0Small)

		P0.SetShift(0)
		P0.ToLayout(Normal)

		P1.SetShift(0)
		P1.ToLayout(Normal)

		// P0 is in Lagrange shifted form, Normal layout
		t.Run("Lagrange, Normal layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < ratio*size; j++ {
					expected := P0.GetCoefficient((j + ratio*i) % (ratio * size))
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})

		P1.SetShift(0)
		P1.ToLayout(BitReversed)

		// P0 is in Lagrange shifted form, BitReversed layout
		t.Run("Lagrange, BitReversed layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < ratio*size; j++ {
					expected := P0.GetCoefficient((j + ratio*i) % (ratio * size))
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})

		P0.SetShift(0)
		P0.ToBasis(d, LagrangeShifted)
		P0.ToLayout(Normal)

		P1.SetShift(0)
		P1.ToBasis(d, LagrangeShifted)
		P1.ToLayout(Normal)

		// P0 is in Lagrange shifted form, Normal layout
		t.Run("Lagrange shifted, Normal layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < ratio*size; j++ {
					expected := P0.GetCoefficient((j + ratio*i) % (ratio * size))
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})

		P1.SetShift(0)
		P1.ToLayout(BitReversed)

		// P0 is in Lagrange shifted form, BitReversed layout
		t.Run("Lagrange shifted, BitReversed layout", func(t *testing.T) {
			for i := 0; i < size; i++ {
				P1.SetShift(i)
				for j := 0; j < ratio*size; j++ {
					expected := P0.GetCoefficient((j + ratio*i) % (ratio * size))
					res := P1.GetCoefficient(j)
					if !expected.Equal(&res) {
						t.Errorf("GetCoefficient() at index %d to be %s, got %s", j, expected.String(), res.String())
					}
				}
			}
		})
	}

}
