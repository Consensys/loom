package univariate

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
)

func TestBuildRatioSimple(t *testing.T) {
	// Test a simple case: Q1 = x0, Q2 = x1
	// Create two polynomials P1[0] and P2[0] in canonical form

	var one, two, three, four koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)
	three.SetUint64(3)
	four.SetUint64(4)

	// P1[0](x) = 1 + 2x + 3x² + 4x³
	coeffs1 := []koalabear.Element{one, two, three, four}
	P1_0, err := NewPolynomial(coeffs1, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P1[0]: %v", err)
	}

	// P2[0](x) = 4 + 3x + 2x² + x³ (reversed coefficients)
	coeffs2 := []koalabear.Element{four, three, two, one}
	P2_0, err := NewPolynomial(coeffs2, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P2[0]: %v", err)
	}

	// Q1 = x0, Q2 = x1
	C1 := sym.NewVar("x0")
	C2 := sym.NewVar("x1")

	P1 := []Polynomial{P1_0}
	P2 := []Polynomial{P2_0}

	// Build the ratio polynomial
	R, err := BuildRatio(C1, C2, P1, P2, WithOutputName("ratio"))
	if err != nil {
		t.Fatalf("BuildRatio failed: %v", err)
	}

	// Verify basic properties
	if R.EP == nil {
		t.Fatal("Ratio polynomial is nil")
	}

	// Check that R is in Lagrange form
	if R.EP.Basis != Lagrange {
		t.Errorf("Expected Lagrange basis, got %v", R.EP.Basis)
	}

	// Check that R[0] = 1
	r0 := R.GetCoefficient(0)
	if !r0.Equal(&one) {
		t.Errorf("Expected R[0] = 1, got %s", r0.String())
	}

	t.Logf("BuildRatio completed successfully")
}

func TestBuildRatioDifferentDegrees(t *testing.T) {
	// Test that BuildRatio returns error when polynomials have different degrees

	var one, two koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)

	// P1[0] has degree 1
	coeffs1 := []koalabear.Element{one, two}
	P1_0, _ := NewPolynomial(coeffs1, WithID("x0"))

	// P2[0] has degree 2
	coeffs2 := []koalabear.Element{one, two, one}
	P2_0, _ := NewPolynomial(coeffs2, WithID("x1"))

	C1 := sym.NewVar("x0")
	C2 := sym.NewVar("x1")

	P1 := []Polynomial{P1_0}
	P2 := []Polynomial{P2_0}

	// Should return error
	_, err := BuildRatio(C1, C2, P1, P2, WithOutputName("ratio"))
	if err == nil {
		t.Error("Expected error for different degree polynomials, got nil")
	}
}

func TestVanishing(t *testing.T) {

	// generate a list of polynomials P1 and P2, which are equal up to permutation
	// It means that:
	// * [P1[0] ∥ P1[1] ∥ .. ∥ P1[n]] = [ a0 a1 .. ∥ ... ∥ am-1 am ]
	// * [P2[0] ∥ P2[1] ∥ .. ∥ P2[n]] = [ b0 b1 .. ∥ ... ∥ bm-1 bm ]
	// are the same values, but permuted
	size := 16
	nbPolys := 2
	coeffs1 := make([][]koalabear.Element, nbPolys)
	coeffs2 := make([][]koalabear.Element, nbPolys)
	for i := 0; i < nbPolys; i++ {
		coeffs1[i] = make([]koalabear.Element, size)
		coeffs2[i] = make([]koalabear.Element, size)
		for j := 0; j < size; j++ {
			// Use deterministic values to avoid flaky tests
			coeffs1[i][j].SetUint64(uint64(i*size + j + 1))
		}
	}

	// Create P2, a permuted version of P1
	for i := 0; i < nbPolys; i++ {
		for j := 0; j < size; j++ {
			coeffs2[i][j].Set(&coeffs1[(i+3)%nbPolys][(j+2)%size])
		}
	}

	P1 := make([]Polynomial, nbPolys)
	P2 := make([]Polynomial, nbPolys)
	var err error
	for i := 0; i < nbPolys; i++ {
		P1[i], err = NewInterpolatedPolynomial(coeffs1[i], fmt.Sprintf("P1_%d", i))
		if err != nil {
			t.Fatal(err)
		}
		P2[i], err = NewInterpolatedPolynomial(coeffs2[i], fmt.Sprintf("P2_%d", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify that flat arrays are permutations
	flat1 := make([]uint64, nbPolys*size)
	flat2 := make([]uint64, nbPolys*size)
	for i := 0; i < nbPolys; i++ {
		for j := 0; j < size; j++ {
			flat1[i*size+j] = coeffs1[i][j].Uint64()
			flat2[i*size+j] = coeffs2[i][j].Uint64()
		}
	}
	// Check if products are equal
	var prod1, prod2 uint64 = 1, 1
	for i := 0; i < nbPolys*size; i++ {
		prod1 *= flat1[i]
		prod2 *= flat2[i]
	}
	if prod1 != prod2 {
		t.Logf("WARNING: Products don't match: %d vs %d", prod1, prod2)
	}

	var c koalabear.Element
	c.SetRandom()
	C1 := sym.NewVar(P1[0].ID).Sub(sym.NewConst(c)) // P1[0]-c
	C2 := sym.NewVar(P2[0].ID).Sub(sym.NewConst(c)) // P2[0]-c
	for i := 1; i < nbPolys; i++ {
		_C1 := sym.NewVar(P1[i].ID).Sub(sym.NewConst(c))
		_C2 := sym.NewVar(P2[i].ID).Sub(sym.NewConst(c))
		C1 = C1.Mul(_C1)
		C2 = C2.Mul(_C2)
	}

	// at this stage
	// * C1 = (P1[0]-c)*..*(P1[i]-c)
	// * C2 = (P2[0]-c)*..*(P2[i]-c)
	R, err := BuildRatio(C1, C2, P1, P2)
	if err != nil {
		t.Fatal(err)
	}

	// Create RS as a circularly shifted version of R, without reallocating the coefficients
	var RS Polynomial
	ShallowCopy(&RS, &R)
	RS.ID = fmt.Sprintf("%s_shifted", R.ID)
	RS.SetShift(1)

	// R is built such that (m:=nbPolys-1, n := size)
	// * R[0]=1
	// * R[1]= (P2[0][0]-c)*..*(P2[m][0]-c) / (P1[0][0]-c)*..*(P1[m][0]-c)
	// * R[2] = R[1]* [ P2[0][1]-c)*..*(P2[m][1]-c) / (P1[0][1]-c)*..*(P1[m][1]-c) ]
	// * ...
	// * R[n-1] = Π_{i<n-1} [ P2[0][i]-c)*..*(P2[m][i]-c) / (P1[0][i]-c)*..*(P1[m][i]-c) ]
	// Since Π_{i<n} [ P2[0][i]-c)*..*(P2[m][i]-c) / (P1[0][i]-c)*..*(P1[m][i]-c) ] = 1, we have:
	// R[n-1]*[ P2[0][n-1]-c)*..*(P2[m][n-1]-c) / (P1[0][n-1]-c)*..*(P1[m][n-1]-c) ] = 1
	// So if R is expressed in canonical basis, in the whole domain X^n-1 the following relation holds:
	// R(wX)(P2[0](X)-c)*..*(P2[m](X)-c) - R(X)*(P1[0](X)-c)*..*(P1[m](X)-c) = 0.
	// We are going to test this property.
	C := sym.NewVar(RS.ID).Mul(C2).Sub(sym.NewVar(R.ID).Mul(C1)) // R(wX)(P2[0](X)-c)*..*(P2[m](X)-c) - R(X)*(P1[0](X)-c)*..*(P1[m](X)-c)
	var wPowI koalabear.Element
	wPowI.SetOne()
	w, err := koalabear.Generator(uint64(size))
	if err != nil {
		t.Fatal(err)
	}

	// Manually compute what R[1] should be
	// R[1] = R[0] * C1[0] / C2[0]
	// where C1[0] = (P1[0][0]-c)*(P1[1][0]-c) and C2[0] = (P2[0][0]-c)*(P2[1][0]-c)
	p1_0_0 := P1[0].GetCoefficient(0)
	p1_1_0 := P1[1].GetCoefficient(0)
	p2_0_0 := P2[0].GetCoefficient(0)
	p2_1_0 := P2[1].GetCoefficient(0)

	var c1_0, c2_0, temp koalabear.Element
	temp.Sub(&p1_0_0, &c)
	c1_0.Set(&temp)
	temp.Sub(&p1_1_0, &c)
	c1_0.Mul(&c1_0, &temp)

	temp.Sub(&p2_0_0, &c)
	c2_0.Set(&temp)
	temp.Sub(&p2_1_0, &c)
	c2_0.Mul(&c2_0, &temp)

	var expectedR1 koalabear.Element
	expectedR1.Inverse(&c2_0)
	expectedR1.Mul(&expectedR1, &c1_0) // expectedR1 = C1[0]/C2[0]
	// R[1] = R[0] * expectedR1 = 1 * expectedR1

	t.Logf("  Expected R[1] = C1[0]/C2[0] = %s", expectedR1.String())
	t.Logf("  C1[0] = (P1[0][0]-c)*(P1[1][0]-c) = %s", c1_0.String())
	t.Logf("  C2[0] = (P2[0][0]-c)*(P2[1][0]-c) = %s", c2_0.String())
	t.Logf("  P1[0][0]=%s, P1[1][0]=%s, P2[0][0]=%s, P2[1][0]=%s",
		p1_0_0.String(), p1_1_0.String(), p2_0_0.String(), p2_1_0.String())

	T := make([]Polynomial, 2*nbPolys+2)
	copy(T, P1)
	copy(T[nbPolys:], P2)
	T[2*nbPolys] = R
	T[2*nbPolys+1] = RS
	varindex := make(sym.VarIndex)
	d := fft.NewDomain(uint64(size))
	for i := 0; i < len(T); i++ {
		varindex[T[i].ID] = i
		T[i].ToBasis(d, Canonical)
	}
	CHorner := sym.ToHorner(sym.Convert(C, varindex, len(T)))
	xi := make([]koalabear.Element, len(T))

	// TODO this is the same test as BruteForceChecker in ../cs/, should refactor
	for j := 0; j < size; j++ {
		for i := 0; i < len(T); i++ {
			xi[varindex[T[i].ID]], err = T[i].Evaluate(wPowI)
			if err != nil {
				t.Fatal(err)
			}
		}
		z := CHorner.Eval(xi)
		if !z.IsZero() {
			if j == 0 {
				// Debug first failure
				t.Logf("At position 0 (evaluating at omega^0 = 1):")
				t.Logf("  R(1)=%s, RS(1)=%s", xi[varindex[R.ID]].String(), xi[varindex[RS.ID]].String())

				// Manually compute what the constraint should be
				p1_0_val := xi[varindex[P1[0].ID]]
				p1_1_val := xi[varindex[P1[1].ID]]
				p2_0_val := xi[varindex[P2[0].ID]]
				p2_1_val := xi[varindex[P2[1].ID]]
				t.Logf("  P1[0](1)=%s, P1[1](1)=%s, P2[0](1)=%s, P2[1](1)=%s",
					p1_0_val.String(), p1_1_val.String(), p2_0_val.String(), p2_1_val.String())

				var c1_eval, c2_eval, temp koalabear.Element
				temp.Sub(&p1_0_val, &c)
				c1_eval.Set(&temp)
				temp.Sub(&p1_1_val, &c)
				c1_eval.Mul(&c1_eval, &temp)

				temp.Sub(&p2_0_val, &c)
				c2_eval.Set(&temp)
				temp.Sub(&p2_1_val, &c)
				c2_eval.Mul(&c2_eval, &temp)

				t.Logf("  C1(1) = %s, C2(1) = %s", c1_eval.String(), c2_eval.String())

				var expected koalabear.Element
				expected.Mul(&xi[varindex[RS.ID]], &c2_eval)
				var actual koalabear.Element
				actual.Mul(&xi[varindex[R.ID]], &c1_eval)
				t.Logf("  RS(1)*C2(1) = %s", expected.String())
				t.Logf("  R(1)*C1(1) = %s", actual.String())
				t.Logf("  Constraint value: %s", z.String())
			}
			t.Errorf("expected 0, got: %s\n", z.String())
		}
		wPowI.Mul(&wPowI, &w)
	}
}
