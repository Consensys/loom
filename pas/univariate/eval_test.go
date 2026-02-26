package univariate

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
)

// makeLagrangePoly builds a polynomial in Lagrange basis from raw uint64 evaluations.
func makeLagrangePoly(t *testing.T, id string, vals ...uint64) *Polynomial {
	t.Helper()
	coeffs := make([]koalabear.Element, len(vals))
	for i, v := range vals {
		coeffs[i].SetUint64(v)
	}
	p, err := NewPolynomial(coeffs, WithBasis(Lagrange), WithLayout(Normal))
	if err != nil {
		t.Fatalf("makeLagrangePoly(%s): %v", id, err)
	}
	return &p
}

// checkPointwise asserts R[i] == expected[i] for each domain point.
func checkPointwise(t *testing.T, R *Polynomial, expected []koalabear.Element) {
	t.Helper()
	n := len(expected)
	for i := 0; i < n; i++ {
		r := R.GetCoefficient(i)
		if !r.Equal(&expected[i]) {
			t.Errorf("point %d: got %s, want %s", i, r.String(), expected[i].String())
		}
	}
}

func TestEvalPointWise(t *testing.T) {

	t.Run("NonHomogeneous_x0sq_plus_x1", func(t *testing.T) {
		// Q = x0^2 + x1
		// P0(ωⁱ) = i+1, P1(ωⁱ) = 2*(i+1)
		// R(ωⁱ) = (i+1)^2 + 2*(i+1)
		size := 8
		var one, two koalabear.Element
		one.SetUint64(1)
		two.SetUint64(2)

		coeffs0 := make([]koalabear.Element, size)
		coeffs1 := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			coeffs0[i].SetUint64(uint64(i + 1))
			coeffs1[i].SetUint64(uint64(2 * (i + 1)))
		}

		P0, err := NewPolynomial(coeffs0, WithBasis(Lagrange))
		if err != nil {
			t.Fatalf("Failed to create P0: %v", err)
		}

		P1, err := NewPolynomial(coeffs1, WithBasis(Lagrange))
		if err != nil {
			t.Fatalf("Failed to create P1: %v", err)
		}

		_ = one
		_ = two

		C := sym.NewVar("x0").Pow(2).Add(sym.NewVar("x1"))
		P := map[string]*Polynomial{"x0": &P0, "x1": &P1}

		R, err := EvalPointWise(P, C, size)
		if err != nil {
			t.Fatalf("EvalPointWise failed: %v", err)
		}

		if len(R.EP.Coefficients) != size {
			t.Fatalf("R is of size %d, expected %d", len(R.EP.Coefficients), size)
		}

		// verify entry per entry: R[i] == P0[i]^2 + P1[i]
		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c0 := P0.GetCoefficient(i)
			c1 := P1.GetCoefficient(i)
			expected[i].Square(&c0).Add(&expected[i], &c1)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("Sub_x0_minus_x1", func(t *testing.T) {
		// Q = x0 - x1
		// R[i] = P0[i] - P1[i]
		size := 8
		P0 := makeLagrangePoly(t, "x0", 10, 20, 30, 40, 50, 60, 70, 80)
		P1 := makeLagrangePoly(t, "x1", 1, 2, 3, 4, 5, 6, 7, 8)

		C := sym.NewVar("x0").Sub(sym.NewVar("x1"))
		Pi := map[string]*Polynomial{"x0": P0, "x1": P1}

		R, err := EvalPointWise(Pi, C, size)
		if err != nil {
			t.Fatalf("EvalPointWise failed: %v", err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c0 := P0.GetCoefficient(i)
			c1 := P1.GetCoefficient(i)
			expected[i].Sub(&c0, &c1)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("Mul_x0_times_x1", func(t *testing.T) {
		// Q = x0 * x1
		// R[i] = P0[i] * P1[i]
		size := 8
		P0 := makeLagrangePoly(t, "x0", 2, 4, 6, 8, 10, 12, 14, 16)
		P1 := makeLagrangePoly(t, "x1", 3, 3, 3, 3, 3, 3, 3, 3)

		C := sym.NewVar("x0").Mul(sym.NewVar("x1"))
		Pi := map[string]*Polynomial{"x0": P0, "x1": P1}

		R, err := EvalPointWise(Pi, C, size)
		if err != nil {
			t.Fatalf("EvalPointWise failed: %v", err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c0 := P0.GetCoefficient(i)
			c1 := P1.GetCoefficient(i)
			expected[i].Mul(&c0, &c1)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("Combined_x0_mul_x1_add_x2_sub_x3", func(t *testing.T) {
		// Q = x0*x1 + x2 - x3
		// R[i] = P0[i]*P1[i] + P2[i] - P3[i]
		size := 8
		P0 := makeLagrangePoly(t, "x0", 1, 2, 3, 4, 5, 6, 7, 8)
		P1 := makeLagrangePoly(t, "x1", 2, 2, 2, 2, 2, 2, 2, 2)
		P2 := makeLagrangePoly(t, "x2", 10, 10, 10, 10, 10, 10, 10, 10)
		P3 := makeLagrangePoly(t, "x3", 1, 1, 1, 1, 1, 1, 1, 1)

		C := sym.NewVar("x0").Mul(sym.NewVar("x1")).
			Add(sym.NewVar("x2")).
			Sub(sym.NewVar("x3"))
		Pi := map[string]*Polynomial{"x0": P0, "x1": P1, "x2": P2, "x3": P3}

		R, err := EvalPointWise(Pi, C, size)
		if err != nil {
			t.Fatalf("EvalPointWise failed: %v", err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c0 := P0.GetCoefficient(i)
			c1 := P1.GetCoefficient(i)
			c2 := P2.GetCoefficient(i)
			c3 := P3.GetCoefficient(i)
			expected[i].Mul(&c0, &c1)
			expected[i].Add(&expected[i], &c2)
			expected[i].Sub(&expected[i], &c3)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("Mul_then_sub_same_poly", func(t *testing.T) {
		// Q = x0*x0 - x0 = x0*(x0-1)
		// R[i] = P0[i]^2 - P0[i]
		size := 8
		P0 := makeLagrangePoly(t, "x0", 0, 1, 2, 3, 5, 7, 11, 13)

		C := sym.NewVar("x0").Mul(sym.NewVar("x0")).Sub(sym.NewVar("x0"))
		Pi := map[string]*Polynomial{"x0": P0}

		R, err := EvalPointWise(Pi, C, size)
		if err != nil {
			t.Fatalf("EvalPointWise failed: %v", err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c := P0.GetCoefficient(i)
			expected[i].Square(&c)
			expected[i].Sub(&expected[i], &c)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("Sub_and_mul_three_terms", func(t *testing.T) {
		// Q = (x0 - x1) * x2
		// R[i] = (P0[i] - P1[i]) * P2[i]
		size := 8
		P0 := makeLagrangePoly(t, "x0", 10, 9, 8, 7, 6, 5, 4, 3)
		P1 := makeLagrangePoly(t, "x1", 1, 2, 3, 4, 5, 6, 7, 8)
		P2 := makeLagrangePoly(t, "x2", 2, 2, 2, 2, 2, 2, 2, 2)

		C := sym.NewVar("x0").Sub(sym.NewVar("x1")).Mul(sym.NewVar("x2"))
		Pi := map[string]*Polynomial{"x0": P0, "x1": P1, "x2": P2}

		R, err := EvalPointWise(Pi, C, size)
		if err != nil {
			t.Fatalf("EvalPointWise failed: %v", err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c0 := P0.GetCoefficient(i)
			c1 := P1.GetCoefficient(i)
			c2 := P2.GetCoefficient(i)
			expected[i].Sub(&c0, &c1)
			expected[i].Mul(&expected[i], &c2)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("ShiftedZero", func(t *testing.T) {
		// Q = x0 - x1 where P1 is P0 shifted by 1:
		// P1[i] = P0[(i+1)%n], so GetCoefficient(i) on P1 (shift=1) == P0[i].
		// The composed polynomial is the zero polynomial.
		size := 8
		evals0 := make([]koalabear.Element, size)
		evals1 := make([]koalabear.Element, size)
		for i := range evals0 {
			evals0[i].SetRandom()
			evals1[(i+1)%size].Set(&evals0[i])
		}

		P0, err := NewInterpolatedPolynomial(evals0, "x0")
		if err != nil {
			t.Fatal(err)
		}
		P1, err := NewInterpolatedPolynomial(evals1, "x1", WithShift(1))
		if err != nil {
			t.Fatal(err)
		}

		C := sym.NewVar("x0").Sub(sym.NewVar("x1"))
		Pi := map[string]*Polynomial{"x0": &P0, "x1": &P1}

		R, err := EvalPointWise(Pi, C, size)
		if err != nil {
			t.Fatal(err)
		}

		// Every evaluation should be zero
		var zero koalabear.Element
		expected := make([]koalabear.Element, size)
		for i := range expected {
			expected[i] = zero
		}
		checkPointwise(t, &R, expected)
	})
}

func TestDivPointWise(t *testing.T) {

	t.Run("Simple", func(t *testing.T) {
		// R[i] = P1[i] / P2[i]
		// P1 = [2, 4, 6, 8, 10, 12, 14, 16], P2 = [2, 2, 2, 2, 2, 2, 2, 2]
		// R = [1, 2, 3, 4, 5, 6, 7, 8]
		size := 8
		P1 := makeLagrangePoly(t, "P1", 2, 4, 6, 8, 10, 12, 14, 16)
		P2 := makeLagrangePoly(t, "P2", 2, 2, 2, 2, 2, 2, 2, 2)

		R, err := DivPointWise(P1, P2, size)
		if err != nil {
			t.Fatal(err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c1 := P1.GetCoefficient(i)
			c2 := P2.GetCoefficient(i)
			expected[i].Div(&c1, &c2)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("IdentityDenominator", func(t *testing.T) {
		// P2 = [1, 1, ...] → R = P1
		size := 8
		P1 := makeLagrangePoly(t, "P1", 3, 7, 11, 5, 2, 9, 6, 4)
		P2 := makeLagrangePoly(t, "P2", 1, 1, 1, 1, 1, 1, 1, 1)

		R, err := DivPointWise(P1, P2, size)
		if err != nil {
			t.Fatal(err)
		}

		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			expected[i] = P1.GetCoefficient(i)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("EqualOperands", func(t *testing.T) {
		// P1 == P2 → R = [1, 1, 1, ...]
		size := 8
		P1 := makeLagrangePoly(t, "P1", 5, 3, 9, 2, 7, 11, 4, 6)
		P2 := makeLagrangePoly(t, "P2", 5, 3, 9, 2, 7, 11, 4, 6)

		R, err := DivPointWise(P1, P2, size)
		if err != nil {
			t.Fatal(err)
		}

		var one koalabear.Element
		one.SetOne()
		expected := make([]koalabear.Element, size)
		for i := range expected {
			expected[i] = one
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("DivisionByZero", func(t *testing.T) {
		// P2 has a zero entry → should return an error
		size := 8
		P1 := makeLagrangePoly(t, "P1", 1, 2, 3, 4, 5, 6, 7, 8)
		P2 := makeLagrangePoly(t, "P2", 1, 0, 1, 1, 1, 1, 1, 1) // zero at index 1

		_, err := DivPointWise(P1, P2, size)
		if err == nil {
			t.Fatal("expected error for division by zero, got nil")
		}
	})

	t.Run("ShiftedNumerator", func(t *testing.T) {
		// P1 is shifted by 1: P1.GetCoefficient(i) = evals[(i+1)%n]
		// R[i] = P1[i] / P2[i] = evals[(i+1)%n] / P2[i]
		size := 8
		evals := make([]koalabear.Element, size)
		for i := range evals {
			evals[i].SetUint64(uint64(i + 1))
		}

		// build backing storage for P1 shifted: store[(i+1)%n] = evals[i]
		backing := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			backing[(i+1)%size].Set(&evals[i])
		}

		P1, err := NewInterpolatedPolynomial(backing, "P1", WithShift(1))
		if err != nil {
			t.Fatal(err)
		}

		P2 := makeLagrangePoly(t, "P2", 1, 1, 1, 1, 1, 1, 1, 1)

		R, err := DivPointWise(&P1, P2, size)
		if err != nil {
			t.Fatal(err)
		}

		// R[i] = P1.GetCoefficient(i) / 1 = evals[i]
		expected := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			expected[i].Set(&evals[i])
		}
		checkPointwise(t, &R, expected)
	})
}

func TestBuildGrandProduct(t *testing.T) {

	t.Run("IdentityRatio", func(t *testing.T) {
		// E[0] = E[1] = x, P[0] = P[1] = some polynomial
		// ratio[i] = P[i]/P[i] = 1, so R = [1, 1, ..., 1]
		size := 8
		P := makeLagrangePoly(t, "x", 2, 3, 4, 5, 6, 7, 8, 9)
		Pi := [2]map[string]*Polynomial{
			{"x": P},
			{"x": P},
		}
		E0 := sym.NewVar("x")
		E1 := sym.NewVar("x")

		R, err := BuildGrandProduct(Pi, [2]sym.Expr{E0, E1}, size)
		if err != nil {
			t.Fatal(err)
		}

		var one koalabear.Element
		one.SetOne()
		expected := make([]koalabear.Element, size)
		for i := range expected {
			expected[i] = one
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("SimpleRecurrence", func(t *testing.T) {
		// E[0] = x (numerator), E[1] = 1 (denominator, constant polynomial)
		// ratio[i] = P[i] / 1 = P[i]
		// R[0]=1, R[i] = R[i-1]*P[i-1]
		size := 8
		P := makeLagrangePoly(t, "x", 2, 3, 4, 5, 6, 7, 8, 9)
		var one koalabear.Element
		one.SetOne()
		constOne, err := NewConstantPolynomial(one)
		if err != nil {
			t.Fatal(err)
		}
		Pi := [2]map[string]*Polynomial{
			{"x": P},
			{"one": &constOne},
		}
		E0 := sym.NewVar("x")
		E1 := sym.NewVar("one")

		R, err := BuildGrandProduct(Pi, [2]sym.Expr{E0, E1}, size)
		if err != nil {
			t.Fatal(err)
		}

		// expected: same as AccumulateProducts(P)
		expected := make([]koalabear.Element, size)
		expected[0].SetOne()
		for i := 1; i < size; i++ {
			pi := P.GetCoefficient(i - 1)
			expected[i].Mul(&expected[i-1], &pi)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("FirstEntryAlwaysOne", func(t *testing.T) {
		// R[0] must always be 1 regardless of P
		size := 8
		P0 := makeLagrangePoly(t, "x", 7, 3, 11, 5, 2, 9, 4, 6)
		P1 := makeLagrangePoly(t, "y", 1, 2, 3, 4, 5, 6, 7, 8)
		Pi := [2]map[string]*Polynomial{
			{"x": P0},
			{"y": P1},
		}
		E0 := sym.NewVar("x")
		E1 := sym.NewVar("y")

		R, err := BuildGrandProduct(Pi, [2]sym.Expr{E0, E1}, size)
		if err != nil {
			t.Fatal(err)
		}

		got := R.GetCoefficient(0)
		var one koalabear.Element
		one.SetOne()
		if !got.Equal(&one) {
			t.Errorf("R[0]: got %s, want 1", got.String())
		}
	})

	t.Run("Recurrence_check", func(t *testing.T) {
		// Verify R[i+1] = R[i] * E0(P0[i]) / E1(P1[i]) for every i
		size := 8
		P0 := makeLagrangePoly(t, "x", 6, 10, 3, 15, 2, 8, 5, 9)
		P1 := makeLagrangePoly(t, "y", 2, 5, 1, 3, 2, 4, 1, 3)
		Pi := [2]map[string]*Polynomial{
			{"x": P0},
			{"y": P1},
		}
		E0 := sym.NewVar("x")
		E1 := sym.NewVar("y")

		R, err := BuildGrandProduct(Pi, [2]sym.Expr{E0, E1}, size)
		if err != nil {
			t.Fatal(err)
		}

		// Verify R[0] = 1
		got0 := R.GetCoefficient(0)
		var one koalabear.Element
		one.SetOne()
		if !got0.Equal(&one) {
			t.Errorf("R[0]: got %s, want 1", got0.String())
		}

		// Verify R[i+1] = R[i] * P0[i] / P1[i] for i in [0, n-2]
		for i := 0; i < size-1; i++ {
			ri := R.GetCoefficient(i)
			ri1 := R.GetCoefficient(i + 1)
			p0i := P0.GetCoefficient(i)
			p1i := P1.GetCoefficient(i)

			// expected = R[i] * p0i / p1i
			var expected koalabear.Element
			expected.Mul(&ri, &p0i)
			expected.Div(&expected, &p1i)

			if !ri1.Equal(&expected) {
				t.Errorf("R[%d]: got %s, want %s", i+1, ri1.String(), expected.String())
			}
		}
	})

	t.Run("DenominatorZero_error", func(t *testing.T) {
		// E[1] = y, P1 has a zero entry → should propagate error
		size := 8
		P0 := makeLagrangePoly(t, "x", 1, 2, 3, 4, 5, 6, 7, 8)
		P1 := makeLagrangePoly(t, "y", 1, 0, 1, 1, 1, 1, 1, 1) // zero at index 1
		Pi := [2]map[string]*Polynomial{
			{"x": P0},
			{"y": P1},
		}
		E0 := sym.NewVar("x")
		E1 := sym.NewVar("y")

		_, err := BuildGrandProduct(Pi, [2]sym.Expr{E0, E1}, size)
		if err == nil {
			t.Fatal("expected error for zero denominator, got nil")
		}
	})
}

func TestAccumulateProducts(t *testing.T) {

	t.Run("Simple", func(t *testing.T) {
		// P = [2, 3, 4, 5, 1, 1, 1, 1]
		// R[0]=1, R[1]=2, R[2]=6, R[3]=24, R[4]=120, R[5]=120, R[6]=120, R[7]=120
		size := 8
		P := makeLagrangePoly(t, "P", 2, 3, 4, 5, 1, 1, 1, 1)

		R, err := AccumulateProducts(P, size)
		if err != nil {
			t.Fatal(err)
		}

		expected := make([]koalabear.Element, size)
		expected[0].SetOne()
		for i := 1; i < size; i++ {
			pi := P.GetCoefficient(i - 1)
			expected[i].Mul(&expected[i-1], &pi)
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("AllOnes", func(t *testing.T) {
		// P = [1, 1, ...] → R = [1, 1, ...]
		size := 8
		P := makeLagrangePoly(t, "P", 1, 1, 1, 1, 1, 1, 1, 1)

		R, err := AccumulateProducts(P, size)
		if err != nil {
			t.Fatal(err)
		}

		var one koalabear.Element
		one.SetOne()
		expected := make([]koalabear.Element, size)
		for i := range expected {
			expected[i] = one
		}
		checkPointwise(t, &R, expected)
	})

	t.Run("FirstEntryAlwaysOne", func(t *testing.T) {
		// R[0] must be 1 regardless of P
		size := 8
		P := makeLagrangePoly(t, "P", 7, 3, 11, 5, 2, 9, 4, 6)

		R, err := AccumulateProducts(P, size)
		if err != nil {
			t.Fatal(err)
		}

		got := R.GetCoefficient(0)
		var one koalabear.Element
		one.SetOne()
		if !got.Equal(&one) {
			t.Errorf("R[0]: got %s, want 1", got.String())
		}
	})

	t.Run("GrandProductInLastEntry", func(t *testing.T) {
		// R[n-1] = P[0]*P[1]*...*P[n-2]
		// With P = [2, 3, 4, 5, 6, 7, 8, 9], R[7] = 2*3*4*5*6*7*8 = 40320
		size := 8
		P := makeLagrangePoly(t, "P", 2, 3, 4, 5, 6, 7, 8, 9)

		R, err := AccumulateProducts(P, size)
		if err != nil {
			t.Fatal(err)
		}

		// compute expected grand product of P[0..n-2]
		var expected koalabear.Element
		expected.SetOne()
		for i := 0; i < size-1; i++ {
			pi := P.GetCoefficient(i)
			expected.Mul(&expected, &pi)
		}
		got := R.GetCoefficient(size - 1)
		if !got.Equal(&expected) {
			t.Errorf("R[%d]: got %s, want %s", size-1, got.String(), expected.String())
		}
	})
}

// verifyQuotientIdentity checks E(Pi(x)) == Q(x)*(x^N-1) at a random point x.
func verifyQuotientIdentity(t *testing.T, Pi map[string]*Polynomial, E sym.Expr, Q Polynomial, N int) {
	t.Helper()

	// Build Horner form of E
	varindex := make(sym.VarIndex)
	leaves := sym.RemoveDuplicates(E.Leaves())
	for i, l := range leaves {
		varindex[l] = i
	}
	EHorner := sym.ToHorner(sym.Convert(E, varindex, len(leaves)))

	// Pick a random evaluation point
	var x koalabear.Element
	x.SetRandom()

	// Evaluate each Pi at x (convert to Canonical using its own domain)
	piAtX := make([]koalabear.Element, len(leaves))
	for name, idx := range varindex {
		p := Pi[name]
		var pCopy Polynomial
		pCopy.EP = &EPolynomial{}
		Copy(&pCopy, p)
		if !pCopy.IsConstant() && pCopy.EP.Basis != Canonical {
			d := fft.NewDomain(uint64(len(pCopy.EP.Coefficients)))
			if err := pCopy.ToBasis(d, Canonical); err != nil {
				t.Fatalf("failed to convert Pi[%s] to Canonical: %v", name, err)
			}
		}
		val, err := pCopy.Evaluate(x)
		if err != nil {
			t.Fatalf("failed to evaluate Pi[%s] at x: %v", name, err)
		}
		piAtX[idx] = val
	}

	// E(Pi(x))
	numeratorAtX := EHorner.Eval(piAtX)

	// Q(x)
	qAtX, err := Q.Evaluate(x)
	if err != nil {
		t.Fatalf("failed to evaluate quotient at x: %v", err)
	}

	// x^N - 1
	var xN, one koalabear.Element
	one.SetOne()
	xN.Exp(x, big.NewInt(int64(N)))
	xN.Sub(&xN, &one)

	// Check E(Pi(x)) == Q(x) * (x^N - 1)
	var rhs koalabear.Element
	rhs.Mul(&qAtX, &xN)
	if !numeratorAtX.Equal(&rhs) {
		t.Errorf("quotient identity failed: E(Pi(x)) = %s, Q(x)*(x^N-1) = %s",
			numeratorAtX.String(), rhs.String())
	}
}

func TestComputeQuotient(t *testing.T) {

	t.Run("TrivialZero", func(t *testing.T) {
		// E = f - g with Pi["f"] == Pi["g"] → E(Pi) = 0 → quotient = 0
		size := 8
		P := makeLagrangePoly(t, "f", 1, 2, 3, 4, 5, 6, 7, 8)
		Pi := map[string]*Polynomial{"f": P, "g": P}
		E := sym.NewVar("f").Sub(sym.NewVar("g"))

		Q, err := ComputeQuotient(Pi, E, size, WithOutputBasis(Canonical))
		if err != nil {
			t.Fatal(err)
		}

		for i, c := range Q.EP.Coefficients {
			if !c.IsZero() {
				t.Errorf("quotient[%d] = %s, want 0", i, c.String())
			}
		}
	})

	t.Run("QuadraticRangeCheck", func(t *testing.T) {
		// E = f*(f-1): zero when f ∈ {0,1}
		// P values [0,1,0,1] at ω^0,ω^1,ω^2,ω^3 → E(P[i]) = 0 for all i
		size := 4
		var one koalabear.Element
		one.SetOne()
		P := makeLagrangePoly(t, "f", 0, 1, 0, 1)
		Pi := map[string]*Polynomial{"f": P}

		var minusOne koalabear.Element
		minusOne.Neg(&one)
		E := sym.NewVar("f").Mul(sym.NewVar("f").Add(sym.NewConst(minusOne)))

		Q, err := ComputeQuotient(Pi, E, size, WithOutputBasis(Canonical))
		if err != nil {
			t.Fatal(err)
		}

		verifyQuotientIdentity(t, Pi, E, Q, size)
	})

	t.Run("ThreeVariable", func(t *testing.T) {
		// E = x0^3 + x1*x2 + x3, with x3 = -(x0^3 + x1*x2) so E(Pi) = 0 mod X^N-1
		size := 16

		c0 := make([]koalabear.Element, size)
		c1 := make([]koalabear.Element, size)
		c2 := make([]koalabear.Element, size)
		c3 := make([]koalabear.Element, size)
		for i := 0; i < size; i++ {
			c0[i].SetRandom()
			c1[i].SetRandom()
			c2[i].SetRandom()
		}

		// x3[i] = -(x0[i]^3 + x1[i]*x2[i])
		varindex3 := sym.VarIndex{"x0": 0, "x1": 1, "x2": 2}
		trunc := sym.NewVar("x0").Pow(3).Add(sym.NewVar("x1").Mul(sym.NewVar("x2")))
		truncH := sym.ToHorner(sym.Convert(trunc, varindex3, 3))
		for i := 0; i < size; i++ {
			c3[i] = truncH.Eval([]koalabear.Element{c0[i], c1[i], c2[i]})
			c3[i].Neg(&c3[i])
		}

		P0, _ := NewPolynomial(c0, WithBasis(Lagrange))
		P1, _ := NewPolynomial(c1, WithBasis(Lagrange))
		P2, _ := NewPolynomial(c2, WithBasis(Lagrange))
		P3, _ := NewPolynomial(c3, WithBasis(Lagrange))
		Pi := map[string]*Polynomial{"x0": &P0, "x1": &P1, "x2": &P2, "x3": &P3}

		E := sym.NewVar("x0").Pow(3).
			Add(sym.NewVar("x1").Mul(sym.NewVar("x2"))).
			Add(sym.NewVar("x3"))

		Q, err := ComputeQuotient(Pi, E, size, WithOutputBasis(Canonical))
		if err != nil {
			t.Fatal(err)
		}

		verifyQuotientIdentity(t, Pi, E, Q, size)
	})

	t.Run("ConstantPiInConstraint", func(t *testing.T) {
		// E = f - gamma where gamma is a constant polynomial representing a challenge value
		// P values = [3, 3, 3, 3, ...] and gamma = 3 → E(Pi) = 0 → quotient = 0
		size := 8
		var three koalabear.Element
		three.SetUint64(3)

		P := makeLagrangePoly(t, "f", 3, 3, 3, 3, 3, 3, 3, 3)
		gamma, err := NewConstantPolynomial(three)
		if err != nil {
			t.Fatal(err)
		}
		Pi := map[string]*Polynomial{"f": P, "gamma": &gamma}
		E := sym.NewVar("f").Sub(sym.NewVar("gamma"))

		Q, err := ComputeQuotient(Pi, E, size, WithOutputBasis(Canonical))
		if err != nil {
			t.Fatal(err)
		}

		for i, c := range Q.EP.Coefficients {
			if !c.IsZero() {
				t.Errorf("quotient[%d] = %s, want 0", i, c.String())
			}
		}
	})
}
