package univariate

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
)

func TestComputeSymNonHomogeneous(t *testing.T) {
	// Test with non-homogeneous Q = x0^2 + x1 (degrees 2 and 1)
	// If P0(x) = x and P1(x) = 2x, then Q(P0, P1) = x^2 + 2x

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

	// Create non-homogeneous Q = x0^2 + x1
	Q := sym.NewVar("x0").Pow(2).Add(sym.NewVar("x1"))

	// Create varindex
	varindex := sym.VarIndex{
		"x0": 0,
		"x1": 1,
	}

	// Convert to Horner
	QM := sym.Convert(Q, varindex, 2)
	QHorner := sym.ToHorner(QM)

	// Compute Q(P0, P1) = P0^2 + P1 = x^2 + 2x
	Pi := []Polynomial{P0, P1}
	result, err := ComputeSym(Pi, Q, WithOutputName("result"))
	if err != nil {
		t.Fatalf("ComputeSym failed: %v", err)
	}

	// Verify by evaluating at a test point
	var x koalabear.Element
	x.SetUint64(5) // x = 5

	resultEval, err := result.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	// Expected: x^2 + 2x = 25 + 10 = 35
	var expected koalabear.Element
	expected.SetUint64(35)

	if !resultEval.Equal(&expected) {
		t.Errorf("Expected %s, got %s", expected.String(), resultEval.String())
	}

	// Also verify using direct evaluation
	P0Eval, _ := P0.Evaluate(x)
	P1Eval, _ := P1.Evaluate(x)
	vals := []koalabear.Element{P0Eval, P1Eval}
	QEval := QHorner.Eval(vals)

	if !resultEval.Equal(&QEval) {
		t.Errorf("Mismatch: result(%s) = %s, but Q(P0(%s), P1(%s)) = %s",
			x.String(), resultEval.String(), x.String(), x.String(), QEval.String())
	}
}

func TestComputeSymMixedDegrees(t *testing.T) {
	// Test with Q = x0^3 + x1^2 + x2 + 1 (non-homogeneous with constant)
	// All Pi have degree 1

	var one, two, three koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)
	three.SetUint64(3)

	// Create P0(x) = x
	coeffs0 := make([]koalabear.Element, 8)
	coeffs0[1] = one
	P0, err := NewPolynomial(coeffs0, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1(x) = 2x
	coeffs1 := make([]koalabear.Element, 8)
	coeffs1[1] = two
	P1, err := NewPolynomial(coeffs1, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Create P2(x) = 3x
	coeffs2 := make([]koalabear.Element, 8)
	coeffs2[1] = three
	P2, err := NewPolynomial(coeffs2, WithID("x2"))
	if err != nil {
		t.Fatalf("Failed to create P2: %v", err)
	}

	// Create Q = x0^3 + x1^2 + x2 + 1
	Q := sym.NewVar("x0").Pow(3).Add(sym.NewVar("x1").Pow(2)).Add(sym.NewVar("x2")).Add(sym.NewConst(one))

	// Create varindex
	varindex := sym.VarIndex{
		"x0": 0,
		"x1": 1,
		"x2": 2,
	}

	// Convert to Horner
	QM := sym.Convert(Q, varindex, 3)
	QHorner := sym.ToHorner(QM)

	// Compute Q(P0, P1, P2)
	Pi := []Polynomial{P0, P1, P2}
	result, err := ComputeSym(Pi, Q, WithOutputName("result"))
	if err != nil {
		t.Fatalf("ComputeSym failed: %v", err)
	}

	// Verify at x = 2
	// P0(2) = 2, P1(2) = 4, P2(2) = 6
	// Q(2, 4, 6) = 8 + 16 + 6 + 1 = 31
	var x koalabear.Element
	x.SetUint64(2)

	resultEval, err := result.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	// Verify using direct evaluation
	P0Eval, _ := P0.Evaluate(x)
	P1Eval, _ := P1.Evaluate(x)
	P2Eval, _ := P2.Evaluate(x)
	vals := []koalabear.Element{P0Eval, P1Eval, P2Eval}
	QEval := QHorner.Eval(vals)

	var expected koalabear.Element
	expected.SetUint64(31)

	if !QEval.Equal(&expected) {
		t.Errorf("Q evaluation incorrect: expected %s, got %s", expected.String(), QEval.String())
	}

	if !resultEval.Equal(&QEval) {
		t.Errorf("Mismatch: result(%s) = %s, but Q(evaluations) = %s",
			x.String(), resultEval.String(), QEval.String())
	}
}

func TestComputeSymSimple(t *testing.T) {
	// Test with Q = x0 + x1 and two polynomials of the same degree
	// If P0(x) = x and P1(x) = 2x, then Q(P0, P1) = x + 2x = 3x

	var one, two koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)

	// Create P0(x) = x (coefficients: [0, 1])
	coeffs0 := make([]koalabear.Element, 8)
	coeffs0[1] = one
	P0, err := NewPolynomial(coeffs0, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1(x) = 2x (coefficients: [0, 2])
	coeffs1 := make([]koalabear.Element, 8)
	coeffs1[1] = two
	P1, err := NewPolynomial(coeffs1, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Create Q = x0 + x1
	Q := sym.NewVar("x0").Add(sym.NewVar("x1"))

	// Compute Q(P0, P1)
	Pi := []Polynomial{P0, P1}
	result, err := ComputeSym(Pi, Q, WithOutputName("result"))
	if err != nil {
		t.Fatalf("ComputeSym failed: %v", err)
	}

	// Expected result: P0(x) + P1(x) = x + 2x = 3x
	// Verify by evaluating at a test point
	var x koalabear.Element
	x.SetUint64(5) // x = 5

	resultEval, err := result.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	// Expected: 3 * 5 = 15
	var expected koalabear.Element
	expected.SetUint64(15)

	if !resultEval.Equal(&expected) {
		t.Errorf("Expected %s, got %s", expected.String(), resultEval.String())
	}
}

func TestComputeSymProduct(t *testing.T) {
	// Test with Q = x0 * x1 and two polynomials of the same degree
	// If P0(x) = 2x and P1(x) = x, then Q(P0, P1) = 2x * x = 2x^2

	var one, two koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)

	// Create P0(x) = 2x
	coeffs0 := make([]koalabear.Element, 8)
	coeffs0[1] = two
	P0, err := NewPolynomial(coeffs0, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1(x) = x
	coeffs1 := make([]koalabear.Element, 8)
	coeffs1[1] = one
	P1, err := NewPolynomial(coeffs1, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Create Q = x0 * x1
	Q := sym.NewVar("x0").Mul(sym.NewVar("x1"))

	// Compute Q(P0, P1)
	Pi := []Polynomial{P0, P1}
	result, err := ComputeSym(Pi, Q, WithOutputName("result"))
	if err != nil {
		t.Fatalf("ComputeSym failed: %v", err)
	}

	// Expected result: P0(x) * P1(x) = 2x * x = 2x^2
	// Verify by evaluating at a test point
	var x koalabear.Element
	x.SetUint64(5) // x = 5

	resultEval, err := result.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	// Expected: 2 * 25 = 50
	var expected koalabear.Element
	expected.SetUint64(50)

	if !resultEval.Equal(&expected) {
		t.Errorf("Expected %s, got %s", expected.String(), resultEval.String())
	}
}

func TestComputeSymSubtraction(t *testing.T) {
	// Test with Q = x0 - x1
	// If P0(x) = 3x and P1(x) = x, then Q(P0, P1) = 3x - x = 2x

	var one, three koalabear.Element
	one.SetUint64(1)
	three.SetUint64(3)

	// Create P0(x) = 3x
	coeffs0 := make([]koalabear.Element, 8)
	coeffs0[1] = three
	P0, err := NewPolynomial(coeffs0, WithID("x0"))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1(x) = x
	coeffs1 := make([]koalabear.Element, 8)
	coeffs1[1] = one
	P1, err := NewPolynomial(coeffs1, WithID("x1"))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Create Q = x0 - x1
	Q := sym.NewVar("x0").Sub(sym.NewVar("x1"))

	// Create varindex
	varindex := sym.VarIndex{
		"x0": 0,
		"x1": 1,
	}

	// Convert to Horner
	QM := sym.Convert(Q, varindex, 2)
	QHorner := sym.ToHorner(QM)

	// Compute Q(P0, P1) = P0 - P1 = 3x - x = 2x
	Pi := []Polynomial{P0, P1}
	result, err := ComputeSym(Pi, Q, WithOutputName("result"))
	if err != nil {
		t.Fatalf("ComputeSym failed: %v", err)
	}

	// Verify by evaluating at a test point
	var x koalabear.Element
	x.SetUint64(5) // x = 5

	resultEval, err := result.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	// Expected: 2x = 2 * 5 = 10
	var expected koalabear.Element
	expected.SetUint64(10)

	if !resultEval.Equal(&expected) {
		t.Errorf("Expected %s, got %s", expected.String(), resultEval.String())
	}

	// Also verify using direct evaluation
	P0Eval, _ := P0.Evaluate(x)
	P1Eval, _ := P1.Evaluate(x)
	vals := []koalabear.Element{P0Eval, P1Eval}
	QEval := QHorner.Eval(vals)

	if !resultEval.Equal(&QEval) {
		t.Errorf("Mismatch: result(%s) = %s, but Q(P0(%s), P1(%s)) = %s",
			x.String(), resultEval.String(), x.String(), x.String(), QEval.String())
	}
}

func TestComputeSymShiftedPolynomial(t *testing.T) {

	// Q := x0 - x1
	Q := sym.NewVar("x0").Sub(sym.NewVar("x1"))

	// random point for evaluaton
	var x koalabear.Element
	x.SetRandom()

	var zero koalabear.Element

	// create two columns shifted
	size := 8
	coeffs0 := make([]koalabear.Element, size)
	coeffs1 := make([]koalabear.Element, size)
	for i := 0; i < size; i++ {
		coeffs0[i].SetRandom()
		coeffs1[(i+1)%size].Set(&coeffs0[i])
	}

	P0, err := NewInterpolatedPolynomial(coeffs0, "x0")
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	P1, err := NewInterpolatedPolynomial(coeffs1, "x1", WithShift(1))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// P0 and P1 are of the same degree 7 and vanish on 8 points, so P0 - P1 should be zero
	R, err := ComputeSym([]Polynomial{P0, P1}, Q, WithOutputName("result"))
	if err != nil {
		t.Fatalf("ComputeSym failed: %v", err)
	}

	resultEval, err := R.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if !resultEval.Equal(&zero) {
		t.Errorf("Expected zero, got %s", resultEval.String())
	}
}
