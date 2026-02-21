package cs

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
)

func TestLagrangeSystem(t *testing.T) {

	// generate a random polynomial P in Lagrange form of size 16, whose 5-th entry is equal to 10
	size := 16
	entry := 5
	var targetValue koalabear.Element
	targetValue.SetUint64(10)

	// Create random evaluations
	coeffs := make([]koalabear.Element, size)
	for i := 0; i < size; i++ {
		coeffs[i].SetRandom()
	}
	// Set the 5th entry to 10
	coeffs[entry] = targetValue

	// Create polynomial in Lagrange form (NewInterpolatedPolynomial creates in Lagrange basis)
	P, err := univariate.NewInterpolatedPolynomial(coeffs, "P")
	if err != nil {
		t.Fatalf("Failed to create polynomial: %v", err)
	}

	// Verify P is in Lagrange basis and the 5th entry is 10
	if P.EP.Basis != univariate.Lagrange {
		t.Fatalf("Expected Lagrange basis, got %v", P.EP.Basis)
	}
	actualValue := P.GetCoefficient(entry)
	if !actualValue.Equal(&targetValue) {
		t.Fatalf("Expected P[%d] = %v, got %v", entry, targetValue.String(), actualValue.String())
	}

	// call NewLagrangeProtocol and verify the proof
	S, T, err := NewLagrangeProtocol(P, entry, targetValue)
	if err != nil {
		t.Fatalf("NewLagrangeProtocol failed: %v", err)
	}

	// check the system using BruteForceChecker
	if err := BruteForceChecker(S); err != nil {
		t.Fatalf("BruteForceChecker failed: %v", err)
	}

	// verify the proof
	if err := Verify(&T); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Additional test: create a system with wrong value to ensure Verify fails
	var wrongValue koalabear.Element
	wrongValue.SetUint64(11) // Different from the actual value
	_, TWrong, err := NewLagrangeProtocol(P, entry, wrongValue)
	if err != nil {
		t.Fatalf("NewLagrangeProtocol failed for wrong value: %v", err)
	}

	// Verify should fail because the constraint is not satisfied
	if err := Verify(&TWrong); err == nil {
		t.Fatal("Expected Verify to fail with wrong value, but it passed")
	}
}
