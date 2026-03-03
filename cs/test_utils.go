package cs

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/giop/pas/dag"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

type Challenge struct {
	Name  string
	Value koalabear.Element
}

// addChallengeInTrace adds challenge as a constant column to T if it has a
// name and is not already present. This allows functions like NewSimpleIOP and
// NewGrandProductIOP to be called directly (without Protocol.SendMeAChallenge) while
// still resolving placeholder references during pointwise evaluation and brute-force checks.
func addChallengeInTrace(T trace.Trace, challenge Challenge) error {
	if challenge.Name == "" {
		return nil
	}
	if _, ok := T[challenge.Name]; ok {
		return nil
	}
	col, err := univariate.NewConstantPolynomial(challenge.Value)
	if err != nil {
		return err
	}
	T[challenge.Name] = &col
	return nil
}

// BuildRandomTrace creates a random trace with 2 columns "A" and "B"
func BuildRandomTrace(t *testing.T, size int) trace.Trace {

	// Create P0 with random evaluations
	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}
	E, err := univariate.NewPolynomial(coeffs0, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs1[i].SetRandom()
	}
	M, err := univariate.NewPolynomial(coeffs1, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	return map[string]*univariate.Polynomial{
		"E": &E,
		"M": &M,
	}

}

func BuildPermutationCircuit(t *testing.T, size int) trace.Trace {

	// Create P0 with random evaluations
	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}
	P0, err := univariate.NewPolynomial(coeffs0, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}

	// Create P1 as a cyclic shift of P0: P1[i] = P0[(i+1) % size].
	// Both encode the same multiset, so Π(P0[i]-gamma) = Π(P1[i]-gamma),
	// meaning the grand product wraps back to 1 and the constraint holds at every row.
	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs1 {
		coeffs1[i] = coeffs0[(i+1)%size]
	}
	P1, err := univariate.NewPolynomial(coeffs1, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	return map[string]*univariate.Polynomial{
		"P0": &P0,
		"P1": &P1,
	}

}

// BuildPermutationMultiSet creates a trace with four columns P0, P1, Q0, Q1 where
// the tuple multiset {(P0[i], P1[i])} equals {(Q0[i], Q1[i])} up to permutation.
// (Q0, Q1) is a cyclic shift of (P0, P1): Q0[i]=P0[(i+1)%size], Q1[i]=P1[(i+1)%size].
func BuildPermutationMultiSet(t *testing.T, size int) trace.Trace {

	coeffs0 := make([]koalabear.Element, size)
	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
		coeffs1[i].SetRandom()
	}
	P0, err := univariate.NewPolynomial(coeffs0, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create P0: %v", err)
	}
	P1, err := univariate.NewPolynomial(coeffs1, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	// Q0[i] = P0[(i+1)%size], Q1[i] = P1[(i+1)%size]: cyclic shift of the pairs
	coeffsQ0 := make([]koalabear.Element, size)
	coeffsQ1 := make([]koalabear.Element, size)
	for i := range coeffsQ0 {
		coeffsQ0[i] = coeffs0[(i+1)%size]
		coeffsQ1[i] = coeffs1[(i+1)%size]
	}
	Q0, err := univariate.NewPolynomial(coeffsQ0, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create Q0: %v", err)
	}
	Q1, err := univariate.NewPolynomial(coeffsQ1, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create Q1: %v", err)
	}

	return map[string]*univariate.Polynomial{
		"P0": &P0,
		"P1": &P1,
		"Q0": &Q0,
		"Q1": &Q1,
	}
}

// BruteForceChecker checks rows by rows a system by evaluating on the domain X^n-1,
// and checks that it is zero on this domain
func BruteForceChecker(T trace.Trace, constraints []Constraint, N int) error {

	for _, C := range constraints {

		leaves := sym.RemoveDuplicates(C.Leaves(sym.NewConfig()))

		// validate all leaves are present before touching any row
		for _, l := range leaves {
			if _, ok := T[l]; !ok {
				return fmt.Errorf("%s not found in the trace", l)
			}
		}

		vals := make(map[string]koalabear.Element, len(leaves))
		for i := 0; i < N; i++ {
			for _, l := range leaves {
				vals[l] = T[l].GetCoefficient(i)
			}
			if z := C.Evaluate(vals); !z.IsZero() {
				return fmt.Errorf("%s should vanish on the trace, but failed at row %d\n", C.String(), i)
			}
		}

	}

	return nil
}

// QuotientChecker checks Constraint satisfiability of S. It returns an error if the constraint is not satisfied by the trace.
// Constraint satisfiability means that C(T)=0 mod X^n-1 where C:=S.Constraint, T:=T. To make this check, we compute the quotient
// h = C(T) / X^n-1 where n is the size of the columns of T, and verify at a random point x that C(T)(x)-(x^n-1)*h(x)=0.
//
// It is a debugging function
func QuotientChecker(T trace.Trace, constraints []Constraint, N int) error {

	d := fft.NewDomain(uint64(N))

	for _, C := range constraints {

		// Compute H = C(trace) / (X^N - 1) in canonical form
		Cdag := dag.ExprToDAG(C)
		H, err := univariate.ComputeQuotient(T, *Cdag, N)
		if err != nil {
			return fmt.Errorf("ComputeQuotient failed: %w", err)
		}

		// Pick a random evaluation point
		var z koalabear.Element
		z.SetRandom()

		// Convert H to Canonical basis so it can be evaluated at a point
		hDomain := fft.NewDomain(uint64(len(H.EP.Coefficients)))
		if err := H.ToBasis(hDomain, univariate.Canonical); err != nil {
			return fmt.Errorf("failed to convert quotient to Canonical basis: %w", err)
		}

		// Evaluate H(z)
		hz, err := H.Evaluate(z)
		if err != nil {
			return fmt.Errorf("failed to evaluate quotient at z: %w", err)
		}

		// For each leaf, copy the trace polynomial, convert to Canonical
		// (copies avoid mutating the original trace), and evaluate at z.
		leaves := sym.RemoveDuplicates(C.Leaves(sym.NewConfig()))
		vals := make(map[string]koalabear.Element, len(leaves))
		for _, l := range leaves {
			var pCopy univariate.Polynomial
			univariate.Copy(&pCopy, T[l])
			if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
				return fmt.Errorf("failed to convert %s to Canonical: %w", l, err)
			}
			val, err := pCopy.Evaluate(z)
			if err != nil {
				return fmt.Errorf("failed to evaluate %s at z: %w", l, err)
			}
			vals[l] = val
		}

		// Evaluate C at the column evaluations: cz = C(traces(z))
		cz := C.Evaluate(vals)

		// Check C(T)(z) == H(z) * (z^N - 1)
		var zN, one koalabear.Element
		one.SetOne()
		zN.Exp(z, big.NewInt(int64(N)))
		zN.Sub(&zN, &one)
		var rhs koalabear.Element
		rhs.Mul(&zN, &hz)

		if !rhs.Equal(&cz) {
			return fmt.Errorf("constraint %s is not satisfied: C(T)(z)=%s, H(z)*(z^N-1)=%s",
				C.String(), cz.String(), rhs.String())
		}
	}

	return nil
}
