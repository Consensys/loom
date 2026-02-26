package system

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// BruteForceChecker checks rows by rows a system by evaluating on the domain X^n-1,
// and checks that it is zero on this domain
func BruteForceChecker(S System) error {

	for _, C := range S.Constraints {

		leaves := C.Leaves()

		varindex := make(sym.VarIndex)
		for i, l := range leaves {
			varindex[l] = i
		}

		// evaluate C rows by rows
		CHorner := sym.ToHorner(sym.Convert(C, varindex, len(leaves)))
		values := make([]koalabear.Element, len(leaves))
		for i := 0; i < S.N; i++ {

			for _, l := range leaves {
				values[varindex[l]] = S.Trace[l].GetCoefficient(i)
			}

			z := CHorner.Eval(values)

			if !z.IsZero() {
				return fmt.Errorf("%s should vanish on the trace, but failed at row %d\n", C.String(), i)
			}
		}

	}

	return nil
}

// QuotientChecker checks Constraint satisfiability of S. It returns an error if the constraint is not satisfied by the trace.
// Constraint satisfiability means that C(T)=0 mod X^n-1 where C:=S.Constraint, T:=S.Trace. To make this check, we compute the quotient
// h = C(T) / X^n-1 where n is the size of the columns of T, and verify at a random point x that C(T)(x)-(x^n-1)*h(x)=0.
//
// It is a debugging function
func QuotientChecker(S System) error {

	d := fft.NewDomain(uint64(S.N))

	for _, C := range S.Constraints {

		// Compute H = C(trace) / (X^N - 1) in canonical form
		H, err := univariate.ComputeQuotient(S.Trace, C, S.N)
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

		// Build varindex from constraint leaves; for each leaf, copy the trace polynomial,
		// convert to Canonical (copies avoid mutating the original trace), and evaluate at z.
		leaves := sym.RemoveDuplicates(C.Leaves())
		varindex := make(sym.VarIndex)
		for i, l := range leaves {
			varindex[l] = i
		}
		values := make([]koalabear.Element, len(leaves))
		for _, l := range leaves {
			var pCopy univariate.Polynomial
			univariate.Copy(&pCopy, S.Trace[l])
			if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
				return fmt.Errorf("failed to convert %s to Canonical: %w", l, err)
			}
			val, err := pCopy.Evaluate(z)
			if err != nil {
				return fmt.Errorf("failed to evaluate %s at z: %w", l, err)
			}
			values[varindex[l]] = val
		}

		// Evaluate C at the column evaluations: cz = C(traces(z))
		CHorner := sym.ToHorner(sym.Convert(C, varindex, len(leaves)))
		cz := CHorner.Eval(values)

		// Check C(T)(z) == H(z) * (z^N - 1)
		var zN, one koalabear.Element
		one.SetOne()
		zN.Exp(z, big.NewInt(int64(S.N)))
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

func BuildPermutationCircuit(t *testing.T, size int) System {
	// Create P0 with random evaluations
	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}
	P0, err := univariate.NewInterpolatedPolynomial(coeffs0, "P0")
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
	P1, err := univariate.NewInterpolatedPolynomial(coeffs1, "P1")
	if err != nil {
		t.Fatalf("Failed to create P1: %v", err)
	}

	T := map[string]*univariate.Polynomial{
		"P0": &P0,
		"P1": &P1,
	}
	S := System{
		Trace:             T,
		Constraints:       []Constraint{},
		CachedConstraints: []Constraint{},
		N:                 size,
	}
	return S
}

func BuildLookupCircuit(t *testing.T, size int) System {
	tCoeffs := make([]koalabear.Element, size)
	for i := range tCoeffs {
		tCoeffs[i].SetUint64(uint64(i + 1))
	}
	T, err := univariate.NewInterpolatedPolynomial(tCoeffs, "T")
	if err != nil {
		t.Fatal(err)
	}

	// S: lookup values — each appears in T, some repeated.
	// Multiplicities: T[0]=1 appears 2x, T[1]=2 appears 1x, T[2]=3 appears 1x,
	// T[3]=4 appears 2x, T[4]=5..T[7]=8 appear 1x each, T[6]=7 appears 2x,
	// T[8]=9..T[12]=13 appear 1x each, T[13]=14..T[15]=16 appear 0x.
	// Total: 2+1+1+2+1+1+2+1+1+1+1+1+1+0+0+0 = 16 = size. ✓
	sVals := []uint64{1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 11, 12, 13}
	sCoeffs := make([]koalabear.Element, size)
	for i, v := range sVals {
		sCoeffs[i].SetUint64(v)
	}
	S, err := univariate.NewInterpolatedPolynomial(sCoeffs, "S")
	if err != nil {
		t.Fatal(err)
	}

	sys := System{
		Trace:             map[string]*univariate.Polynomial{"S": &S, "T": &T},
		Constraints:       []Constraint{},
		CachedConstraints: []Constraint{},
		N:                 size,
	}

	return sys
}
