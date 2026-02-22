package cs

import (
	"fmt"
	"math/big"

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
