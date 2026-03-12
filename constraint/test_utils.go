package constraint

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/giop/internal/constants"
	"github.com/consensys/giop/internal/dag"
	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/internal/poly"
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
	T[challenge.Name] = []koalabear.Element{challenge.Value}
	return nil
}

// BuildRandomTrace creates a random trace with 2 columns "A" and "B"
func BuildRandomTrace(t *testing.T, size int) trace.Trace {

	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}

	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs1 {
		coeffs1[i].SetRandom()
	}

	return trace.Trace{
		"E": coeffs0,
		"M": coeffs1,
	}
}

func BuildPermutationCircuit(t *testing.T, size int) trace.Trace {

	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}

	// P1 is a cyclic shift of P0: P1[i] = P0[(i+1)%size]
	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs1 {
		coeffs1[i] = coeffs0[(i+1)%size]
	}

	return trace.Trace{
		"P0": coeffs0,
		"P1": coeffs1,
	}
}

// BuildPermutationTuple creates a trace with four columns P0, P1, Q0, Q1 where
// the tuple multiset {(P0[i], P1[i])} equals {(Q0[i], Q1[i])} up to permutation.
// (Q0, Q1) is a cyclic shift of (P0, P1): Q0[i]=P0[(i+1)%size], Q1[i]=P1[(i+1)%size].
func BuildPermutationTuple(t *testing.T, size int) trace.Trace {

	coeffs0 := make([]koalabear.Element, size)
	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
		coeffs1[i].SetRandom()
	}

	coeffsQ0 := make([]koalabear.Element, size)
	coeffsQ1 := make([]koalabear.Element, size)
	for i := range coeffsQ0 {
		coeffsQ0[i] = coeffs0[(i+1)%size]
		coeffsQ1[i] = coeffs1[(i+1)%size]
	}

	return trace.Trace{
		"P0": coeffs0,
		"P1": coeffs1,
		"Q0": coeffsQ0,
		"Q1": coeffsQ1,
	}
}

// BruteForceChecker checks rows by rows a system by evaluating on the domain X^n-1,
// and checks that it is zero on this domain
func BruteForceChecker(T trace.Trace, constraints []Relation, N int) error {

	for _, C := range constraints {

		leaves := expr.RemoveDuplicates(C.Leaves(expr.NewConfig(expr.WithoutRotatedColumns())))

		// validate all live columns are present before touching any row
		for _, l := range leaves {
			if _, ok := T[l]; !ok {
				return fmt.Errorf("%s not found in the trace", l)
			}
		}

		vals, err := poly.BuildPointwiseEvaluation(T, C, N, nil)
		if err != nil {
			return err
		}
		for i, v := range vals {
			if !v.IsZero() {
				return fmt.Errorf("relation not zero at row %d", i)
			}
		}

	}

	return nil
}

// evalCanonical evaluates a polynomial in canonical form (c_0 + c_1*x + ...) at point z using Horner's method.
func evalCanonical(coeffs []koalabear.Element, z koalabear.Element) koalabear.Element {
	if len(coeffs) == 0 {
		return koalabear.Element{}
	}
	y := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		y.Mul(&y, &z)
		y.Add(&y, &coeffs[i])
	}
	return y
}

// lagrangeToCanonical converts a Lagrange-Normal polynomial to canonical form in-place via IFFT.
func lagrangeToCanonical(p []koalabear.Element) {
	d := fft.NewDomain(uint64(len(p)))
	d.FFTInverse(p, fft.DIF)
	fft.BitReverse(p)
}

// QuotientChecker checks Relation satisfiability of S. It returns an error if the constraint is not satisfied by the trace.
// Relation satisfiability means that C(T)=0 mod X^n-1 where C:=S.Relation, T:=T. To make this check, we compute the quotient
// h = C(T) / X^n-1 where n is the size of the columns of T, and verify at a random point x that C(T)(x)-(x^n-1)*h(x)=0.
//
// It is a debugging function
func QuotientChecker(T trace.Trace, constraints []Relation, N int) error {

	for _, C := range constraints {

		// Compute H = C(trace) / (X^N - 1) in coset-Lagrange form
		Cdag := dag.ExprToDAG(C)
		H, err := poly.ComputeQuotient(T, *Cdag, N)
		if err != nil {
			return fmt.Errorf("ComputeQuotient failed: %w", err)
		}

		// Convert H from coset-Lagrange to standard Lagrange Normal
		poly.CosetLagrangeToLagrangeNormal(H)

		// Pick a random evaluation point
		var z koalabear.Element
		z.SetRandom()

		// Evaluate H(z) via IFFT + Horner
		hCoeffs := make([]koalabear.Element, len(H))
		copy(hCoeffs, H)
		lagrangeToCanonical(hCoeffs)
		hz := evalCanonical(hCoeffs, z)

		// For each leaf, evaluate the trace polynomial at z (or w^shift*z for shifted columns)
		leavesNormal := expr.RemoveDuplicates(C.Leaves(expr.NewConfig(expr.WithoutRotatedColumns())))
		leavesShifted := expr.RemoveDuplicates(C.Leaves(expr.NewConfig(
			expr.WithoutChallenges(), expr.WithoutCommittedColumns(), expr.WithoutVirtualumns())))
		vals := make(map[string]koalabear.Element, len(leavesNormal)+len(leavesShifted))
		for _, l := range leavesNormal {
			poly := T[l]
			if len(poly) == 1 {
				vals[l] = poly[0]
				continue
			}
			pCopy := make([]koalabear.Element, len(poly))
			copy(pCopy, poly)
			lagrangeToCanonical(pCopy)
			vals[l] = evalCanonical(pCopy, z)
		}
		w, err := koalabear.Generator(uint64(N))
		if err != nil {
			return err
		}
		for _, l := range leavesShifted {
			baseName, shift, err := constants.SplitShiftedName(l)
			if err != nil {
				return err
			}
			poly := T[baseName]
			if len(poly) == 1 {
				vals[l] = poly[0]
				continue
			}
			pCopy := make([]koalabear.Element, len(poly))
			copy(pCopy, poly)
			lagrangeToCanonical(pCopy)
			var wShift koalabear.Element
			wShift.Set(&w)
			absShift := shift
			if absShift < 0 {
				wShift.Inverse(&wShift)
				absShift = -absShift
			}
			wShift.Exp(wShift, big.NewInt(int64(absShift)))
			wShift.Mul(&wShift, &z)
			vals[l] = evalCanonical(pCopy, wShift)
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
