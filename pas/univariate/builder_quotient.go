package univariate

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
)

// ComputeQuotient computes Q(P[0], P[1], ..., P[n]) / (X^n-1) where Q(P[0], P[1], ..., P[n]) = 0 mod X^n-1.
// The polynomials P[i] are supposed to be of the same degree m, where n=m+1.
// The result is returned in canonical basis with normal layout by default, or according to the provided options.
func ComputeQuotient(Pi []Polynomial, C sym.Expr, opts ...BuilderOption) (Polynomial, error) {
	// step 0: set the configuration options and validate inputs
	if len(Pi) == 0 {
		return Polynomial{}, fmt.Errorf("no input polynomials provided")
	}

	config := NewBuilderConfig()

	// Apply options
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}

	// ensure that all the polynomials are of the same size. Pick the first non constant polynomial to assess the size
	var offset int
	var targetSize int
	for offset := 0; offset < len(Pi); offset++ {
		if Pi[offset].IsConstant() {
			continue
		}
		targetSize = len(Pi[offset].EP.Coefficients)
		break
	}
	for i := offset + 1; i < len(Pi); i++ {
		if Pi[i].IsConstant() {
			continue
		}
		if len(Pi[i].EP.Coefficients) != targetSize {
			return Polynomial{}, fmt.Errorf("polynomials should be of the size size")
		}
	}

	// Get the target domain size - this is the degree of the vanishing polynomial X^n - 1
	targetDomainSize := len(Pi[0].EP.Coefficients)

	// step 1: compute R := Q(Pi) using ComputeSym, where R is in Lagrange shifted basis
	// We use WithResultBasis(LagrangeShifted) to keep R in Lagrange shifted basis
	R, err := ComputeSym(Pi, C, WithOutputName(config.OutputName+"_temp"), WithResultBasis(LagrangeShifted))
	if err != nil {
		return Polynomial{}, fmt.Errorf("ComputeSym failed: %w", err)
	}

	// Ensure R is in LagrangeShifted basis
	if R.EP.Basis != LagrangeShifted {
		return Polynomial{}, fmt.Errorf("expected R in LagrangeShifted basis, got %v", R.EP.Basis)
	}

	// The actual domain size for R (may be larger than targetDomainSize)
	domainSize := len(R.EP.Coefficients)

	// Create domain for the computation
	domain := fft.NewDomain(uint64(domainSize))

	// step 2: divide R pointwise by the evaluations of X^targetDomainSize-1 on the shifted domain
	// On the shifted domain, the evaluation points are w*omega^i where w is the multiplicative generator
	// and omega is a primitive domainSize-th root of unity
	// We want to divide by (X^targetDomainSize - 1) evaluated at each w*omega^i
	// (w*omega^i)^targetDomainSize - 1

	// Get the multiplicative generator w and the generator omega
	w := domain.FrMultiplicativeGen
	omega := domain.Generator

	// Precompute w^targetDomainSize
	var wPowTarget koalabear.Element
	wPowTarget.Exp(w, big.NewInt(int64(targetDomainSize)))

	// Precompute omega^targetDomainSize (this will be a domainSize/targetDomainSize-th root of unity if domainSize is a multiple of targetDomainSize)
	var omegaPowTarget koalabear.Element
	omegaPowTarget.Exp(omega, big.NewInt(int64(targetDomainSize)))

	// Divide each evaluation pointwise
	quotient := &EPolynomial{
		Coefficients: make([]koalabear.Element, domainSize),
		Basis:        LagrangeShifted,
		Layout:       R.EP.Layout,
		Degree:       0, // Will be computed after converting to canonical
	}

	var one koalabear.Element
	one.SetOne()

	// At each point w*omega^i, compute (w*omega^i)^targetDomainSize - 1
	var omegaPowTargetI koalabear.Element
	omegaPowTargetI.SetOne()
	for i := 0; i < domainSize; i++ {
		// (w*omega^i)^targetDomainSize = w^targetDomainSize * (omega^targetDomainSize)^i
		var denominator koalabear.Element
		denominator.Mul(&wPowTarget, &omegaPowTargetI)
		denominator.Sub(&denominator, &one)

		if denominator.IsZero() {
			return Polynomial{}, fmt.Errorf("division by zero at index %d: (w*omega^%d)^%d - 1 = 0", i, i, targetDomainSize)
		}

		// Divide R[i] by denominator
		var invDenom koalabear.Element
		invDenom.Inverse(&denominator)
		c := R.GetCoefficient(i)
		quotient.Coefficients[i].Mul(&c, &invDenom) // TODO use getter for coefficient

		// Update omega^(targetDomainSize*i) for next iteration
		omegaPowTargetI.Mul(&omegaPowTargetI, &omegaPowTarget)
	}

	// step 3: convert the quotient polynomial back to the desired basis and layout
	if config.ResultBasis == Canonical {
		if err := quotient.toCanonical(domain); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert to canonical basis: %w", err)
		}
	} else if config.ResultBasis == Lagrange {
		if err := quotient.toLagrange(domain); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert to Lagrange basis: %w", err)
		}
	}
	// If ResultBasis is LagrangeShifted, we're already in the right basis

	// Adjust layout if needed
	if config.ResultLayout == Normal && quotient.Layout != Normal {
		quotient.toNormal()
	} else if config.ResultLayout == BitReversed && quotient.Layout != BitReversed {
		quotient.toBitReversed()
	}

	var r Polynomial
	r.EP = quotient
	r.ID = config.OutputName

	return r, nil
}
