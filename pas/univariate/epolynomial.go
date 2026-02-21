package univariate

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

// Basis represents the basis in which a polynomial is represented
type Basis int

const (
	// Canonical represents the canonical basis (1, x, x^2, ...)
	Canonical Basis = iota
	// Lagrange represents the Lagrange basis (evaluations at FFT domain points)
	Lagrange
	// LagrangeShifted represents the Lagrange basis on a shifted domain
	LagrangeShifted
)

// Layout represents the memory layout of polynomial coefficients
type Layout int

const (
	// Normal represents the standard coefficient ordering
	Normal Layout = iota
	// BitReversed represents bit-reversed ordering used in FFT operations
	BitReversed
)

// EPolynomial represents a univariate polynomial over the koalabear finite field
// The E stands for Embedded, as this struct is embedded in Polynomial, which stores a pointer to an EPolynomial and adds additional metadata.
type EPolynomial struct {
	// Coefficients stores the polynomial coefficients
	// For canonical basis: coefficient at index i corresponds to x^i
	// For Lagrange basis: evaluation at the i-th domain point
	Coefficients []koalabear.Element

	// Basis indicates the representation basis
	Basis Basis

	// Layout indicates the memory layout of coefficients
	Layout Layout

	// Degree is the degree of the polynomial
	Degree int

	// IsConstant if set, len(Coefficients)=1.
	IsConstant bool
}

// isPowerOfTwo checks if n is a power of two
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// NextPowerOfTwo returns the next power of two greater than or equal to n
func NextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	if isPowerOfTwo(n) {
		return n
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}

// nextPowerOfTwo is an alias for NextPowerOfTwo for internal use
func nextPowerOfTwo(n int) int {
	return NextPowerOfTwo(n)
}

// NewInterpolatedEPolynomial creates a new polynomial in Lagrange basis from given evaluations at FFT domain points.
// The size of the evaluations slice is automatically padded to the next power of two if necessary.
// The resulting polynomial has Lagrange basis and normal layout.
func NewInterpolatedEPolynomial(evals []koalabear.Element, id string) (*EPolynomial, error) {
	if len(evals) == 0 {
		return nil, fmt.Errorf("evaluations slice cannot be empty")
	}

	// Pad to next power of two if necessary
	size := len(evals)
	if !isPowerOfTwo(size) {
		size = nextPowerOfTwo(size)
		padded := make([]koalabear.Element, size)
		copy(padded, evals)
		evals = padded
	}

	return &EPolynomial{
		Coefficients: evals,
		Basis:        Lagrange,
		Layout:       Normal,
		Degree:       size - 1, // we don't actually know the degree until we convert to canonical, but this is an upper bound
	}, nil
}

// NewEPolynomial creates a new polynomial with the given coefficients in canonical basis with normal layout.
// The size of the coefficient slice is automatically padded to the next power of two if necessary.
func NewEPolynomial(coeffs []koalabear.Element, id string) (*EPolynomial, error) {
	if len(coeffs) == 0 {
		return nil, fmt.Errorf("coefficients slice cannot be empty")
	}

	// Pad to next power of two if necessary
	size := len(coeffs)
	if !isPowerOfTwo(size) {
		targetSize := nextPowerOfTwo(size)
		padded := make([]koalabear.Element, targetSize)
		copy(padded, coeffs)
		coeffs = padded
	}

	// Calculate actual degree
	degree := len(coeffs) - 1
	for degree > 0 && coeffs[degree].IsZero() {
		degree--
	}

	return &EPolynomial{
		Coefficients: coeffs,
		Basis:        Canonical,
		Layout:       Normal,
		Degree:       degree,
	}, nil
}

// ToLayout converts the polynomial to the target layout (Normal or BitReversed) by applying bit reversal if necessary.
func (p *EPolynomial) ToLayout(target Layout) {
	switch target {
	case Normal:
		p.toNormal()
	case BitReversed:
		p.toBitReversed()
	}
}

// toNormal converts the polynomial layout to Normal.
// If already in Normal layout, this is a no-op.
func (p *EPolynomial) toNormal() {
	if p.Layout == Normal {
		return
	}

	fft.BitReverse(p.Coefficients)
	p.Layout = Normal
}

// toBitReversed converts the polynomial layout to BitReversed.
// If already in BitReversed layout, this is a no-op.
func (p *EPolynomial) toBitReversed() {
	if p.Layout == BitReversed {
		return
	}

	fft.BitReverse(p.Coefficients)
	p.Layout = BitReversed
}

// ToBasis converts the polynomial to the target basis (Canonical, Lagrange, or LagrangeShifted) using FFT transformations.
func (p *EPolynomial) ToBasis(d *fft.Domain, targetBasis Basis) error {
	switch targetBasis {
	case Canonical:
		return p.toCanonical(d)
	case Lagrange:
		return p.toLagrange(d)
	case LagrangeShifted:
		return p.toLagrangeShifted(d)
	default:
		return fmt.Errorf("unknown target basis: %v", targetBasis)
	}
}

// toLagrange converts the polynomial from canonical basis to Lagrange basis using FFT.
// The domain size must be at least degree+1, but can be larger.
// To minimize BitReverse calls, the layout changes according to the FFT algorithm:
// - If input layout is Normal: uses DIF (output becomes BitReversed)
// - If input layout is BitReversed: uses DIT (output becomes Normal)
// The polynomial coefficients are padded to match the domain size if necessary.
func (p *EPolynomial) toLagrange(d *fft.Domain) error {
	if p.Basis == Lagrange {
		return nil // Already in Lagrange basis
	}

	// If in LagrangeShifted basis, need to convert to canonical first
	if p.Basis == LagrangeShifted {
		if err := p.toCanonical(d); err != nil {
			return fmt.Errorf("cannot convert from LagrangeShifted to Lagrange: %w", err)
		}
	}

	// Check domain size is sufficient
	domainSize := int(d.Cardinality)
	if domainSize < p.Degree+1 {
		return fmt.Errorf("domain size %d is too small for polynomial of degree %d (need at least %d)",
			domainSize, p.Degree, p.Degree+1)
	}

	// Pad coefficients to match domain size if necessary
	if len(p.Coefficients) < domainSize {
		padded := make([]koalabear.Element, domainSize)
		copy(padded, p.Coefficients)
		p.Coefficients = padded
	}

	// Choose decimation mode based on current layout to minimize BitReverse calls
	var decimation fft.Decimation
	if p.Layout == Normal {
		// DIF: Normal input → BitReversed output (0 BitReverse calls)
		decimation = fft.DIF
		d.FFT(p.Coefficients, decimation)
		p.Layout = BitReversed
	} else {
		// DIT: BitReversed input → Normal output (0 BitReverse calls)
		decimation = fft.DIT
		d.FFT(p.Coefficients, decimation)
		p.Layout = Normal
	}

	p.Basis = Lagrange
	return nil
}

// toCanonical converts the polynomial from Lagrange basis to canonical basis using inverse FFT.
// The domain size must be at least degree+1, but can be larger.
// To minimize BitReverse calls, the layout changes according to the FFT algorithm:
// - If input layout is Normal: uses DIF (output becomes BitReversed)
// - If input layout is BitReversed: uses DIT (output becomes Normal)
func (p *EPolynomial) toCanonical(d *fft.Domain) error {
	if p.Basis == Canonical {
		return nil // Already in canonical basis
	}

	// Check domain size matches coefficient size
	domainSize := int(d.Cardinality)
	if len(p.Coefficients) != domainSize {
		return fmt.Errorf("domain size %d does not match coefficient size %d",
			domainSize, len(p.Coefficients))
	}

	// Choose decimation mode based on current layout to minimize BitReverse calls
	var decimation fft.Decimation
	if p.Basis == LagrangeShifted {
		// Convert from shifted Lagrange basis using inverse FFT with OnCoset option
		if p.Layout == Normal {
			// DIF: Normal input → BitReversed output (0 BitReverse calls)
			decimation = fft.DIF
			d.FFTInverse(p.Coefficients, decimation, fft.OnCoset())
			p.Layout = BitReversed
		} else {
			// DIT: BitReversed input → Normal output (0 BitReverse calls)
			decimation = fft.DIT
			d.FFTInverse(p.Coefficients, decimation, fft.OnCoset())
			p.Layout = Normal
		}
	} else {
		// Convert from standard Lagrange basis
		if p.Layout == Normal {
			// DIF: Normal input → BitReversed output (0 BitReverse calls)
			decimation = fft.DIF
			d.FFTInverse(p.Coefficients, decimation)
			p.Layout = BitReversed
		} else {
			// DIT: BitReversed input → Normal output (0 BitReverse calls)
			decimation = fft.DIT
			d.FFTInverse(p.Coefficients, decimation)
			p.Layout = Normal
		}
	}

	// Recalculate degree after conversion to canonical form
	p.Degree = len(p.Coefficients) - 1
	for p.Degree > 0 && p.Coefficients[p.Degree].IsZero() {
		p.Degree--
	}

	p.Basis = Canonical
	return nil
}

// toLagrangeShifted converts the polynomial to Lagrange basis on a shifted domain.
// The domain is shifted by d.FrMultiplicativeGen.
// The domain size must be at least degree+1, but can be larger.
// To minimize BitReverse calls, the layout changes according to the FFT algorithm:
// - If input layout is Normal: uses DIF (output becomes BitReversed)
// - If input layout is BitReversed: uses DIT (output becomes Normal)
// The polynomial coefficients are padded to match the domain size if necessary.
func (p *EPolynomial) toLagrangeShifted(d *fft.Domain) error {
	if p.Basis == LagrangeShifted {
		return nil // Already in LagrangeShifted basis
	}

	// If in Lagrange basis, need to convert to canonical first
	if p.Basis == Lagrange {
		if err := p.toCanonical(d); err != nil {
			return fmt.Errorf("cannot convert from Lagrange to LagrangeShifted: %w", err)
		}
	}

	// Now we're in canonical basis
	// Check domain size is sufficient
	domainSize := int(d.Cardinality)
	if domainSize < p.Degree+1 {
		return fmt.Errorf("domain size %d is too small for polynomial of degree %d (need at least %d)",
			domainSize, p.Degree, p.Degree+1)
	}

	// Pad coefficients to match domain size if necessary
	if len(p.Coefficients) < domainSize {
		padded := make([]koalabear.Element, domainSize)
		copy(padded, p.Coefficients)
		p.Coefficients = padded
	}

	// Choose decimation mode based on current layout to minimize BitReverse calls
	var decimation fft.Decimation
	if p.Layout == Normal {
		// DIF: Normal input → BitReversed output (0 BitReverse calls)
		decimation = fft.DIF
		d.FFT(p.Coefficients, decimation, fft.OnCoset())
		p.Layout = BitReversed
	} else {
		// DIT: BitReversed input → Normal output (0 BitReverse calls)
		decimation = fft.DIT
		d.FFT(p.Coefficients, decimation, fft.OnCoset())
		p.Layout = Normal
	}

	p.Basis = LagrangeShifted
	return nil
}

// Evaluate evaluates the polynomial at a given point x using Horner's method.
// The polynomial must be in canonical basis (not Lagrange or LagrangeShifted).
// For a polynomial p(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n,
// Horner's method computes: (...((a_n * x + a_{n-1}) * x + a_{n-2}) * x + ... + a_1) * x + a_0
func (p *EPolynomial) Evaluate(x koalabear.Element) (koalabear.Element, error) {
	if p.Basis != Canonical {
		return koalabear.Element{}, fmt.Errorf("polynomial must be in canonical basis for evaluation (current basis: %v)", p.Basis)
	}

	// Handle empty polynomial (shouldn't happen with proper construction, but be safe)
	if len(p.Coefficients) == 0 {
		return koalabear.Element{}, nil
	}

	// Horner's method: start from the highest degree term and work down
	var result koalabear.Element

	// Start with the highest degree coefficient
	if p.Layout == Normal {

		for i := len(p.Coefficients) - 1; i >= 0; i-- {
			// result = result * x + coefficients[i]
			result.Mul(&result, &x)
			result.Add(&result, &p.Coefficients[i])
		}
	} else { // in that case, query the i-th term in bit-reversed order
		n := uint64(len(p.Coefficients))
		if !isPowerOfTwo(int(n)) {
			return koalabear.Element{}, fmt.Errorf("coefficient length must be a power of two for bit-reversed layout")
		}
		nn := uint64(64 - bits.TrailingZeros64(n))
		for i := int(n) - 1; i >= 0; i-- {
			iRev := bits.Reverse64(uint64(i)) >> nn
			result.Mul(&result, &x)
			result.Add(&result, &p.Coefficients[iRev])
		}
	}

	return result, nil
}

// CopyE copies the contents of src EPolynomial to dst EPolynomial, including coefficients, basis, layout, degree, and ID.
func CopyE(dst, src *EPolynomial) {
	dst.Coefficients = make([]koalabear.Element, len(src.Coefficients))
	copy(dst.Coefficients, src.Coefficients)
	dst.Basis = src.Basis
	dst.Layout = src.Layout
	dst.Degree = src.Degree
	dst.IsConstant = src.IsConstant
}
