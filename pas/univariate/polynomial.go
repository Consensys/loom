package univariate

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
)

// Polynomial is a wrapper around EPolynomial that includes additional metadata such as shift.
type Polynomial struct {

	// E contains the actual polynomial
	EP *EPolynomial

	// Shift the polynomial is interpreted as P(w^shift X) where P is described by the coefficients of EP
	Shift int

	// Identifier for plugging the EPolynomial into a symbolic expression system (optional, can be empty)
	ID string

	// IsCommitted flag telling if the polynomial has been committed
	IsCommitted bool
}

// Config holds configuration options for ComputeSym and ComputeQuotient
type PolynomialConfig struct {
	Shift  int
	Layout Layout
	Basis  Basis
	ID     string
}

func NewPolynomialConfig() PolynomialConfig {
	return PolynomialConfig{
		Shift:  0,
		Layout: Normal,
		Basis:  Canonical,
		ID:     "P",
	}
}

// PolynomialOption is a functional option type for configuring ComputeSym and ComputeQuotient
type PolynomialOption func(*PolynomialConfig) error

// WithShift sets the shift for the resulting polynomial
func WithShift(shift int) PolynomialOption {
	return func(c *PolynomialConfig) error {
		c.Shift = shift
		return nil
	}
}

func WithLayout(l Layout) PolynomialOption {
	return func(c *PolynomialConfig) error {
		c.Layout = l
		return nil
	}
}

func WithBasis(b Basis) PolynomialOption {
	return func(c *PolynomialConfig) error {
		c.Basis = b
		return nil
	}
}

func WithID(id string) PolynomialOption {
	return func(c *PolynomialConfig) error {
		c.ID = id
		return nil
	}
}

// NewInterpolatedPolynomial creates a new polynomial in Lagrange basis from given evaluations at FFT domain points.
func NewInterpolatedPolynomial(evals []koalabear.Element, id string, opts ...PolynomialOption) (Polynomial, error) {
	var config PolynomialConfig
	for o := range opts {
		if err := opts[o](&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}
	var res Polynomial
	var err error
	res.EP, err = NewInterpolatedEPolynomial(evals, id)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to create EPolynomial: %w", err)
	}

	res.ID = id
	res.Shift = config.Shift
	return res, nil
}

// NewConstantPolynomial returns a constant polynomial. Useful for saving memory as there is only one coefficient.
func NewConstantPolynomial(value koalabear.Element, opts ...PolynomialOption) (Polynomial, error) {
	config := NewPolynomialConfig()
	for o := range opts {
		if err := opts[o](&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}
	var res Polynomial
	var err error
	res.EP, err = NewEPolynomial([]koalabear.Element{value}, config.ID)
	if err != nil {
		return Polynomial{}, err
	}
	res.EP.IsConstant = true
	res.ID = config.ID
	return res, nil
}

// NewPolynomial creates a new polynomial with the given coefficients.
// By default, it is in canonical basis with normal layout.
// The size of the coefficient slice is automatically padded to the next power of two if necessary.
func NewPolynomial(coeffs []koalabear.Element, opts ...PolynomialOption) (Polynomial, error) {
	config := NewPolynomialConfig()
	for o := range opts {
		if err := opts[o](&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}
	var res Polynomial
	var err error
	res.EP, err = NewEPolynomial(coeffs, config.ID)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to create EPolynomial: %w", err)
	}

	res.EP.Basis = config.Basis
	res.EP.Layout = config.Layout
	res.ID = config.ID
	res.Shift = config.Shift

	return res, nil
}

func (p *Polynomial) IsConstant() bool {
	return p.EP.IsConstant
}

// ToLayout converts the polynomial to the target layout (Normal or BitReversed) by applying bit reversal if necessary.
func (p *Polynomial) ToLayout(target Layout) {
	p.EP.ToLayout(target)
}

// ToBasis converts the polynomial to the target layout (Normal or BitReversed) by applying bit reversal if necessary.
func (p *Polynomial) ToBasis(d *fft.Domain, target Basis) error {
	if p.EP.IsConstant {
		p.EP.Basis = target
		return nil
	}
	return p.EP.ToBasis(d, target)
}

// GetCoefficient returns the coefficient of x^i in the polynomial. If the polynomial is in Lagrange shifted basis, it returns the evaluation at the corresponding shifted point in the domain.
func (p *Polynomial) GetCoefficient(i int) koalabear.Element {
	if p.EP.Basis != Canonical {
		if p.EP.IsConstant {
			return p.EP.Coefficients[0]
		}
		if p.Shift != 0 {
			// if shift=i, P = P'(w^i x) where P' is the underlying EPolynomial and w is the generator of the FFT domain of size P.Degree+1.
			// When p is in Lagrange or Lagrange shifted form, it means that P[i] = P'[ (i+(shift * len(p.Coefficient)/(p.Degree()+1)) % len(p.Coefficient) ] where P[i] is the i-th coefficient of P in the current basis and layout,
			// and P'[j] is the j-th coefficient of P' in the current basis and layout.
			n := nextPowerOfTwo(p.Degree() + 1)
			npt := nextPowerOfTwo(len(p.EP.Coefficients))
			ratio := npt / n
			shiftedIndex := (i + p.Shift*ratio) % len(p.EP.Coefficients)

			// If the layout is bit-reversed, we need to reverse the bits of the shifted index before accessing the coefficient.
			if p.EP.Layout == BitReversed {
				nn := uint64(64 - bits.TrailingZeros64(uint64(npt)))
				shiftedIndex = int(bits.Reverse64(uint64(shiftedIndex)) >> nn)
			}

			return p.EP.Coefficients[shiftedIndex]
		} else {

			// If the layout is bit-reversed, we need to reverse the bits of the index before accessing the coefficient.
			if p.EP.Layout == BitReversed {
				npt := nextPowerOfTwo(len(p.EP.Coefficients))
				nn := uint64(64 - bits.TrailingZeros64(uint64(npt)))
				reversedIndex := int(bits.Reverse64(uint64(i)) >> nn)
				return p.EP.Coefficients[reversedIndex]
			} else {
				return p.EP.Coefficients[i]
			}
		}
	} else {
		panic("GetCoefficient is not supported for polynomials in canonical basis, as the coefficients may be stored in a different order depending on the layout. Please convert to Lagrange or Lagrange shifted basis before calling GetCoefficient.")
	}
}

// Degree returns the degree of the polynomial, which is determined by the degree of the underlying EPolynomial.
func (p *Polynomial) Degree() int {
	return p.EP.Degree
}

// Copy copies the contents of src Polynomial to dst Polynomial, including coefficients, basis, layout, degree, ID, and shift.
func Copy(dst, src *Polynomial) {
	if dst.EP == nil {
		dst.EP = &EPolynomial{}
	}
	CopyE(dst.EP, src.EP)
	dst.ID = src.ID
	dst.Shift = src.Shift
	dst.IsCommitted = src.IsCommitted
}

// ShallowCopy creates a shallow copy of src Polynomial to dst Polynomial, where dst shares the same underlying EPolynomial as src, but has its own shift value.
// TODO should made it mandatory to change the ID
func ShallowCopy(dst, src *Polynomial) {
	dst.EP = src.EP // points to the same EPolynomial
	dst.Shift = src.Shift
	dst.ID = src.ID
	dst.IsCommitted = src.IsCommitted
}

// SetShift sets the shift value for the polynomial, which determines how the coefficients are accessed when the polynomial is in Lagrange or Lagrange shifted basis. The shift is applied as a circular shift on the coefficients when accessed through GetCoefficient.
func (p *Polynomial) SetShift(shift int) {
	p.Shift = shift
}

// Evaluate evaluates the polynomial at a given point x using Horner's method. If shift!=0, it evaluates P(x * g^shift) where g is the generator of the FFT domain.
func (p *Polynomial) Evaluate(x koalabear.Element) (koalabear.Element, error) {
	if p.EP.IsConstant {
		return p.EP.Coefficients[0], nil
	}
	if p.Shift != 0 {
		g, err := koalabear.Generator(uint64(p.Degree() + 1))
		if err != nil {
			return koalabear.Element{}, fmt.Errorf("failed to get generator: %w", err)
		}
		g.Exp(g, big.NewInt(int64(p.Shift)))
		x.Mul(&x, &g)
	}
	return p.EP.Evaluate(x)
}

// ComputeSym computes the resulting polynomial from evaluating a symbolic expression Q at polynomials Pi.
// The varindex maps variable names in Pi to indices in Q.
// The resulting polynomial is returned in canonical basis with normal layout.
// The i-th variable in Q corresponds to the polynomial Pi[varindex[Pi[i].ID]].
func ComputeSym(Pi []Polynomial, E sym.Expr, opts ...BuilderOption) (Polynomial, error) {
	if len(Pi) == 0 {
		return Polynomial{}, fmt.Errorf("no input polynomials provided")
	}

	config := NewBuilderConfig()

	// create varindex, and convert E to horner
	varindex := make(sym.VarIndex)
	for i, p := range Pi {
		varindex[p.ID] = i
	}
	Q := sym.ToHorner(sym.Convert(E, varindex, len(Pi)))

	// Apply options
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Ensure that all Pi have the same size (for domain compatibility). Treat the constant polynomials separately.
	var offset int
	var targetSize int
	for offset := 0; offset < len(Pi); offset++ {
		if !Pi[offset].IsConstant() {
			targetSize = len(Pi[offset].EP.Coefficients)
			break
		}
	}
	for i := offset + 1; i < len(Pi); i++ {
		if !Pi[i].IsConstant() {
			if len(Pi[i].EP.Coefficients) != targetSize {
				return Polynomial{}, fmt.Errorf("polynomial %d has size %d, expected %d",
					i, len(Pi[i].EP.Coefficients), targetSize)
			}
		}
	}

	// Ensure that all Pi have the same degree. Treat the constant polynomials separately
	offset = 0
	var targetDegree int
	for offset := 0; offset < len(Pi); offset++ {
		if !Pi[offset].IsConstant() {
			targetDegree = Pi[offset].Degree()
			break
		}
	}
	for i := offset + 1; i < len(Pi); i++ {
		if !Pi[i].IsConstant() {
			if Pi[i].Degree() != targetDegree {
				return Polynomial{}, fmt.Errorf("polynomial %d has degree %d, expected %d (all polynomials must have the same degree)",
					i, Pi[i].Degree(), targetDegree)
			}
		}
	}

	// Ensure that all Pi have different IDs
	idSet := make(map[string]int)
	for i := 0; i < len(Pi); i++ {
		if Pi[i].ID == "" {
			return Polynomial{}, fmt.Errorf("polynomial %d has empty ID (all polynomials must have non-empty, unique IDs)", i)
		}
		if prevIdx, exists := idSet[Pi[i].ID]; exists {
			return Polynomial{}, fmt.Errorf("polynomial %d has duplicate ID %q (same as polynomial %d)", i, Pi[i].ID, prevIdx)
		}
		idSet[Pi[i].ID] = i
	}

	// Handle leaf case: Q is a constant
	if Q.IsLeaf {
		coeffs := make([]koalabear.Element, targetSize)
		coeffs[0] = Q.Constant
		return NewPolynomial(coeffs, WithID(config.OutputName))
	}

	// Determine number of variables Q expects, and ensure it matches the number of input polynomials
	numVars := Q.NumVars()
	if numVars != len(Pi) {
		return Polynomial{}, fmt.Errorf("Q expects %d variables, but %d input polynomials provided",
			numVars, len(Pi))
	}

	// Compute the degree of the resulting polynomial
	// For polynomial composition, if Q has degree d and we substitute each variable
	// with a polynomial of degree d_i (all equal), the result has degree d * d_i
	qDegree := Q.Degree()
	if qDegree == sym.NegInf {
		// Q is the zero polynomial, result is zero
		coeffs := make([]koalabear.Element, targetSize)
		return NewPolynomial(coeffs, WithID(config.OutputName))
	}

	// All input polynomials have the same degree (targetDegree)
	// Result degree is Q's degree times the input polynomial degree
	resultDegree := qDegree * targetDegree
	if resultDegree < 0 {
		resultDegree = 0
	}

	// Domain size must be at least resultDegree + 1, rounded up to power of 2.
	// If WithDomainSize was specified, use that instead (e.g. when computing mod X^N-1).
	var domainSize int
	if config.DomainSize > 0 {
		domainSize = config.DomainSize
		if domainSize < targetSize {
			domainSize = targetSize
		}
	} else {
		domainSize = nextPowerOfTwo(resultDegree + 1)
		if domainSize < targetSize {
			domainSize = targetSize
		}
	}

	// Create domain for the computation
	domain := fft.NewDomain(uint64(domainSize))

	// Transform all Pi to Lagrange shifted basis on the same domain
	// Make copies to avoid modifying the originals
	PiCopies := make([]*Polynomial, len(Pi))
	for i := 0; i < len(Pi); i++ {
		// Create a copy
		coeffsCopy := make([]koalabear.Element, len(Pi[i].EP.Coefficients))
		copy(coeffsCopy, Pi[i].EP.Coefficients)

		PiCopies[i] = &Polynomial{
			EP: &EPolynomial{
				Coefficients: coeffsCopy,
				Basis:        Pi[i].EP.Basis,
				Layout:       Pi[i].EP.Layout,
				Degree:       Pi[i].EP.Degree,
			},
			ID:    Pi[i].ID,
			Shift: Pi[i].Shift,
		}

		// Pad to domain size if needed
		if len(PiCopies[i].EP.Coefficients) < domainSize {
			// Padding with zeros only works correctly in Canonical basis with Normal layout
			// If not in Canonical basis, convert first
			if PiCopies[i].EP.Basis != Canonical {
				// Need to convert to Canonical basis before padding
				// Create a domain for the current size
				currentSize := len(PiCopies[i].EP.Coefficients)
				currentDomain := fft.NewDomain(uint64(currentSize))
				if err := PiCopies[i].ToBasis(currentDomain, Canonical); err != nil {
					return Polynomial{}, fmt.Errorf("failed to convert polynomial %d to Canonical for padding: %w", i, err)
				}
			}

			// If in BitReversed layout, convert to Normal first before padding
			if PiCopies[i].EP.Layout == BitReversed {
				PiCopies[i].ToLayout(Normal)
			}

			padded := make([]koalabear.Element, domainSize)
			copy(padded, PiCopies[i].EP.Coefficients)
			PiCopies[i].EP.Coefficients = padded
		}

		// Convert to LagrangeShifted basis, so it avoids the vanishing sets of the form X^n-1 where n is a power of two, which is important for ComputeQuotient
		if err := PiCopies[i].ToBasis(domain, LagrangeShifted); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert polynomial %d to LagrangeShifted: %w", i, err)
		}
	}

	// Determine the layout of the result (matches the layout of PiCopies after conversion)
	// After ToLagrangeShifted, the layout depends on input layout and will alternate
	// For simplicity, normalize all to the same layout before pointwise evaluation
	resultLayout := config.ResultLayout
	if len(PiCopies) > 0 {
		// Ensure all have the same layout for consistent pointwise evaluation
		for i := 0; i < len(PiCopies); i++ {
			if PiCopies[i].EP.Layout != resultLayout {
				// Normalize to Normal layout
				for j := 0; j < len(PiCopies); j++ {
					PiCopies[j].ToLayout(Normal)
				}
				resultLayout = Normal
				break
			}
		}
	}

	// Create result polynomial R in Lagrange shifted basis
	ER := &EPolynomial{
		Coefficients: make([]koalabear.Element, domainSize),
		Basis:        LagrangeShifted,
		Layout:       resultLayout,
		Degree:       0, // Will be computed after converting to canonical
	}

	// Evaluate Q pointwise: for each evaluation point in the domain
	// R[i] = Q(P0[i], P1[i], ..., Pn[i])
	for i := 0; i < domainSize; i++ {
		// Gather values from each polynomial at point i
		values := make([]koalabear.Element, numVars)
		for j := 0; j < numVars && j < len(PiCopies); j++ {
			values[varindex[PiCopies[j].ID]] = PiCopies[j].GetCoefficient(i)
		}

		// Evaluate Q at these values
		ER.Coefficients[i] = Q.Eval(values)
	}

	// Transform R to the desired basis
	if config.ResultBasis == Canonical {
		if err := ER.toCanonical(domain); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert to canonical basis: %w", err)
		}
	} else if config.ResultBasis == Lagrange {
		if err := ER.toLagrange(domain); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert to Lagrange basis: %w", err)
		}
	}
	// If ResultBasis is LagrangeShifted, R is already in the right basis

	// Ensure the desired layout
	if config.ResultLayout == Normal && ER.Layout != Normal {
		ER.toNormal()
	} else if config.ResultLayout == BitReversed && ER.Layout != BitReversed {
		ER.toBitReversed()
	}

	var R Polynomial
	R.EP = ER
	R.ID = config.OutputName

	return R, nil
}
