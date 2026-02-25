// /!\ In this package, every inputs polynomials must be in lagrange basis (the inputs come from columns of a trace).

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

	// IsCommitted flag telling if the polynomial has been committed
	IsCommitted bool
}

// Config holds configuration options for EvalPointWise and ComputeQuotient
type PolynomialConfig struct {
	Shift  int
	Layout Layout
	Basis  Basis
}

func NewPolynomialConfig() PolynomialConfig {
	return PolynomialConfig{
		Shift:  0,
		Layout: Normal,
		Basis:  Canonical,
	}
}

// PolynomialOption is a functional option type for configuring EvalPointWise and ComputeQuotient
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
	res.EP, err = NewEPolynomial([]koalabear.Element{value})
	if err != nil {
		return Polynomial{}, err
	}
	res.EP.IsConstant = true
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

	res.EP, err = NewEPolynomial(coeffs)
	res.EP.Basis = config.Basis
	res.EP.Layout = config.Layout
	res.Shift = config.Shift

	// Calculate actual degree
	degree := len(res.EP.Coefficients) - 1
	if res.EP.Basis == Canonical {
		for degree > 0 && coeffs[degree].IsZero() {
			degree--
		}
	}

	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to create EPolynomial: %w", err)
	}

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
	if p.EP.IsConstant {
		return p.EP.Coefficients[0]
	}
	if p.EP.Basis != Canonical {
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

// Copy copies the contents of src Polynomial to dst Polynomial, including coefficients, basis, layout, degree, and shift.
func Copy(dst, src *Polynomial) {
	if dst.EP == nil {
		dst.EP = &EPolynomial{}
	}
	CopyE(dst.EP, src.EP)
	dst.Shift = src.Shift
	dst.IsCommitted = src.IsCommitted
}

// ShallowCopy creates a shallow copy of src Polynomial to dst Polynomial, where dst shares the same underlying EPolynomial as src, but has its own shift value.
func ShallowCopy(dst, src *Polynomial) {
	dst.EP = src.EP // points to the same EPolynomial
	dst.Shift = src.Shift
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

// evalPointWise eval point wise E on Pi, by picking the coefficient direclty (no conversion, no copies).
// internal function only.
// N is the size of the polynomials in Pi, assumed to have all the same size, except the constant (size 1)
// nbVars is the number of variables in E
func evalPointWise(Pi map[string]*Polynomial, E sym.Expr, N int) ([]koalabear.Element, error) {
	varindex := make(sym.VarIndex)
	leaves := sym.RemoveDuplicates(E.Leaves())
	for i, l := range leaves {
		varindex[l] = i
	}
	Q := sym.ToHorner(sym.Convert(E, varindex, len(leaves)))
	resultCoeffs := make([]koalabear.Element, N)
	values := make([]koalabear.Element, len(leaves))
	for i := 0; i < N; i++ {
		for name, idx := range varindex {
			p, ok := Pi[name]
			if !ok {
				return []koalabear.Element{}, fmt.Errorf("polynomial %s not found in Pi", name)
			}
			values[idx] = p.GetCoefficient(i)
		}
		resultCoeffs[i] = Q.Eval(values)
	}
	return resultCoeffs, nil
}

func getRefBasisAndRefLayout(P map[string]*Polynomial) (refBasis Basis, refLayout Layout, allConstants bool) {
	allConstants = true
	for _, k := range P {
		if k.IsConstant() {
			continue
		}
		allConstants = false
		refBasis = k.EP.Basis
		refLayout = k.EP.Layout
		break
	}
	return
}

// ensurePolynomialsAreInLagrange if not all polynomials are in lagrange (except constants),
// it throws an error
func ensurePolynomialsAreInLagrange(P map[string]*Polynomial) error {
	for name, k := range P {
		if k.IsConstant() {
			continue
		}
		if k.EP.Basis != Lagrange {
			return fmt.Errorf("all polynomials must be in lagrange, %s is not in Lagrange basis", name)
		}
	}
	return nil
}

// EvalPointWise computes the resulting polynomial from evaluating a symbolic expression Q at polynomials Pi point wise.
// The Pi are converted in Lagrange basis if they are in canonical form. If they are in LagrangeShifted basis, we leave
// them in this basis.
// The result is in Normal layout
// N: size of the polynomials in P
func EvalPointWise(Pi map[string]*Polynomial, E sym.Expr, N int) (Polynomial, error) {

	resultCoeffs, err := evalPointWise(Pi, E, N)
	if err != nil {
		return Polynomial{}, err
	}

	// The result is in the same basis as the inputs, Normal layout
	result := &EPolynomial{
		Coefficients: resultCoeffs,
		Basis:        Lagrange,
		Layout:       Normal,
		Degree:       N - 1,
	}

	var R Polynomial
	R.EP = result
	return R, nil
}

// DivPointWise computes the resulting polynomial from dividing pointwise.
// N = size of polynomials. All polynomials must be of the same size, same basis, same layout
func DivPointWise(P1, P2 *Polynomial, N int) (Polynomial, error) {

	if !P1.IsConstant() && P1.EP.Basis != Lagrange {
		return Polynomial{}, fmt.Errorf("P1 is not in Lagrange basis")
	}
	if !P2.IsConstant() && P2.EP.Basis != Lagrange {
		return Polynomial{}, fmt.Errorf("P2 is not in Lagrange basis")
	}

	// Make copies of all polynomials and convert non-constant ones to Lagrange basis
	var p1Copy, p2Copy Polynomial
	Copy(&p1Copy, P1)
	Copy(&p2Copy, P2)

	// Build result polynomial pointwise: R[i] = P_1[i] / P_2[i]
	resultCoeffs := make([]koalabear.Element, N)
	for i := 0; i < N; i++ {
		p1i := p1Copy.GetCoefficient(i)
		p2i := p2Copy.GetCoefficient(i)
		if p2i.IsZero() {
			return Polynomial{}, fmt.Errorf("division by zero at index %d", i)
		}
		resultCoeffs[i].Div(&p1i, &p2i)
	}

	// The result is in Lagrange basis, Normal layout
	result := &EPolynomial{
		Coefficients: resultCoeffs,
		Basis:        Lagrange,
		Layout:       Normal,
		Degree:       N - 1,
	}

	var R Polynomial
	R.EP = result
	return R, nil
}

// AccumulateProducts returns R such that R[i+1] = R[i]*P[i], R[0]=1
// N = size of P
func AccumulateProducts(P *Polynomial, N int) (Polynomial, error) {

	if P.EP.Basis == Canonical {
		return Polynomial{}, fmt.Errorf("cannot accumulate ratios on canonical polynomial: must be in an evaluation basis (shifted or not)")
	}

	// build the result R in lagrange basis of size targetSize such that:
	// R[0] = 1
	// R[i] = R[i-1]*P[i-1] for i > 0
	resultCoeffs := make([]koalabear.Element, N)
	resultCoeffs[0].SetOne()
	for i := 1; i < N; i++ {
		pi := P.GetCoefficient(i - 1)
		resultCoeffs[i].Mul(&resultCoeffs[i-1], &pi)
	}

	result := &EPolynomial{
		Coefficients: resultCoeffs,
		Basis:        P.EP.Basis,
		Layout:       P.EP.Layout,
		Degree:       N - 1,
	}

	var R Polynomial
	R.EP = result
	return R, nil
}

// BuildGrandProduct returns R such that R[0]=1, R[i+1] = R[i] * E[0](P[0][i]) / E[1](P[1][i])
// N = size of the polynomials in P
// Polynomials in P must have the same basis, same layout
func BuildGrandProduct(P [2]map[string]*Polynomial, E [2]sym.Expr, N int) (Polynomial, error) {

	Q0, err := EvalPointWise(P[0], E[0], N)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to evaluate numerator expression: %w", err)
	}

	Q1, err := EvalPointWise(P[1], E[1], N)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to evaluate denominator expression: %w", err)
	}

	// When one side is all-constants, EvalPointWise returns a zero-value basis (Canonical).
	// Align both results to the resolved refBasis/refLayout so DivPointWise can proceed.
	Q0.EP.Basis = Lagrange
	Q0.EP.Layout = Normal
	Q1.EP.Basis = Lagrange
	Q1.EP.Layout = Normal

	// Div is not allowed in the AST (TODO should I allow it?)
	ratio, err := DivPointWise(&Q0, &Q1, N)
	if err != nil {
		return Polynomial{}, fmt.Errorf("failed to compute pointwise ratio: %w", err)
	}

	return AccumulateProducts(&ratio, N)
}

// ComputeQuotientLowMemory particular where E is of degree 4: we don't allocate one big-domain size slice for each
// polynomial in Pi, but instead we put the Pi in 4 lagrange cosets of size N, and populate a single big-domain size
// slice to build the numerator.
func ComputeQuotientLowMemory(Pi map[string]*Polynomial, E sym.Expr, N int, opts ...BuilderOption) (Polynomial, error) {

	err := ensurePolynomialsAreInLagrange(Pi)
	if err != nil {
		return Polynomial{}, err
	}

	config := NewBuilderConfig()
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Degree of E(Pi) is at most E.Degree() * sizePi
	eDeg := E.Degree()
	if eDeg <= 0 {
		return Polynomial{}, fmt.Errorf("expression degree must be at least 1, got %d", eDeg)
	}
	N = nextPowerOfTwo(N)
	bigSize := nextPowerOfTwo(eDeg * N)
	if bigSize%N != 0 {
		return Polynomial{}, fmt.Errorf("big domain size %d is not divisible by vanishing domain size %d", bigSize, N)
	}

	bigDomain := fft.NewDomain(uint64(bigSize))
	smallDomain := fft.NewDomain(uint64(N))

	// Convert Pi to LagrangeShifted on the big domain (avoids zeros of X^N-1)
	piCopies := make(map[string]*Polynomial, len(Pi))
	for name, p := range Pi {
		var pCopy Polynomial
		// pCopy.EP = &EPolynomial{}
		Copy(&pCopy, p)
		err := pCopy.ToBasis(smallDomain, Canonical)
		if err != nil {
			return Polynomial{}, err
		}
		pCopy.ToLayout(Normal) // TODO this stage is not needed for inflating pCopy, ok for the moment
		err = pCopy.ToBasis(bigDomain, LagrangeShifted)
		if err != nil {
			return Polynomial{}, err
		}
		if err := pCopy.ToBasis(bigDomain, LagrangeShifted); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert %s to LagrangeShifted: %w", name, err)
		}
		piCopies[name] = &pCopy
	}

	// Evaluate E pointwise on the shifted big domain
	numerator, err := EvalPointWise(piCopies, E, bigSize)
	if err != nil {
		return Polynomial{}, err
	}

	// Divide by X^N-1 evaluated at each shifted point g*ω_big^i:
	//   (g*ω_big^i)^N - 1 = g^N * (ω_big^N)^i - 1
	// ω_big^N has order bigSize/N, so values repeat with that period.
	var gN koalabear.Element
	gN.Set(&bigDomain.FrMultiplicativeGen)
	gN.Exp(gN, big.NewInt(int64(N)))

	var wN koalabear.Element
	wN.Set(&bigDomain.Generator)
	wN.Exp(wN, big.NewInt(int64(N)))

	var one koalabear.Element
	one.SetOne()

	quotientCoeffs := make([]koalabear.Element, bigSize)
	var omegaNI koalabear.Element
	omegaNI.SetOne()
	for i := 0; i < bigSize; i++ {
		var vanishingI koalabear.Element
		vanishingI.Mul(&gN, &omegaNI)
		vanishingI.Sub(&vanishingI, &one) // g^N * (ω_big^N)^i - 1
		ni := numerator.GetCoefficient(i)
		quotientCoeffs[i].Div(&ni, &vanishingI)
		omegaNI.Mul(&omegaNI, &wN)
	}

	// Build quotient in LagrangeShifted basis, Normal layout
	result := &EPolynomial{
		Coefficients: quotientCoeffs,
		Basis:        LagrangeShifted,
		Layout:       Normal,
		Degree:       bigSize - 1,
	}

	if config.OutputBasis != LagrangeShifted {
		if err := result.ToBasis(bigDomain, config.OutputBasis); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert quotient to %v: %w", config.OutputBasis, err)
		}
	}
	result.ToLayout(config.OutputLayout)

	var R Polynomial
	R.EP = result
	return R, nil

}

// ComputeQuotient computes E(Pi) / (X^N - 1) on a big enough domain.
// It is the caller's responsibility to ensure E(Pi) is divisible by X^N - 1.
// All Pi must be in Lagrange form, as this function is called from the prover, who as access to the trace in Lagrange form.
func ComputeQuotient(Pi map[string]*Polynomial, E sym.Expr, N int, opts ...BuilderOption) (Polynomial, error) {

	err := ensurePolynomialsAreInLagrange(Pi)
	if err != nil {
		return Polynomial{}, err
	}

	config := NewBuilderConfig()
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return Polynomial{}, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Degree of E(Pi) is at most E.Degree() * sizePi
	eDeg := E.Degree()
	if eDeg <= 0 {
		return Polynomial{}, fmt.Errorf("expression degree must be at least 1, got %d", eDeg)
	}
	N = nextPowerOfTwo(N)
	bigSize := nextPowerOfTwo(eDeg * N)
	if bigSize%N != 0 {
		return Polynomial{}, fmt.Errorf("big domain size %d is not divisible by vanishing domain size %d", bigSize, N)
	}

	bigDomain := fft.NewDomain(uint64(bigSize))
	smallDomain := fft.NewDomain(uint64(N))

	// Convert Pi to LagrangeShifted on the big domain (avoids zeros of X^N-1)
	piCopies := make(map[string]*Polynomial, len(Pi))
	for name, p := range Pi {
		var pCopy Polynomial
		// pCopy.EP = &EPolynomial{}
		Copy(&pCopy, p)
		err := pCopy.ToBasis(smallDomain, Canonical)
		if err != nil {
			return Polynomial{}, err
		}
		pCopy.ToLayout(Normal) // TODO this stage is not needed for inflating pCopy, ok for the moment
		err = pCopy.ToBasis(bigDomain, LagrangeShifted)
		if err != nil {
			return Polynomial{}, err
		}
		if err := pCopy.ToBasis(bigDomain, LagrangeShifted); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert %s to LagrangeShifted: %w", name, err)
		}
		piCopies[name] = &pCopy
	}

	// Evaluate E pointwise on the shifted big domain
	numerator, err := EvalPointWise(piCopies, E, bigSize)
	if err != nil {
		return Polynomial{}, err
	}

	// Divide by X^N-1 evaluated at each shifted point g*ω_big^i:
	//   (g*ω_big^i)^N - 1 = g^N * (ω_big^N)^i - 1
	// ω_big^N has order bigSize/N, so values repeat with that period.
	var gN koalabear.Element
	gN.Set(&bigDomain.FrMultiplicativeGen)
	gN.Exp(gN, big.NewInt(int64(N)))

	var wN koalabear.Element
	wN.Set(&bigDomain.Generator)
	wN.Exp(wN, big.NewInt(int64(N)))

	var one koalabear.Element
	one.SetOne()

	quotientCoeffs := make([]koalabear.Element, bigSize)
	var omegaNI koalabear.Element
	omegaNI.SetOne()
	for i := 0; i < bigSize; i++ {
		var vanishingI koalabear.Element
		vanishingI.Mul(&gN, &omegaNI)
		vanishingI.Sub(&vanishingI, &one) // g^N * (ω_big^N)^i - 1
		ni := numerator.GetCoefficient(i)
		quotientCoeffs[i].Div(&ni, &vanishingI)
		omegaNI.Mul(&omegaNI, &wN)
	}

	// Build quotient in LagrangeShifted basis, Normal layout
	result := &EPolynomial{
		Coefficients: quotientCoeffs,
		Basis:        LagrangeShifted,
		Layout:       Normal,
		Degree:       bigSize - 1,
	}

	if config.OutputBasis != LagrangeShifted {
		if err := result.ToBasis(bigDomain, config.OutputBasis); err != nil {
			return Polynomial{}, fmt.Errorf("failed to convert quotient to %v: %w", config.OutputBasis, err)
		}
	}
	result.ToLayout(config.OutputLayout)

	var R Polynomial
	R.EP = result
	return R, nil
}
