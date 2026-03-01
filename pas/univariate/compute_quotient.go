package univariate

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/giop/pas/sym"
)

// ComputeQuotient computes E(PI)/X^N-1
// /!\ all polynomials must be in normal layout, lagrange basis
func ComputeQuotient(Pi map[string]*Polynomial, E sym.Expr, N int, opts ...BuilderOption) (Polynomial, error) {

	err := ensurePolynomialsAreInLagrange(Pi)
	if err != nil {
		return Polynomial{}, err
	}
	err = ensurePolynomialsAreInNormalLayout(Pi)
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

	// we do the evaluation manually (don't use EvalPointWise)
	varindex := make(sym.VarIndex)
	leaves := sym.RemoveDuplicates(E.Leaves(sym.Config{}))
	for i, l := range leaves {
		varindex[l] = i
	}
	Q := sym.ToHorner(sym.Convert(E, varindex, len(leaves)))

	numerator := make([]koalabear.Element, bigSize)

	// copy only the polynomials referenced by E (indexed by varindex).
	// Pi may contain more entries than E.Leaves() (e.g. when the full trace is passed in),
	// so we must NOT use len(Pi) as the slice size — unused slots would remain nil and crash FFTInverse.
	nbPolys := len(leaves)
	PiCopies := make([][]koalabear.Element, nbPolys)
	for _, l := range leaves {
		v := Pi[l]
		PiCopies[varindex[l]] = make([]koalabear.Element, len(v.EP.Coefficients)) // len = N except for constant polynomials
		copy(PiCopies[varindex[l]], v.EP.Coefficients)
	}

	// variables assignment
	x := make([]koalabear.Element, len(leaves))

	// create domains
	bigDomain := fft.NewDomain(uint64(bigSize))
	smallDomain := fft.NewDomain(uint64(N))

	// number of cosets of smalldomain in bigdomain
	rho := bigSize / N

	// create the twiddles of size N (not bigSize):
	// after IFFT(DIF) of size N, output is BitReversed w.r.t. N, so twiddle[bitrev_N(k)] = g^k,
	// i.e. build powers of g then BitReverse with length N.
	twiddleFrMultiplicativeGen := make([]koalabear.Element, N)
	fft.BuildExpTable(bigDomain.FrMultiplicativeGen, twiddleFrMultiplicativeGen)
	fft.BitReverse(twiddleFrMultiplicativeGen)
	twiddleGeneratorBigDomain := make([]koalabear.Element, N)
	fft.BuildExpTable(bigDomain.Generator, twiddleGeneratorBigDomain)
	fft.BitReverse(twiddleGeneratorBigDomain)
	scaleByTwiddles := func(a, b []koalabear.Element) {
		for i := 0; i < N; i++ {
			a[i].Mul(&a[i], &b[i])
		}
	}

	// at this stage, all polynomials in PiCopies are in Lagrange form. We write them in canonical basis, shifted by twiddles[i][0]
	// to prepare the FFT on the cosets (twiddles[i][0] is <bigDomain.FrMultiplicativeGen^i>), used to avoid the zeroes on X^N-1).
	for _, pCopy := range PiCopies {

		if len(pCopy) == 1 { // /!\ polynomials coming from challenges are constants -> the size of coeff is 1 in that case
			continue
		}

		// shift coset manually
		smallDomain.FFTInverse(pCopy, fft.DIF)             // PiCopies[j] bit reversed, canonical
		scaleByTwiddles(pCopy, twiddleFrMultiplicativeGen) // PiCopies[j] are scaled by <bigDomain.FrMultiplicativeGen^i> to avoid zeroes of X^N-1
	}

	// at this stage, all the polynomials c[i] in c are in canonical, bit reverse, scaled by <bigDomain.FrMultiplicativeGen^i>
	for i := 0; i < rho; i++ {

		// evaluate the polys shifted by <bigDomain.FrMultiplicativeGen> on  <bigDomain.Generator^i> -> the result is the polys
		// evaluated on the coset bigDomain.FrMultiplicativeGen*<bigDomain.Generator^i>
		for _, pCopy := range PiCopies {
			if len(pCopy) == 1 { // /!\ polynomials coming from challenges are constants -> the size of coeff is 1 in that case
				continue
			}
			// shift coset manually
			smallDomain.FFT(pCopy, fft.DIT) // PiCopies[j] bit reversed, canonical
		}

		// at this stage, the polys are evaluated on bigDomain.FrMultiplicativeGen*<bigDomain.Generator^i>. We can compute the rho-ith
		// component of the numerator
		for j := 0; j < N; j++ {
			for k, pCopy := range PiCopies { // assign variables
				if len(pCopy) == 1 { // /!\ polynomials coming from challenges are constants -> the size of coeff is 1 in that case
					x[k].Set(&pCopy[0])
					continue
				}
				x[k].Set(&pCopy[j])
			}
			numerator[rho*j+i] = Q.Eval(x)
		}

		// FFTInv on PiCopies -> the PiCopies become in canonical, the k-th coeffs are shifted by bigDomain.FrMultiplicativeGen^k*<bigDomain.Generator^ik>
		for _, pCopy := range PiCopies {
			if len(pCopy) == 1 { // /!\ polynomials coming from challenges are constants -> the size of coeff is 1 in that case
				continue
			}
			// shift coset manually
			smallDomain.FFTInverse(pCopy, fft.DIF)            // PiCopies[j] bit reversed, canonical
			scaleByTwiddles(pCopy, twiddleGeneratorBigDomain) // the k-th coeffs are now shifted by bigDomain.FrMultiplicativeGen^k*<bigDomain.Generator^(i+1)k>
		}
	}

	// X^N-1 evaluated at coset representative FrGen·bigDomain.Generator^i:
	//   (FrGen·bigDomain.Generator^i)^N = FrGen^N · (bigDomain.Generator^N)^i
	// bigDomain.Generator^N has order rho, so only rho distinct values.
	// numerator[rho*j+i] was evaluated on coset i, so it must be divided by xnMinusOne[i].
	xnMinusOne := make([]koalabear.Element, rho)
	one := koalabear.One()
	var gn, frn koalabear.Element
	NBigInt := big.NewInt(int64(N))
	frn.Exp(bigDomain.FrMultiplicativeGen, NBigInt) // FrGen^N
	gn.Exp(bigDomain.Generator, NBigInt)            // bigDomain.Generator^N, has order rho
	accgn := koalabear.One()
	for i := 0; i < rho; i++ {
		xnMinusOne[i].Mul(&frn, &accgn).Sub(&xnMinusOne[i], &one) // FrGen^N · gn^i - 1
		accgn.Mul(&accgn, &gn)
	}

	// do the division
	for i := 0; i < bigSize; i++ {
		numerator[i].Div(&numerator[i], &xnMinusOne[i%rho])
	}

	// Build quotient in LagrangeShifted basis, Normal layout
	result := &EPolynomial{
		Coefficients: numerator,
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
