package poly

import (
	"fmt"
	"math/big"

	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/internal/dag"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
)

// ComputeQuotient computes E(PI)/X^N-1
// /!\ all polynomials must be in normal layout, lagrange basis
func ComputeQuotient(Pi map[string]Polynomial, vanishingRelation dag.DAG, N int) (Polynomial, error) {

	// Degree of E(Pi) is at most E.Degree() * sizePi
	eDeg := vanishingRelation.Degree()
	if eDeg <= 0 {
		return Polynomial{}, fmt.Errorf("expression degree must be at least 1, got %d", eDeg)
	}
	N = nextPowerOfTwo(N)
	bigSize := nextPowerOfTwo(eDeg * N)
	if bigSize%N != 0 {
		return Polynomial{}, fmt.Errorf("big domain size %d is not divisible by vanishing domain size %d", bigSize, N)
	}

	// Assign Leaf.Idx by column name (shifted and non-shifted versions of the same
	// column share the same index and polynomial; EvalOnIthEntry handles shifts).
	// Copy each base polynomial once so FFT mutations don't affect the caller's trace.
	nameToIdx := make(map[string]int)
	baseCopies := make(map[string][]koalabear.Element)
	for _, n := range vanishingRelation.Nodes {
		if n.Kind != dag.KindLeaf || n.Leaf.Type == expr.ConstantColumn {
			continue
		}
		l := n.Leaf
		if _, ok := nameToIdx[l.Name]; !ok {
			nameToIdx[l.Name] = len(nameToIdx)
			src := Pi[l.Name]
			cp := make([]koalabear.Element, len(src))
			copy(cp, src)
			baseCopies[l.Name] = cp
		}
		l.Idx = nameToIdx[l.Name]
	}

	// _Pi[idx] is the (mutable) copy of the polynomial for that leaf name.
	// The FFT loop mutates these slices in-place; EvalOnIthEntry reads from them.
	_Pi := make([][]koalabear.Element, len(nameToIdx))
	for name, idx := range nameToIdx {
		_Pi[idx] = baseCopies[name]
	}

	// piNonConst: non-constant polynomial slices that need FFT (one per base column).
	piNonConst := make([][]koalabear.Element, 0, len(baseCopies))
	for _, poly := range baseCopies {
		if len(poly) > 1 {
			piNonConst = append(piNonConst, poly)
		}
	}

	numerator := make([]koalabear.Element, bigSize)

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
	utils.BitReverse(twiddleFrMultiplicativeGen)
	twiddleGeneratorBigDomain := make([]koalabear.Element, N)
	fft.BuildExpTable(bigDomain.Generator, twiddleGeneratorBigDomain)
	utils.BitReverse(twiddleGeneratorBigDomain)
	scaleByTwiddles := func(a, b []koalabear.Element) {
		for i := 0; i < N; i++ {
			a[i].Mul(&a[i], &b[i])
		}
	}

	// at this stage, all polynomials in PiCopies are in Lagrange form. We write them in canonical basis, shifted by twiddles[i][0]
	// to prepare the FFT on the cosets (twiddles[i][0] is <bigDomain.FrMultiplicativeGen^i>), used to avoid the zeroes on X^N-1).
	for _, pCopy := range piNonConst {
		// shift coset manually
		smallDomain.FFTInverse(pCopy, fft.DIF)             // pCopy: bit reversed, canonical
		scaleByTwiddles(pCopy, twiddleFrMultiplicativeGen) // pCopy: scaled by <bigDomain.FrMultiplicativeGen^i> to avoid zeroes of X^N-1
	}

	// at this stage, all the polynomials c[i] in c are in canonical, bit reverse, scaled by <bigDomain.FrMultiplicativeGen^i>
	for i := range rho {

		// evaluate the polys shifted by <bigDomain.FrMultiplicativeGen> on  <bigDomain.Generator^i> -> the result is the polys
		// evaluated on the coset bigDomain.FrMultiplicativeGen*<bigDomain.Generator^i>
		for _, pCopy := range piNonConst {
			smallDomain.FFT(pCopy, fft.DIT) // pCopy: evaluated on coset i
		}

		// at this stage, the polys are evaluated on bigDomain.FrMultiplicativeGen*<bigDomain.Generator^i>. We can compute the rho-ith
		// component of the numerator
		for j := 0; j < N; j++ {
			numerator[rho*j+i] = vanishingRelation.EvalOnIthEntry(_Pi, j)
		}

		// FFTInv on piNonConst -> polys become canonical again, k-th coeff shifted by bigDomain.FrMultiplicativeGen^k*<bigDomain.Generator^ik>
		for _, pCopy := range piNonConst {
			smallDomain.FFTInverse(pCopy, fft.DIF)            // pCopy: bit reversed, canonical
			scaleByTwiddles(pCopy, twiddleGeneratorBigDomain) // k-th coeff now shifted by bigDomain.FrMultiplicativeGen^k*<bigDomain.Generator^(i+1)k>
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
	for i := range rho {
		xnMinusOne[i].Mul(&frn, &accgn).Sub(&xnMinusOne[i], &one) // FrGen^N · gn^i - 1
		accgn.Mul(&accgn, &gn)
	}

	// do the division
	for i := range bigSize {
		numerator[i].Div(&numerator[i], &xnMinusOne[i%rho])
	}

	return numerator, nil
}

// CosetLagrangeToLagrangeNormal converts a polynomial from coset-Lagrange Normal form
// (as returned by ComputeQuotient, evaluated on {FrMultiplicativeGen * ω^j}) to
// standard Lagrange Normal form (evaluated on {ω^j}).
// The conversion is in-place.
func CosetLagrangeToLagrangeNormal(p Polynomial) {
	N := uint64(len(p))
	d := fft.NewDomain(N)

	// Step 1: coset-Lagrange Normal → BitReversed IFFT (= c_k * FrGen^k, BitReversed)
	d.FFTInverse(p, fft.DIF)

	// Step 2: BitReverse → Normal order (= c_k * FrGen^k)
	utils.BitReverse(p)

	// Step 3: divide by FrGen^k to get canonical coefficients c_k
	invFrGen := d.FrMultiplicativeGen
	invFrGen.Inverse(&invFrGen)
	acc := koalabear.One()
	for k := range p {
		p[k].Mul(&p[k], &acc)
		acc.Mul(&acc, &invFrGen)
	}

	// Step 4: canonical Normal → Lagrange BitReversed
	d.FFT(p, fft.DIF)

	// Step 5: BitReverse → Lagrange Normal
	utils.BitReverse(p)
}
