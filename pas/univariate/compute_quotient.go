package univariate

import (
	"fmt"
	"math/big"

	"github.com/consensys/giop/pas/dag"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
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

	// Collect unique non-Const leaves, set Leaf.Idx, and pair each with its
	// base polynomial copy. A ShiftedColumn and its base CommittedColumn share
	// the same backing slice (baseCopies keyed by l.Name); only one copy and
	// one FFT pass is needed per base column.
	type leafSlot struct {
		leaf *sym.Leaf
		poly []koalabear.Element
	}
	type varKey struct{ name string; shift int }
	varToIdx := make(map[varKey]int)
	baseCopies := make(map[string][]koalabear.Element)
	var slots []leafSlot
	for _, n := range vanishingRelation.Nodes {
		if n.Kind != dag.KindLeaf {
			continue
		}
		l := n.Leaf.(*sym.Leaf)
		if l.Type == sym.Const {
			continue // EvaluateWithIdx returns l.Value directly; no slot needed
		}
		key := varKey{l.Name, l.Shift}
		if idx, ok := varToIdx[key]; ok {
			l.Idx = idx
			continue
		}
		l.Idx = len(slots)
		varToIdx[key] = l.Idx
		if _, ok := baseCopies[l.Name]; !ok {
			v := Pi[l.Name]
			coeffs := make([]koalabear.Element, len(v))
			copy(coeffs, v)
			baseCopies[l.Name] = coeffs
		}
		slots = append(slots, leafSlot{leaf: l, poly: baseCopies[l.Name]})
	}

	// piNonConst: unique non-constant polynomial slices for FFT (one per base column).
	piNonConst := make([][]koalabear.Element, 0, len(baseCopies))
	for _, poly := range baseCopies {
		if len(poly) > 1 {
			piNonConst = append(piNonConst, poly)
		}
	}

	// Pre-fill vals for size-1 polynomials (challenges); they never change across rows.
	vals := make([]koalabear.Element, len(slots))
	for _, s := range slots {
		if len(s.poly) == 1 {
			vals[s.leaf.Idx] = s.poly[0]
		}
	}

	numerator := make([]koalabear.Element, bigSize)

	// eval cache (reused across all inner-loop iterations)
	evalCache := make([]koalabear.Element, len(vanishingRelation.Nodes))

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
	for _, pCopy := range piNonConst {
		// shift coset manually
		smallDomain.FFTInverse(pCopy, fft.DIF)             // pCopy: bit reversed, canonical
		scaleByTwiddles(pCopy, twiddleFrMultiplicativeGen) // pCopy: scaled by <bigDomain.FrMultiplicativeGen^i> to avoid zeroes of X^N-1
	}

	// at this stage, all the polynomials c[i] in c are in canonical, bit reverse, scaled by <bigDomain.FrMultiplicativeGen^i>
	for i := 0; i < rho; i++ {

		// evaluate the polys shifted by <bigDomain.FrMultiplicativeGen> on  <bigDomain.Generator^i> -> the result is the polys
		// evaluated on the coset bigDomain.FrMultiplicativeGen*<bigDomain.Generator^i>
		for _, pCopy := range piNonConst {
			smallDomain.FFT(pCopy, fft.DIT) // pCopy: evaluated on coset i
		}

		// at this stage, the polys are evaluated on bigDomain.FrMultiplicativeGen*<bigDomain.Generator^i>. We can compute the rho-ith
		// component of the numerator
		for j := 0; j < N; j++ {
			for _, s := range slots {
				if len(s.poly) == 1 {
					continue // challenge: already set
				}
				if s.leaf.Type == sym.ShiftedColumn {
					vals[s.leaf.Idx] = s.poly[((j+s.leaf.Shift)%N+N)%N]
				} else {
					vals[s.leaf.Idx] = s.poly[j]
				}
			}
			numerator[rho*j+i] = vanishingRelation.EvalWithIdx(vals, evalCache)
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
	for i := 0; i < rho; i++ {
		xnMinusOne[i].Mul(&frn, &accgn).Sub(&xnMinusOne[i], &one) // FrGen^N · gn^i - 1
		accgn.Mul(&accgn, &gn)
	}

	// do the division
	for i := 0; i < bigSize; i++ {
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
	fft.BitReverse(p)

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
	fft.BitReverse(p)
}
