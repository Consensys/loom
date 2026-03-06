package univariate

import (
	"fmt"
	"math/big"

	"github.com/consensys/giop/constants"
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

	// we do the evaluation manually (don't use EvalPointWise)
	// Separate regular leaves from shifted leaves
	leavesNormal := sym.RemoveDuplicates(vanishingRelation.Leaves(sym.NewConfig(sym.WithoutShiftedColumns())))
	leavesShifted := sym.RemoveDuplicates(vanishingRelation.Leaves(sym.NewConfig(sym.OnlyShiftedColumns...)))

	numerator := make([]koalabear.Element, bigSize)

	// Copy regular (non-shifted) polynomials. Also ensure base columns of shifted leaves are present.
	PiCopies := make(map[string][]koalabear.Element, len(leavesNormal))
	for _, name := range leavesNormal {
		v := Pi[name]
		coeffs := make([]koalabear.Element, len(v)) // len = N except for constant polynomials
		copy(coeffs, v)
		PiCopies[name] = coeffs
	}

	// Parse shifted leaves and ensure their base columns are in PiCopies
	for _, name := range leavesShifted {
		baseName, _, err := constants.SplitShiftedName(name)
		if err != nil {
			return Polynomial{}, fmt.Errorf("ComputeQuotient: %w", err)
		}
		if _, ok := PiCopies[baseName]; !ok {
			v := Pi[baseName]
			coeffs := make([]koalabear.Element, len(v))
			copy(coeffs, v)
			PiCopies[baseName] = coeffs
		}
	}

	// Build varInfos from DAG.VarIndex: maps variable index → poly slice + shift.
	// This replaces the vals map and shiftedInfo map in the hot inner loop.
	type varInfo struct {
		poly       []koalabear.Element
		shift      int
		skipUpdate bool // true for constants and size-1 (challenge) polynomials
	}
	varInfos := make([]varInfo, len(vanishingRelation.VarIndex))
	vars := make([]koalabear.Element, len(vanishingRelation.VarIndex))
	emptyVals := map[string]koalabear.Element{}
	for _, n := range vanishingRelation.Nodes {
		if n.Kind != dag.KindLeaf {
			continue
		}
		idx := n.VarIdx
		name := n.Leaf.String()

		// Try as regular column in PiCopies
		if poly, ok := PiCopies[name]; ok {
			if len(poly) == 1 {
				vars[idx] = poly[0]
				varInfos[idx].skipUpdate = true
			} else {
				varInfos[idx] = varInfo{poly: poly}
			}
			continue
		}

		// Try as shifted column (name = "baseName_shift_N")
		if baseName, shift, err := constants.SplitShiftedName(name); err == nil {
			if poly, ok := PiCopies[baseName]; ok {
				if len(poly) == 1 {
					vars[idx] = poly[0]
					varInfos[idx].skipUpdate = true
				} else {
					varInfos[idx] = varInfo{poly: poly, shift: shift}
				}
				continue
			}
		}

		// Const leaf: not in PiCopies, evaluate once
		vars[idx] = n.Leaf.Evaluate(emptyVals)
		varInfos[idx].skipUpdate = true
	}

	// piNonConst: unique non-constant poly slices, used for FFT loops.
	// Built from PiCopies (one entry per base column, no duplicates).
	piNonConst := make([][]koalabear.Element, 0, len(PiCopies))
	for _, poly := range PiCopies {
		if len(poly) > 1 {
			piNonConst = append(piNonConst, poly)
		}
	}

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
			// Fill vars using pre-built varInfos (no map ops: pure slice reads/writes)
			for k, vi := range varInfos {
				if vi.skipUpdate {
					continue
				}
				if vi.shift == 0 {
					vars[k] = vi.poly[j]
				} else {
					vars[k] = vi.poly[((j+vi.shift)%N+N)%N]
				}
			}
			numerator[rho*j+i] = vanishingRelation.EvalWithCacheVars(vars, evalCache)
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
