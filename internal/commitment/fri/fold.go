package fri

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
)

// foldCoset computes the FRI k-way fold at a single coset.
//
// cosetValues[t] = g(ω^(j + t·(N/k))) for t = 0..k-1, where N is the current
// layer's domain size. alpha is the verifier's folding challenge. cosetBase is
// the field element ω^j (the base point of this coset in the domain). kDomain
// is a pre-built FFT domain of size k whose Generator is a primitive k-th root
// of unity η.
//
// The function:
//  1. Finds the unique degree-<k polynomial p_j satisfying p_j(η^t) = cosetValues[t].
//  2. Returns p_j(alpha / cosetBase).
func foldCoset(cosetValues []koalabear.Element, alpha, cosetBase koalabear.Element, kDomain *fft.Domain) koalabear.Element {
	k := len(cosetValues)
	coeffs := make([]koalabear.Element, k)
	copy(coeffs, cosetValues)

	// IDFT over {η^0, η^1, …, η^{k-1}}: coeffs[s] such that Σ_s coeffs[s]·η^(s·t) = cosetValues[t].
	kDomain.FFTInverse(coeffs, fft.DIF)
	utils.BitReverse(coeffs)

	// Evaluate p_j at alpha / cosetBase using Horner's method.
	var invBase koalabear.Element
	invBase.Inverse(&cosetBase)
	var evalAt koalabear.Element
	evalAt.Mul(&alpha, &invBase)

	var result koalabear.Element
	for i := k - 1; i >= 0; i-- {
		result.Mul(&result, &evalAt)
		result.Add(&result, &coeffs[i])
	}
	return result
}

// foldLayer performs one round of k-way FRI folding on codeword g.
//
// g has size N (evaluations on the N-th roots of unity). domainGen is the
// generator ω of the current layer's domain (ω^N = 1). k is the folding factor
// (must be a power of 2 and ≤ N). Returns the folded codeword of size N/k.
func foldLayer(g []koalabear.Element, alpha, domainGen koalabear.Element, k int) []koalabear.Element {
	N := len(g)
	nOut := N / k
	kDomain := fft.NewDomain(uint64(k))

	// Precompute ω^j for j = 0..nOut-1 by consecutive multiplication.
	omegaJ := make([]koalabear.Element, nOut)
	omegaJ[0].SetOne()
	for j := 1; j < nOut; j++ {
		omegaJ[j].Mul(&omegaJ[j-1], &domainGen)
	}

	out := make([]koalabear.Element, nOut)
	coset := make([]koalabear.Element, k)
	for j := 0; j < nOut; j++ {
		// Coset at leaf j: positions {j, j+nOut, j+2·nOut, …, j+(k-1)·nOut}.
		for t := 0; t < k; t++ {
			coset[t] = g[j+t*nOut]
		}
		out[j] = foldCoset(coset, alpha, omegaJ[j], kDomain)
	}
	return out
}

// elementPow computes base^exp using square-and-multiply.
func elementPow(base koalabear.Element, exp int) koalabear.Element {
	var result koalabear.Element
	result.SetOne()
	for exp > 0 {
		if exp&1 == 1 {
			result.Mul(&result, &base)
		}
		base.Mul(&base, &base)
		exp >>= 1
	}
	return result
}
