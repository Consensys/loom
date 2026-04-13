package reedsolomon

import (
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/internal/poly"
)

func NewRSEncoder(N uint64) RSEncoder {
	domain := fft.NewDomain(N)
	return RSEncoder{
		Domain: domain,
	}
}

type RSEncoder struct {
	Domain *fft.Domain
}

// RSEncode evalutes p on the N-th roots of unity (N must be > len(p))
// p is in Lagrange form
// it returns a copy of p
func (res *RSEncoder) Encode(p poly.Polynomial, d *fft.Domain, N int) poly.Polynomial {

	// get the size of p
	n := len(p)

	// create _p, a copy of p of size N (zero-padded)
	_p := make(poly.Polynomial, N)
	copy(_p, p)

	// compute fftinv(_p[:n]) using d (d must be of the size of p)
	// Lagrange normal → canonical bit-reversed (w.r.t. n); then un-reverse to canonical normal
	d.FFTInverse(_p[:n], fft.DIF)
	utils.BitReverse(_p[:n])

	// compute fft(_p) using the RSencoder domain
	// canonical normal (zero-padded to N) → Lagrange bit-reversed (w.r.t. N) → Lagrange normal
	res.Domain.FFT(_p, fft.DIF)
	utils.BitReverse(_p)

	// return _p
	return _p
}
