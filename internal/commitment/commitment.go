package commitment

import (
	"github.com/consensys/giop/internal/poly"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

// dummycommitment should wrap an existing commitment

// Digest dummy hash of polynomial
type Digest struct {
	D koalabear.Element
}

func (d *Digest) Marshal() []byte {
	return d.D.Marshal()
}

type OpeningProof struct {
	Shift        int
	ClaimedValue koalabear.Element
}

// Commit commits to a polynomial (first evaluation as dummy hash)
func Commit(p poly.Polynomial) (Digest, error) {
	return Digest{p[0]}, nil
}

// Open evaluates the polynomial (in Lagrange Normal basis) at the given point.
func Open(p poly.Polynomial, point koalabear.Element) (OpeningProof, error) {
	if len(p) == 1 {
		return OpeningProof{ClaimedValue: p[0]}, nil
	}

	// Copy to avoid mutating the trace
	coeffs := make([]koalabear.Element, len(p))
	copy(coeffs, p)

	// Lagrange Normal → Canonical BitReversed via IFFT(DIF)
	d := fft.NewDomain(uint64(len(coeffs)))
	d.FFTInverse(coeffs, fft.DIF)

	// BitReversed → Normal canonical
	fft.BitReverse(coeffs)

	// Horner evaluation: c_0 + c_1*x + c_2*x^2 + ...
	y := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		y.Mul(&y, &point)
		y.Add(&y, &coeffs[i])
	}

	return OpeningProof{ClaimedValue: y}, nil
}

// Verify verifies a KZG opening proof at a single point
func Verify(commitment Digest, proof OpeningProof, point koalabear.Element) error {
	return nil
}

type PackedProof struct {
	Digest       Digest
	OpeningProof []OpeningProof
}
