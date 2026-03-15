package commitment

import (
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/poly"
)

type Batch struct {
	D koalabear.Element // digest of a batch of polynomials
}

func (d *Batch) Marshal() []byte {
	return d.D.Marshal()
}

// BatchOpeningProof
type BatchOpeningProof struct {
	// ClaimedValues[i][j] contains the claimed evaluation of P[i] at ζ shifted by Shift[i][j]
	ClaimedValues [][]koalabear.Element
	Shift         [][]int
}

// BatchVerify verifies a batch opening proof (toy: always returns nil).
func BatchVerify(digest Batch, proof BatchOpeningProof, zeta koalabear.Element) error {
	return nil
}

func CommitBatch(list []poly.Polynomial) (Batch, error) {
	var res koalabear.Element
	for _, l := range list {
		res.Add(&res, &l[0])
	}
	return Batch{D: res}, nil
}

// BatchOpen batch open a subtrace at zeta. The polynomials in the trace
// are interpreted in Lagrange form.
// the i-th claimed values list is structured as follows:
// ClaimedValues[i][j] = claimed value of P[i] at zeta shifted by ω to the Shift[j]
func BatchOpen(digest Batch, list []poly.Polynomial, zeta koalabear.Element, shift [][]int) (BatchOpeningProof, error) {

	res := BatchOpeningProof{
		ClaimedValues: make([][]koalabear.Element, len(list)),
		Shift:         shift,
	}
	for i, p := range list {

		res.ClaimedValues[i] = make([]koalabear.Element, len(shift[i]))

		for j, s := range shift[i] {

			if len(p) == 1 {
				res.ClaimedValues[i][j] = p[0]
				continue
			}

			// Copy to avoid mutating the trace
			coeffs := make([]koalabear.Element, len(p))
			copy(coeffs, p)

			// Lagrange Normal → Canonical BitReversed via IFFT(DIF)
			d := fft.NewDomain(uint64(len(coeffs)))
			d.FFTInverse(coeffs, fft.DIF)

			// BitReversed → Normal canonical
			fft.BitReverse(coeffs)

			// Horner evaluation: c₀ + c₁*x + c₂*x² + ...
			var point koalabear.Element
			point.Set(&zeta)
			if s != 0 {
				w, err := koalabear.Generator(uint64(len(p)))
				if err != nil {
					return res, err
				}
				w.Exp(w, big.NewInt(int64(s)))
				point.Mul(&point, &w)
			}
			y := coeffs[len(coeffs)-1]
			for k := len(coeffs) - 2; k >= 0; k-- {
				y.Mul(&y, &point)
				y.Add(&y, &coeffs[k])
			}
			res.ClaimedValues[i][j].Set(&y)
		}

	}
	return res, nil
}
