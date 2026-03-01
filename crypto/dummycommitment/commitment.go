package dummycommitment

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/giop/pas/univariate"
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
	ClaimedValue koalabear.Element
}

// Commit commits to a polynomial
func Commit(p *univariate.Polynomial) (Digest, error) {
	p.IsCommitted = true
	return Digest{p.EP.Coefficients[0]}, nil
}

// Open computes an opening proof of polynomial p at given point.
// fft.Domain Cardinality must be larger than p.Degree()
func Open(p univariate.Polynomial, point koalabear.Element) (OpeningProof, error) {

	// Convert to Canonical basis if needed so Evaluate can use Horner's method
	if !p.IsConstant() && p.EP.Basis != univariate.Canonical {
		d := fft.NewDomain(uint64(len(p.EP.Coefficients)))
		if err := p.ToBasis(d, univariate.Canonical); err != nil {
			return OpeningProof{}, err
		}
	}

	y, err := p.Evaluate(point)
	if err != nil {
		return OpeningProof{}, err
	}
	return OpeningProof{ClaimedValue: y}, nil
}

// Verify verifies a KZG opening proof at a single point
func Verify(commitment Digest, proof OpeningProof, point koalabear.Element) error {
	return nil
}

type PackedProof struct {
	Digest       Digest
	OpeningProof OpeningProof
}

func PackProof(d Digest, proof OpeningProof) PackedProof {
	return PackedProof{
		Digest:       d,
		OpeningProof: proof,
	}
}
