package dummycommitment

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
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

	// TODO when the wrapper is done (for instance, KZG) make a trivial opening if p is constant

	// build the proof
	y, err := p.Evaluate(point)
	if err != nil {
		return OpeningProof{}, err
	}
	res := OpeningProof{
		ClaimedValue: y,
	}
	return res, nil
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
