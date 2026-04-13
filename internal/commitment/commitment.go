package commitment

import (
	"crypto/sha256"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

type RSCommit struct {
	Encoder    reedsolomon.Encoder
	LeafHasher merkle.LeafHasher
	NodeHasher merkle.NodeHasher
}

func NewRSCommit(N uint64, leafHasher merkle.LeafHasher, nodehasher merkle.NodeHasher) RSCommit {
	d := fft.NewDomain(N)
	rsEncoder := reedsolomon.Encoder{Domain: d}
	return RSCommit{
		Encoder:    rsEncoder,
		LeafHasher: leafHasher,
		NodeHasher: nodehasher,
	}
}

func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Commit to the polynomials p. The polynomials in p are assumed to be in Lagrange form, and might be of
// different sizes. It is assumed that the maximum size is < rs.N
func (rs *RSCommit) Commit(p []poly.Polynomial, rsEncoder *reedsolomon.Encoder, maxSize int) (*merkle.Tree, error) {

	domainsPool := map[int]*fft.Domain{}

	// 1- encode every polynomial
	_p := make([]poly.Polynomial, len(p))
	for i, pol := range p {
		n := len(pol)
		_, ok := domainsPool[n]
		if !ok {
			d := fft.NewDomain(uint64(n))
			domainsPool[n] = d
		}
		d := domainsPool[n]
		_p[i] = rs.Encoder.Encode(pol, d)
	}

	// 2- build the merkle tree, whose i-th leaf is the vector of the i-th entries of the encoded polynomials
	N := rs.Encoder.Domain.Cardinality
	tree, err := merkle.New(int(N), LeafHash, NodeHash)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, koalabear.Bytes*len(_p))
	for i := 0; i < int(N); i++ {
		for j := 0; j < len(_p); i++ {
			copy(buf[j*koalabear.Bytes:], _p[j][i].Marshal())
		}
		tree.BuildIthLeaf(buf, i)
	}
	tree.BuildNodes()

	return tree, nil
}
