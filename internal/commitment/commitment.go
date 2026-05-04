// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

func NewRSCommit(N uint64, rate uint64, leafHasher merkle.LeafHasher, nodehasher merkle.NodeHasher) RSCommit {
	d := fft.NewDomain(rate * N)
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
// the number of leaves is rs.N/2, the i-th leaf is
// ( .., {p_j(w^i), p_j(-w^i)}, {p_j+1(w^i), p_j+1(-w^i)}.. ) that is the concatenation of pairs {p_j(w^i), p_j(-w^i)} for j form 1 to len(p)
func (rs *RSCommit) Commit(p []poly.Polynomial) (*merkle.Tree, error) {

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

	// 2- build the merkle tree, with rs.N/2 leafs
	// the i-th leaf is ( .., {p_j(w^i), p_j(-w^i)}, {p_j+1(w^i), p_j+1(-w^i)}.. )
	N := rs.Encoder.Domain.Cardinality
	halfN := int(N >> 1)
	tree, err := merkle.New(halfN, LeafHash, NodeHash)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2*koalabear.Bytes*len(_p))
	for i := 0; i < halfN; i++ {
		for j := 0; j < len(_p); j++ {
			copy(buf[2*j*koalabear.Bytes:], _p[j][i].Marshal())
			copy(buf[(2*j+1)*koalabear.Bytes:], _p[j][i+halfN].Marshal())
		}
		tree.BuildIthLeaf(buf, i)
	}
	tree.BuildNodes()

	return tree, nil
}
