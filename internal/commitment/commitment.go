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
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

type RSCommit struct {
	Encoder    reedsolomon.Encoder
	LeafHasher merkle.LeafHasher
	NodeHasher merkle.NodeHasher
}

type WMerkleTree struct {
	Tree *merkle.Tree

	numLeaves int
	baseWidth int
	extWidth  int
}

// PointSampling contains the pair evaluation {f(w^i),f(-w^i)} for batches of
// base and extension polynomials at a given point w^i, where i is
// Proof.LeafIdx.
type WMerkleProof struct {
	RawLeafBase []PairBase
	RawLeafExt  []PairExt
	Proof       merkle.Proof
}

func (wt WMerkleTree) Root() []byte {
	return wt.Tree.Root()
}

func (wt WMerkleTree) NumLeaves() int {
	return wt.numLeaves
}

// BaseWidth returns the number of base-field pairs stored in each leaf.
func (wt WMerkleTree) BaseWidth() int {
	return wt.baseWidth
}

// ExtWidth returns the number of extension-field pairs stored in each leaf.
func (wt WMerkleTree) ExtWidth() int {
	return wt.extWidth
}

// OpenProof returns the Merkle proof for leaf i. Raw leaf values are
// reconstructed by the prover from the committed polynomials when needed.
func (wt WMerkleTree) OpenProof(i int) (merkle.Proof, error) {
	return wt.Tree.OpenProof(i)
}

type PairBase = [2]koalabear.Element // used to store the pairs {f_k(w^i), f_k(-w^i)}
type PairExt = [2]ext.E4             // used to store the pairs {f_k(w^i), f_k(-w^i)}

func NewRSCommit(N uint64, rate uint64, leafHasher merkle.LeafHasher, nodehasher merkle.NodeHasher) RSCommit {
	return NewRSCommitWithDomainCache(N, rate, leafHasher, nodehasher, nil)
}

// NewRSCommitWithDomainCache constructs an RSCommit using cache for the
// Reed-Solomon encoder domain.
func NewRSCommitWithDomainCache(N uint64, rate uint64, leafHasher merkle.LeafHasher, nodehasher merkle.NodeHasher, cache *poly.DomainCache) RSCommit {
	rsEncoder := reedsolomon.NewEncoderWithDomainCache(rate*N, cache)
	return RSCommit{
		Encoder:    rsEncoder,
		LeafHasher: leafHasher,
		NodeHasher: nodehasher,
	}
}

// CommitConfig configures RSCommit.Commit.
type CommitConfig struct {
	DomainCache *poly.DomainCache
}

// CommitOption configures RSCommit.Commit.
type CommitOption func(c *CommitConfig) error

// WithDomainCache reuses cache for input-polynomial FFT domains.
func WithDomainCache(cache *poly.DomainCache) CommitOption {
	return func(c *CommitConfig) error {
		c.DomainCache = cache
		return nil
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

// Commit commits to base and extension polynomials in one Merkle tree. Inputs
// are assumed to be in Lagrange form and may have different sizes. Each leaf is
// the byte serialization of all base pairs followed by all extension pairs.
func (rs *RSCommit) Commit(basePolys []poly.Polynomial, extPolys []poly.ExtPolynomial, opts ...CommitOption) (WMerkleTree, error) {
	var config CommitConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return WMerkleTree{}, err
		}
	}
	domainCache := config.DomainCache
	if domainCache == nil {
		domainCache = &poly.DomainCache{}
	}

	// 1- encode every polynomial on its rail
	encodedBase := make([]poly.Polynomial, len(basePolys))
	for i, pol := range basePolys {
		n := len(pol)
		encodedBase[i] = rs.Encoder.Encode(pol, domainCache.Get(uint64(n)))
	}

	encodedExt := make([]poly.ExtPolynomial, len(extPolys))
	for i, pol := range extPolys {
		n := len(pol)
		encodedExt[i] = rs.Encoder.EncodeExt(pol, domainCache.Get(uint64(n)))
	}

	// 2- build the merkle tree, with rs.N/2 leafs
	// the i-th leaf is base pairs followed by extension pairs.
	N := rs.Encoder.Domain.Cardinality
	halfN := int(N >> 1)
	tree, err := merkle.New(halfN, LeafHash, NodeHash)
	if err != nil {
		return WMerkleTree{}, err
	}
	wTree := WMerkleTree{
		Tree:      tree,
		numLeaves: halfN,
		baseWidth: len(encodedBase),
		extWidth:  len(encodedExt),
	}
	baseLeaf := make([]PairBase, len(encodedBase))
	extLeaf := make([]PairExt, len(encodedExt))
	leafBuf := make([]byte, rawLeafSizeForWidths(len(encodedBase), len(encodedExt)))
	for i := 0; i < halfN; i++ {
		if len(encodedBase) > 0 {
			for j := range encodedBase {
				baseLeaf[j][0].Set(&encodedBase[j][i])
				baseLeaf[j][1].Set(&encodedBase[j][i+halfN])
			}
		}
		if len(encodedExt) > 0 {
			for j := range encodedExt {
				extLeaf[j][0].Set(&encodedExt[j][i])
				extLeaf[j][1].Set(&encodedExt[j][i+halfN])
			}
		}
		tree.BuildIthLeaf(SerializeRawLeafInto(leafBuf, baseLeaf, extLeaf), i)
	}
	tree.BuildNodes()

	return wTree, nil
}

// SerializeRawLeaf encodes a dual-rail Merkle leaf as base pairs followed by
// extension pairs. Extension elements use gnark-crypto's coordinate order:
// B0.A0, B0.A1, B1.A0, B1.A1.
func SerializeRawLeaf(base []PairBase, ext []PairExt) []byte {
	buf := make([]byte, rawLeafSize(base, ext))
	return SerializeRawLeafInto(buf, base, ext)
}

// SerializeRawLeafInto encodes a dual-rail Merkle leaf into buf and returns the
// written slice. It allocates only when cap(buf) is too small.
func SerializeRawLeafInto(buf []byte, base []PairBase, ext []PairExt) []byte {
	size := rawLeafSize(base, ext)
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}
	offset := 0
	for _, pair := range base {
		offset = putBaseElement(buf, offset, &pair[0])
		offset = putBaseElement(buf, offset, &pair[1])
	}
	for _, pair := range ext {
		offset = putExtElement(buf, offset, &pair[0])
		offset = putExtElement(buf, offset, &pair[1])
	}
	return buf
}

func rawLeafSize(base []PairBase, ext []PairExt) int {
	return rawLeafSizeForWidths(len(base), len(ext))
}

func rawLeafSizeForWidths(baseWidth int, extWidth int) int {
	return 2*baseWidth*koalabear.Bytes + 8*extWidth*koalabear.Bytes
}

func putBaseElement(buf []byte, offset int, e *koalabear.Element) int {
	bytes := e.Bytes()
	copy(buf[offset:offset+koalabear.Bytes], bytes[:])
	return offset + koalabear.Bytes
}

func putExtElement(buf []byte, offset int, e *ext.E4) int {
	offset = putBaseElement(buf, offset, &e.B0.A0)
	offset = putBaseElement(buf, offset, &e.B0.A1)
	offset = putBaseElement(buf, offset, &e.B1.A0)
	offset = putBaseElement(buf, offset, &e.B1.A1)
	return offset
}
