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
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/parallel"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

const (
	leafDomainTag uint64 = 0x4c454146 // "LEAF"
	nodeDomainTag uint64 = 0x4e4f4445 // "NODE"
)

type LeafHash = hash.Digest
type NodeHash = hash.Digest

type LeafHasher interface {
	HashLeaf(base []PairBase, ext []PairExt) hash.Digest
}

// LeafSource describes the column-oriented data used to build paired Merkle
// leaves. Leaf i absorbs values at i and i+PairOffset for every base and
// extension polynomial.
type LeafSource struct {
	Base       []poly.Polynomial
	Ext        []poly.ExtPolynomial
	PairOffset int
}

// BatchLeafHasher hashes a consecutive range of leaves into dst. HashLeaf
// remains the compatibility path and the source of truth for single-leaf
// verifier checks.
type BatchLeafHasher interface {
	LeafHasher
	HashLeaves(dst []hash.Digest, src LeafSource, start int)
}

type NodeHasher interface {
	HashNode(left, right hash.Digest) hash.Digest
}

type Poseidon2LeafHasher struct{}

type Poseidon2NodeHasher struct{}

var (
	DefaultLeafHasher Poseidon2LeafHasher
	DefaultNodeHasher Poseidon2NodeHasher
)

type RSCommit struct {
	Encoder    reedsolomon.Encoder
	LeafHasher LeafHasher
	NodeHasher NodeHasher
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

func (wt WMerkleTree) Root() hash.Digest {
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

func NewRSCommit(N uint64, rate uint64, leafHasher LeafHasher, nodehasher NodeHasher) RSCommit {
	return NewRSCommitWithDomainCache(N, rate, leafHasher, nodehasher, nil)
}

// NewRSCommitWithDomainCache constructs an RSCommit using cache for the
// Reed-Solomon encoder domain.
func NewRSCommitWithDomainCache(N uint64, rate uint64, leafHasher LeafHasher, nodehasher NodeHasher, cache *poly.DomainCache) RSCommit {
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

func (Poseidon2LeafHasher) HashLeaf(base []PairBase, ext []PairExt) hash.Digest {
	h := hash.NewPoseidon2SpongeHasher()
	h.WriteElements(hash.NewElement(leafDomainTag), hash.NewElement(uint64(len(base))), hash.NewElement(uint64(len(ext))))
	for _, pair := range base {
		h.WriteElements(pair[0], pair[1])
	}
	for _, pair := range ext {
		h.WriteExt(pair[0], pair[1])
	}
	return h.Sum()
}

func (lh Poseidon2LeafHasher) HashLeaves(dst []hash.Digest, src LeafSource, start int) {
	hashLeavesScalar(lh, dst, src, start)
}

func (Poseidon2NodeHasher) HashNode(left, right hash.Digest) hash.Digest {
	h := hash.NewPoseidon2MDHasher()
	h.WriteElements(hash.NewElement(nodeDomainTag))
	h.WriteElements(left[:]...)
	h.WriteElements(right[:]...)
	return h.Sum()
}

// Commit commits to base and extension polynomials in one Merkle tree. Inputs
// are assumed to be in Lagrange form and may have different sizes. Each leaf
// hash absorbs all base pairs followed by all extension pairs.
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
	tree, err := merkle.New(halfN, rs.NodeHasher)
	if err != nil {
		return WMerkleTree{}, err
	}
	wTree := WMerkleTree{
		Tree:      tree,
		numLeaves: halfN,
		baseWidth: len(encodedBase),
		extWidth:  len(encodedExt),
	}
	leaves := make([]hash.Digest, halfN)
	src := LeafSource{
		Base:       encodedBase,
		Ext:        encodedExt,
		PairOffset: halfN,
	}
	if batchHasher, ok := rs.LeafHasher.(BatchLeafHasher); ok {
		parallel.Execute(halfN, func(start, end int) {
			batchHasher.HashLeaves(leaves[start:end], src, start)
		})
	} else {
		parallel.Execute(halfN, func(start, end int) {
			hashLeavesScalar(rs.LeafHasher, leaves[start:end], src, start)
		})
	}

	if err := tree.Build(leaves); err != nil {
		return WMerkleTree{}, err
	}

	return wTree, nil
}

func hashLeavesScalar(lh LeafHasher, dst []hash.Digest, src LeafSource, start int) {
	baseLeaf := make([]PairBase, len(src.Base))
	extLeaf := make([]PairExt, len(src.Ext))
	for k := range dst {
		i := start + k
		if len(src.Base) > 0 {
			for j := range src.Base {
				baseLeaf[j][0].Set(&src.Base[j][i])
				baseLeaf[j][1].Set(&src.Base[j][i+src.PairOffset])
			}
		}
		if len(src.Ext) > 0 {
			for j := range src.Ext {
				extLeaf[j][0].Set(&src.Ext[j][i])
				extLeaf[j][1].Set(&src.Ext[j][i+src.PairOffset])
			}
		}
		dst[k] = lh.HashLeaf(baseLeaf, extLeaf)
	}
}
