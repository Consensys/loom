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
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

const (
	leafDomainTag uint64 = 0x4c454146 // "LEAF"
	nodeDomainTag uint64 = 0x4e4f4445 // "NODE"
)

type LeafHash = hash.HashOutput
type NodeHash = hash.HashOutput

type LeafHasher interface {
	HashLeaf(base []PairBase, ext []PairExt) hash.HashOutput
}

type NodeHasher interface {
	HashNode(left, right hash.HashOutput) hash.HashOutput
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

func (wt WMerkleTree) Root() hash.HashOutput {
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

func (Poseidon2LeafHasher) HashLeaf(base []PairBase, ext []PairExt) hash.HashOutput {
	h := hash.NewPoseidon2MDHasher()
	h.WriteElements(hash.NewElement(leafDomainTag), hash.NewElement(uint64(len(base))), hash.NewElement(uint64(len(ext))))
	for _, pair := range base {
		h.WriteElements(pair[0], pair[1])
	}
	for _, pair := range ext {
		h.WriteExt(pair[0], pair[1])
	}
	return h.Sum()
}

func (Poseidon2NodeHasher) HashNode(left, right hash.HashOutput) hash.HashOutput {
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
	baseLeaf := make([]PairBase, len(encodedBase))
	extLeaf := make([]PairExt, len(encodedExt))
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
		if err := tree.BuildIthLeaf(rs.LeafHasher.HashLeaf(baseLeaf, extLeaf), i); err != nil {
			return WMerkleTree{}, err
		}
	}
	tree.BuildNodes()

	return wTree, nil
}
