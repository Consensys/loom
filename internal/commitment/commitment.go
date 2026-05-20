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

type WMerkleTree struct {
	Tree              *merkle.Tree
	numLeaves         int
	UnhashedLeafsBase [][]PairBase // UnhashedLeafsBase[i][j] = {f_j(w^i), f_j(-w^i)}
	UnhashedLeafsExt  [][]PairExt  // UnhashedLeafsExt[i][j] = {f_j(w^i), f_j(-w^i)}
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

type PairBase = [2]koalabear.Element // used to store the pairs {f_k(w^i), f_k(-w^i)}
type PairExt = [2]ext.E4             // used to store the pairs {f_k(w^i), f_k(-w^i)}

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

// Commit commits to base and extension polynomials in one Merkle tree. Inputs
// are assumed to be in Lagrange form and may have different sizes. Each leaf is
// the byte serialization of all base pairs followed by all extension pairs.
func (rs *RSCommit) Commit(basePolys []poly.Polynomial, extPolys []poly.ExtPolynomial) (WMerkleTree, error) {
	domainsPool := map[int]*fft.Domain{}

	// 1- encode every polynomial on its rail
	encodedBase := make([]poly.Polynomial, len(basePolys))
	for i, pol := range basePolys {
		n := len(pol)
		_, ok := domainsPool[n]
		if !ok {
			d := fft.NewDomain(uint64(n))
			domainsPool[n] = d
		}
		d := domainsPool[n]
		encodedBase[i] = rs.Encoder.Encode(pol, d)
	}

	encodedExt := make([]poly.ExtPolynomial, len(extPolys))
	for i, pol := range extPolys {
		n := len(pol)
		_, ok := domainsPool[n]
		if !ok {
			d := fft.NewDomain(uint64(n))
			domainsPool[n] = d
		}
		d := domainsPool[n]
		encodedExt[i] = rs.Encoder.EncodeExt(pol, d)
	}

	// 2- build the merkle tree, with rs.N/2 leafs
	// the i-th leaf is base pairs followed by extension pairs.
	N := rs.Encoder.Domain.Cardinality
	halfN := int(N >> 1)
	tree, err := merkle.New(halfN, LeafHash, NodeHash)
	if err != nil {
		return WMerkleTree{}, err
	}
	wTree := WMerkleTree{Tree: tree, numLeaves: halfN}
	if len(encodedBase) > 0 {
		wTree.UnhashedLeafsBase = make([][]PairBase, halfN)
	}
	if len(encodedExt) > 0 {
		wTree.UnhashedLeafsExt = make([][]PairExt, halfN)
	}
	leafBuf := make([]byte, rawLeafSizeForWidths(len(encodedBase), len(encodedExt)))
	for i := 0; i < halfN; i++ {
		if len(encodedBase) > 0 {
			wTree.UnhashedLeafsBase[i] = make([]PairBase, len(encodedBase))
			for j := range encodedBase {
				wTree.UnhashedLeafsBase[i][j][0].Set(&encodedBase[j][i])
				wTree.UnhashedLeafsBase[i][j][1].Set(&encodedBase[j][i+halfN])
			}
		}
		if len(encodedExt) > 0 {
			wTree.UnhashedLeafsExt[i] = make([]PairExt, len(encodedExt))
			for j := range encodedExt {
				wTree.UnhashedLeafsExt[i][j][0].Set(&encodedExt[j][i])
				wTree.UnhashedLeafsExt[i][j][1].Set(&encodedExt[j][i+halfN])
			}
		}
		tree.BuildIthLeaf(SerializeRawLeafInto(leafBuf, wTree.baseLeaf(i), wTree.extLeaf(i)), i)
	}
	tree.BuildNodes()

	return wTree, nil
}

func (wt WMerkleTree) baseLeaf(i int) []PairBase {
	if len(wt.UnhashedLeafsBase) == 0 {
		return nil
	}
	return wt.UnhashedLeafsBase[i]
}

func (wt WMerkleTree) extLeaf(i int) []PairExt {
	if len(wt.UnhashedLeafsExt) == 0 {
		return nil
	}
	return wt.UnhashedLeafsExt[i]
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
