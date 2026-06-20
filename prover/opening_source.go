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

package prover

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/fri/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
)

type commitmentOpeningSource struct {
	fullDomainSize int
	base           []poly.Polynomial
	ext            []poly.ExtPolynomial
}

func newCommitmentOpeningSource(base []poly.Polynomial, ext []poly.ExtPolynomial, N int) commitmentOpeningSource {
	return commitmentOpeningSource{
		fullDomainSize: int(constants.RATE) * N,
		base:           append([]poly.Polynomial(nil), base...),
		ext:            append([]poly.ExtPolynomial(nil), ext...),
	}
}

func (s *commitmentOpeningSource) setFullDomainSize(N int) {
	s.fullDomainSize = int(constants.RATE) * N
}

func (s *commitmentOpeningSource) setBase(polyIdx int, p poly.Polynomial) {
	if len(s.base) <= polyIdx {
		s.base = append(s.base, make([]poly.Polynomial, polyIdx+1-len(s.base))...)
	}
	s.base[polyIdx] = p
}

func (s *commitmentOpeningSource) setExt(polyIdx int, p poly.ExtPolynomial) {
	if len(s.ext) <= polyIdx {
		s.ext = append(s.ext, make([]poly.ExtPolynomial, polyIdx+1-len(s.ext))...)
	}
	s.ext[polyIdx] = p
}

func (s commitmentOpeningSource) rawLeaf(pos int, leafCount int, domainCache *poly.DomainCache) ([]commitment.PairBase, []commitment.PairExt, error) {
	if s.fullDomainSize == 0 {
		return nil, nil, fmt.Errorf("missing opening source")
	}
	if s.fullDomainSize != 2*leafCount {
		return nil, nil, fmt.Errorf("opening source full domain size %d does not match leaf count %d", s.fullDomainSize, leafCount)
	}
	fullDomain := domainCache.Get(uint64(s.fullDomainSize))
	weightCache := make(map[weightKey][]koalabear.Element)

	baseLeaf := make([]commitment.PairBase, len(s.base))
	for i, p := range s.base {
		if len(p) == 0 {
			return nil, nil, fmt.Errorf("missing base polynomial at index %d", i)
		}
		baseLeaf[i][0] = evalBaseOnRoot(p, pos, fullDomain, domainCache, weightCache)
		baseLeaf[i][1] = evalBaseOnRoot(p, pos+leafCount, fullDomain, domainCache, weightCache)
	}

	extLeaf := make([]commitment.PairExt, len(s.ext))
	for i, p := range s.ext {
		if len(p) == 0 {
			return nil, nil, fmt.Errorf("missing extension polynomial at index %d", i)
		}
		extLeaf[i][0] = evalExtOnRoot(p, pos, fullDomain, domainCache, weightCache)
		extLeaf[i][1] = evalExtOnRoot(p, pos+leafCount, fullDomain, domainCache, weightCache)
	}

	return baseLeaf, extLeaf, nil
}

type weightKey struct {
	size      int
	rootIndex int
}

func evalBaseOnRoot(p poly.Polynomial, rootIndex int, fullDomain *fft.Domain, domainCache *poly.DomainCache, weightCache map[weightKey][]koalabear.Element) koalabear.Element {
	weights := weightsForRoot(len(p), rootIndex, fullDomain, domainCache, weightCache)
	return poly.EvaluateLagrangeWithWeights(p, weights)
}

func evalExtOnRoot(p poly.ExtPolynomial, rootIndex int, fullDomain *fft.Domain, domainCache *poly.DomainCache, weightCache map[weightKey][]koalabear.Element) ext.E6 {
	weights := weightsForRoot(len(p), rootIndex, fullDomain, domainCache, weightCache)
	return poly.ExtEvaluateLagrangeWithWeights(p, weights)
}

func weightsForRoot(size int, rootIndex int, fullDomain *fft.Domain, domainCache *poly.DomainCache, weightCache map[weightKey][]koalabear.Element) []koalabear.Element {
	fullDomainSize := int(fullDomain.Cardinality)
	rootIndex %= fullDomainSize
	if rootIndex < 0 {
		rootIndex += fullDomainSize
	}
	key := weightKey{size: size, rootIndex: rootIndex}
	if weights, ok := weightCache[key]; ok {
		return weights
	}
	weights := poly.LagrangeWeightsOnExtendedDomainRoot(domainCache.Get(uint64(size)), fullDomain, rootIndex)
	weightCache[key] = weights
	return weights
}
