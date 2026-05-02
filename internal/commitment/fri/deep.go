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

package fri

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/poly"
)

// deepCombineErr is returned when a DEEP evaluation point lands on the codeword domain.
var deepCombineErr = errors.New("fri: DEEP evaluation point is on the codeword domain")

// deepDuplicateErr is returned when a single polynomial is opened at the same point twice.
var deepDuplicateErr = errors.New("fri: duplicate DEEP evaluation point on the same polynomial")

// computeClaimedValue evaluates the polynomial committed in oracle at point z
// using Lagrange interpolation over the codeword domain.
func computeClaimedValue(codeword poly.Polynomial, codewordDomain *fft.Domain, z koalabear.Element) koalabear.Element {
	return poly.Evaluate(codeword, codewordDomain, z)
}

// buildDEEPCombiner constructs the combined DEEP quotient codeword q on L of
// size N. Open requests are grouped per polynomial: for a polynomial f opened
// at points {x_1,…,x_R} with claimed values {y_1,…,y_R}, the per-polynomial
// DEEP quotient is
//
//	Q(X) = (f(X) − I(X)) / Π_k (X − x_k),       I(x_j) = y_j.
//
// Using the partial-fractions identity I(X)/Π_k(X−x_k) = Σ_j w_j/(X−x_j) with
// w_j := y_j / Π_{k≠j}(x_j − x_k), evaluating Q on L costs O(R · N + R²)
// field operations per polynomial, with all inversions batched via
// koalabear.BatchInvert:
//
//	Q(ω^i) = f(ω^i) · [Π_k(ω^i − x_k)]^{-1} − Σ_j w_j · (ω^i − x_j)^{-1}.
//
// The combined codeword is q = Σ_p β^p · Q_p, where p indexes polynomials in
// first-opened order (one β-power per distinct polynomial, regardless of how
// many points it is opened at).
//
// claimedValues[r] holds y_r for each request in registration order (same
// order as openRequests). All oracles must have CodewordDomainSize == N.
func buildDEEPCombiner(
	openRequests []openRequest,
	claimedValues []koalabear.Element,
	oracles []committedOracle,
	beta koalabear.Element,
	N int,
) ([]koalabear.Element, error) {
	q := make([]koalabear.Element, N)
	if len(openRequests) == 0 {
		return q, nil
	}

	// Precompute ω^i for i = 0..N-1.
	domainGen := fft.NewDomain(uint64(N)).Generator
	omegaPows := make([]koalabear.Element, N)
	omegaPows[0].SetOne()
	for i := range N - 1 {
		omegaPows[i+1].Mul(&omegaPows[i], &domainGen)
	}

	// Group requests by (oracleI, name), preserving first-opened order. Each
	// distinct polynomial gets its own DEEP quotient and β-power.
	type polyKey struct {
		oracleI int
		name    string
	}
	order := make([]polyKey, 0)
	groups := make(map[polyKey][]int)
	for r, req := range openRequests {
		k := polyKey{req.oracleI, req.name}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}

	// Sort order canonically so β-powers are independent of Open call ordering.
	slices.SortFunc(order, func(a, b polyKey) int {
		if a.oracleI != b.oracleI {
			return cmp.Compare(a.oracleI, b.oracleI)
		}
		return cmp.Compare(a.name, b.name)
	})

	var betaPow koalabear.Element
	betaPow.SetOne()

	for _, key := range order {
		rs := groups[key]
		R := len(rs)
		xs := make([]koalabear.Element, R)
		ys := make([]koalabear.Element, R)
		for j, r := range rs {
			xs[j] = openRequests[r].point
			ys[j] = claimedValues[r]
		}
		// Reject duplicates within this polynomial.
		for j := range R {
			for k := j + 1; k < R; k++ {
				if xs[j].Equal(&xs[k]) {
					return nil, fmt.Errorf("%w: polynomial %q opened at the same point twice", deepDuplicateErr, key.name)
				}
			}
		}

		weights, err := computeBarycentricWeights(xs, ys)
		if err != nil {
			return nil, err
		}

		// prodDenoms[i] = Π_k (ω^i − x_k); error if any factor is zero.
		prodDenoms := make([]koalabear.Element, N)
		for i := range N {
			prodDenoms[i].SetOne()
		}
		var diff koalabear.Element
		for k := range R {
			for i := range N {
				diff.Sub(&omegaPows[i], &xs[k])
				if diff.IsZero() {
					return nil, deepCombineErr
				}
				prodDenoms[i].Mul(&prodDenoms[i], &diff)
			}
		}
		invProdDenoms := koalabear.BatchInvert(prodDenoms)

		// Per-pole denominators (ω^i − x_j) for j < R, i < N. Already shown
		// non-zero in the prodDenoms pass above.
		poleDenoms := make([]koalabear.Element, R*N)
		for j := range R {
			for i := range N {
				poleDenoms[j*N+i].Sub(&omegaPows[i], &xs[j])
			}
		}
		invPoleDenoms := koalabear.BatchInvert(poleDenoms)

		codeword := oracles[key.oracleI].Codewords[key.name]
		accumulateDEEP(q, codeword, weights, invProdDenoms, invPoleDenoms, betaPow, N, R)
		betaPow.Mul(&betaPow, &beta)
	}

	return q, nil
}

// computeBarycentricWeights returns w_j = y_j / Π_{k≠j}(x_j − x_k).
// xs is assumed to be duplicate-free.
func computeBarycentricWeights(xs, ys []koalabear.Element) ([]koalabear.Element, error) {
	R := len(xs)
	weights := make([]koalabear.Element, R)
	if R == 1 {
		weights[0] = ys[0]
		return weights, nil
	}
	denoms := make([]koalabear.Element, R)
	var diff koalabear.Element
	for j := range R {
		denoms[j].SetOne()
		for k := range R {
			if k == j {
				continue
			}
			diff.Sub(&xs[j], &xs[k])
			denoms[j].Mul(&denoms[j], &diff)
		}
	}
	invDenoms := koalabear.BatchInvert(denoms)
	for j := range R {
		weights[j].Mul(&ys[j], &invDenoms[j])
	}
	return weights, nil
}

// accumulateDEEP adds β^p · Q(ω^i) to q[i] for i = 0..N-1, where
//
//	Q(ω^i) = codeword[i] · invProdDenoms[i] − Σ_j weights[j] · invPoleDenoms[j·N+i].
func accumulateDEEP(
	q []koalabear.Element,
	codeword poly.Polynomial,
	weights []koalabear.Element,
	invProdDenoms []koalabear.Element,
	invPoleDenoms []koalabear.Element,
	betaPow koalabear.Element,
	N int,
	R int,
) {
	var term, polesum, scratch koalabear.Element
	for i := range N {
		term.Mul(&codeword[i], &invProdDenoms[i])
		polesum.SetZero()
		for j := range R {
			scratch.Mul(&weights[j], &invPoleDenoms[j*N+i])
			polesum.Add(&polesum, &scratch)
		}
		term.Sub(&term, &polesum)
		term.Mul(&term, &betaPow)
		q[i].Add(&q[i], &term)
	}
}
