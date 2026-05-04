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
	"fmt"
	"slices"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/merkle"
)

// Verify checks the embedded Proof against the verifier's transcript state
// (which must have been advanced by all BindCommitment + Open calls before
// this is invoked) and against the Verifier's configured parameter floor.
//
// lh and nh must be the same leaf and node hashers used during commitment.
func (v *Verifier) Verify(lh merkle.LeafHasher, nh merkle.NodeHasher) error {
	proof := v.proof

	// Reject any proof whose self-described protocol parameters are weaker
	// than the verifier's configured floor. This catches a malicious prover
	// that, for example, chose NumQueries=1.
	if proof.NumQueries < v.Config.NumQueries {
		return fmt.Errorf("fri: proof claims NumQueries=%d, want >= %d", proof.NumQueries, v.Config.NumQueries)
	}
	if v.Config.FoldingFactor != 0 && proof.FoldingFactor != v.Config.FoldingFactor {
		return fmt.Errorf("fri: proof FoldingFactor=%d, want %d", proof.FoldingFactor, v.Config.FoldingFactor)
	}
	if v.Config.FinalPolynomialMaxLen != 0 && proof.FinalPolynomialMaxLen > v.Config.FinalPolynomialMaxLen {
		return fmt.Errorf("fri: proof FinalPolynomialMaxLen=%d, want <= %d", proof.FinalPolynomialMaxLen, v.Config.FinalPolynomialMaxLen)
	}
	if v.Config.MinBlowupFactor != 0 && proof.BlowupFactor < v.Config.MinBlowupFactor {
		return fmt.Errorf("fri: proof BlowupFactor=%d, want >= %d", proof.BlowupFactor, v.Config.MinBlowupFactor)
	}
	if v.Config.GrindingBits > 0 && proof.GrindingBits < v.Config.GrindingBits {
		return fmt.Errorf("fri: proof GrindingBits=%d, want >= %d", proof.GrindingBits, v.Config.GrindingBits)
	}

	if len(v.deepPoints) == 0 {
		// Nothing was committed; nothing to verify.
		return nil
	}

	if len(v.proof.Commitments) == 0 {
		return fmt.Errorf("fri: no commitments in proof")
	}
	N := int(v.proof.Commitments[0].CodewordDomainSize)
	for i, c := range v.proof.Commitments {
		if int(c.CodewordDomainSize) != N {
			return fmt.Errorf("fri: commitment %d has domain %d, want %d", i, c.CodewordDomainSize, N)
		}
	}

	// Infer folding factor k from the layer coset data when layers exist;
	// otherwise recover k from the oracle coset data (K·k entries per leaf).
	if len(v.proof.QueryIndices) == 0 {
		// No queries in proof; skip.
		return nil
	}
	numLayers := len(v.proof.LayerCommitments)
	var k int
	switch {
	case numLayers > 0 && len(v.proof.LayerCosetData) > 0 && len(v.proof.LayerCosetData[0]) > 0:
		k = len(v.proof.LayerCosetData[0][0])
	case len(v.proof.OracleCosetData) > 0 && len(v.proof.OracleCosetData[0]) > 0:
		K := len(v.proof.Commitments[0].PolynomialNames)
		if K == 0 {
			return fmt.Errorf("fri: oracle has no polynomials")
		}
		k = len(v.proof.OracleCosetData[0][0]) / K
	default:
		return fmt.Errorf("fri: proof has queries but no oracle or layer data")
	}
	if k == 0 {
		return fmt.Errorf("fri: inferred folding factor is zero")
	}
	numQueries := len(v.proof.QueryIndices)
	nLeaves := N / k

	// 1. Re-derive combiner challenge β.
	if err := v.Transcript.NewChallenge(friCombineChallenge); err != nil {
		return err
	}
	betaBytes, err := v.Transcript.ComputeChallenge(friCombineChallenge)
	if err != nil {
		return err
	}
	var beta koalabear.Element
	beta.SetBytes(betaBytes)

	// 2. Re-derive layer folding challenges by binding each LayerCommitment.
	alphas := make([]koalabear.Element, numLayers)
	for li, root := range v.proof.LayerCommitments {
		challengeName := fmt.Sprintf(friLayerChallengeFmt, li)
		if err := v.Transcript.NewChallenge(challengeName); err != nil {
			return err
		}
		if err := v.Transcript.Bind(challengeName, root); err != nil {
			return err
		}
		b, err := v.Transcript.ComputeChallenge(challengeName)
		if err != nil {
			return err
		}
		alphas[li].SetBytes(b)
	}

	// 3. Bind final polynomial to transcript.
	if err := v.Transcript.NewChallenge(friFinalChallenge); err != nil {
		return err
	}
	if err := v.Transcript.Bind(friFinalChallenge, marshalElements(v.proof.FinalPolynomial)); err != nil {
		return err
	}
	if _, err := v.Transcript.ComputeChallenge(friFinalChallenge); err != nil {
		return err
	}

	// 3a. Optional proof-of-work grinding check.
	if v.Config.GrindingBits > 0 {
		if err := verifyAndBindGrinding(v.Transcript, v.Config.GrindingBits, v.proof.GrindingNonce); err != nil {
			return err
		}
	}

	// 4. Re-derive query indices and check they match the v.proof.
	derivedIndices, err := deriveQueryIndices(v.Transcript, numQueries, nLeaves)
	if err != nil {
		return err
	}
	for i, di := range derivedIndices {
		if di != v.proof.QueryIndices[i] {
			return fmt.Errorf("fri: query index %d mismatch: proof has %d, transcript gives %d",
				i, v.proof.QueryIndices[i], di)
		}
	}

	// Precompute ω^i for i = 0..N-1.
	domainGen := fft.NewDomain(uint64(N)).Generator
	omegaPows := make([]koalabear.Element, N)
	omegaPows[0].SetOne()
	for i := 1; i < N; i++ {
		omegaPows[i].Mul(&omegaPows[i-1], &domainGen)
	}

	kDomain := fft.NewDomain(uint64(k))

	// 5. Verify each query.
	for qi, j64 := range v.proof.QueryIndices {
		j := int(j64)

		// 5a. Reconstruct the DEEP-combined codeword values at this coset using
		// the same merged per-polynomial partial-fractions form as the prover.
		//
		// For polynomial p with R opens at {x_1,…,x_R} and claimed values
		// {y_1,…,y_R}, and coset positions ω^{j+t·nLeaves} for t = 0..k-1:
		//
		//   Q_p(ω^{j+t·nLeaves}) = f_p(ω^{j+t·nLeaves}) · [Π_s(ω^{j+t·nLeaves}−x_s)]^{-1}
		//                         − Σ_s w_s · (ω^{j+t·nLeaves}−x_s)^{-1}
		//
		// where w_s = y_s / Π_{u≠s}(x_s−x_u) (barycentric weights).
		//
		// qCheck[t] = Σ_p β^p · Q_p(ω^{j+t·nLeaves}).
		qCheck := make([]koalabear.Element, k)

		// Group deepPoints by (oracleI, name) preserving first-open order.
		type dpKey struct {
			oracleI int
			name    string
		}
		dpOrder := make([]dpKey, 0, len(v.deepPoints))
		dpGroups := make(map[dpKey][]int) // key → indices into v.deepPoints
		for r, dp := range v.deepPoints {
			key := dpKey{dp.oracleI, dp.name}
			if _, ok := dpGroups[key]; !ok {
				dpOrder = append(dpOrder, key)
			}
			dpGroups[key] = append(dpGroups[key], r)
		}

		// Sort canonically so β-powers match the prover regardless of
		// RegisterOpenAt call order.
		slices.SortFunc(dpOrder, func(a, b dpKey) int {
			if a.oracleI != b.oracleI {
				return cmp.Compare(a.oracleI, b.oracleI)
			}
			return cmp.Compare(a.name, b.name)
		})

		var betaPow koalabear.Element
		betaPow.SetOne()
		for _, key := range dpOrder {
			rs := dpGroups[key]
			R := len(rs)
			xs := make([]koalabear.Element, R)
			ys := make([]koalabear.Element, R)
			for jx, r := range rs {
				xs[jx] = v.deepPoints[r].point
				ys[jx] = v.proof.OpenedValues[r]
			}

			weights, err := computeBarycentricWeights(xs, ys)
			if err != nil {
				return fmt.Errorf("fri: barycentric weights for %q: %w", key.name, err)
			}

			// Locate the polynomial index within its oracle.
			comm := v.proof.Commitments[key.oracleI]
			polyIdx := -1
			for pi, name := range comm.PolynomialNames {
				if name == key.name {
					polyIdx = pi
					break
				}
			}
			if polyIdx < 0 {
				return fmt.Errorf("fri: polynomial %q not found in oracle %d", key.name, key.oracleI)
			}

			// Build denominator vectors for the k coset positions; batch-invert.
			// prodDenoms[t] = Π_s (ω^{j+t·nLeaves} − x_s)
			// poleDenoms[s·k+t] = ω^{j+t·nLeaves} − x_s
			prodDenoms := make([]koalabear.Element, k)
			poleDenoms := make([]koalabear.Element, R*k)
			for t := range k {
				pos := j + t*nLeaves
				prodDenoms[t].SetOne()
				for s := range R {
					var d koalabear.Element
					d.Sub(&omegaPows[pos], &xs[s])
					if d.IsZero() {
						return fmt.Errorf("fri: DEEP point lands on evaluation domain at query %d", qi)
					}
					prodDenoms[t].Mul(&prodDenoms[t], &d)
					poleDenoms[s*k+t] = d
				}
			}
			invProd := koalabear.BatchInvert(prodDenoms)
			invPole := koalabear.BatchInvert(poleDenoms)

			for t := range k {
				fVal := v.proof.OracleCosetData[qi][key.oracleI][polyIdx*k+t]
				var qVal, polesum, scratch koalabear.Element
				qVal.Mul(&fVal, &invProd[t])
				for s := range R {
					scratch.Mul(&weights[s], &invPole[s*k+t])
					polesum.Add(&polesum, &scratch)
				}
				qVal.Sub(&qVal, &polesum)
				qVal.Mul(&qVal, &betaPow)
				qCheck[t].Add(&qCheck[t], &qVal)
			}
			betaPow.Mul(&betaPow, &beta)
		}

		// Verify oracle Merkle proofs (one per oracle, not per request).
		oracleVerified := make([]bool, len(v.proof.Commitments))
		for _, dp := range v.deepPoints {
			oi := dp.oracleI
			if oracleVerified[oi] {
				continue
			}
			leafData := cosetLeafBytes(v.proof.OracleCosetData[qi][oi])
			if !merkle.Verify(v.proof.Commitments[oi].Root, v.proof.OracleOpenings[qi][oi], leafData, lh, nh) {
				return fmt.Errorf("fri: oracle %d Merkle proof failed at query %d", oi, qi)
			}
			oracleVerified[oi] = true
		}

		// 5b. Check DEEP quotient values.
		// With FRI layers: qCheck must match layer-0 coset data, then we walk
		// the fold chain. Without layers (codeword small enough that no folding
		// happened), FinalPolynomial is the full DEEP-combined codeword q, so
		// we check qCheck directly against FinalPolynomial at the same coset.
		if numLayers == 0 {
			for t := range k {
				pos := j + t*nLeaves
				if pos >= len(v.proof.FinalPolynomial) {
					return fmt.Errorf("fri: final polynomial index %d out of range (len=%d)",
						pos, len(v.proof.FinalPolynomial))
				}
				if !qCheck[t].Equal(&v.proof.FinalPolynomial[pos]) {
					return fmt.Errorf("fri: DEEP quotient mismatch against final polynomial at query %d coset offset %d", qi, t)
				}
			}
			continue
		}

		for t := range k {
			if !qCheck[t].Equal(&v.proof.LayerCosetData[qi][0][t]) {
				return fmt.Errorf("fri: DEEP quotient mismatch at query %d coset offset %d", qi, t)
			}
		}

		// 5c. Verify fold consistency across layers.
		jEll := j
		omegaEll := domainGen
		NellLeaves := nLeaves

		for li := range numLayers {
			leafData := cosetLeafBytes(v.proof.LayerCosetData[qi][li])
			if !merkle.Verify(v.proof.LayerCommitments[li], v.proof.LayerOpenings[qi][li], leafData, lh, nh) {
				return fmt.Errorf("fri: layer %d Merkle proof failed at query %d", li, qi)
			}

			cosetBase := elementPow(omegaEll, jEll)
			foldOutput := foldCoset(v.proof.LayerCosetData[qi][li], alphas[li], cosetBase, kDomain)

			if li == numLayers-1 {
				if jEll >= len(v.proof.FinalPolynomial) {
					return fmt.Errorf("fri: final polynomial index %d out of range (len=%d)",
						jEll, len(v.proof.FinalPolynomial))
				}
				if !foldOutput.Equal(&v.proof.FinalPolynomial[jEll]) {
					return fmt.Errorf("fri: fold mismatch against final polynomial at query %d", qi)
				}
			} else {
				NellNext := NellLeaves / k
				jNext := jEll % NellNext
				tNext := jEll / NellNext
				if !foldOutput.Equal(&v.proof.LayerCosetData[qi][li+1][tNext]) {
					return fmt.Errorf("fri: fold mismatch at query %d layer %d", qi, li)
				}
				jEll = jNext
				NellLeaves = NellNext
			}

			omegaEll = elementPow(omegaEll, k)
		}
	}
	return nil
}
