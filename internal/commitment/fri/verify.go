package fri

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/merkle"
)

// VerifyOpening checks the OpeningProof against the verifier's transcript state
// (which must have been advanced by all Bind calls before this is called).
//
// lh and nh must be the same leaf and node hashers used during commitment.
//
// Protocol parameters (k, NumQueries) are inferred from the proof itself: k is
// the number of elements in the layer coset data, and NumQueries is the length
// of QueryIndices. This makes the proof self-describing and removes the need to
// pass a Config.
func (v *Verifier) VerifyOpening(proof OpeningProof, lh merkle.LeafHasher, nh merkle.NodeHasher) error {
	if len(v.deepPoints) == 0 {
		// Nothing was committed; nothing to verify.
		return nil
	}

	if len(proof.Commitments) == 0 {
		return fmt.Errorf("fri: no commitments in proof")
	}
	N := int(proof.Commitments[0].CodewordDomainSize)
	for i, c := range proof.Commitments {
		if int(c.CodewordDomainSize) != N {
			return fmt.Errorf("fri: commitment %d has domain %d, want %d", i, c.CodewordDomainSize, N)
		}
	}

	// Infer folding factor k from the layer coset data when layers exist;
	// otherwise recover k from the oracle coset data (K·k entries per leaf).
	if len(proof.QueryIndices) == 0 {
		// No queries in proof; skip.
		return nil
	}
	numLayers := len(proof.LayerCommitments)
	var k int
	switch {
	case numLayers > 0 && len(proof.LayerCosetData) > 0 && len(proof.LayerCosetData[0]) > 0:
		k = len(proof.LayerCosetData[0][0])
	case len(proof.OracleCosetData) > 0 && len(proof.OracleCosetData[0]) > 0:
		K := proof.Commitments[0].NumPolynomials
		if K == 0 {
			return fmt.Errorf("fri: oracle has no polynomials")
		}
		k = len(proof.OracleCosetData[0][0]) / K
	default:
		return fmt.Errorf("fri: proof has queries but no oracle or layer data")
	}
	if k == 0 {
		return fmt.Errorf("fri: inferred folding factor is zero")
	}
	numQueries := len(proof.QueryIndices)
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
	for li, root := range proof.LayerCommitments {
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
	if err := v.Transcript.Bind(friFinalChallenge, marshalElements(proof.FinalPolynomial)); err != nil {
		return err
	}
	if _, err := v.Transcript.ComputeChallenge(friFinalChallenge); err != nil {
		return err
	}

	// 3a. Optional proof-of-work grinding check.
	if v.GrindingBits > 0 {
		if err := verifyAndBindGrinding(v.Transcript, v.GrindingBits, proof.GrindingNonce); err != nil {
			return err
		}
	}

	// 4. Re-derive query indices and check they match the proof.
	derivedIndices, err := deriveQueryIndices(v.Transcript, numQueries, nLeaves)
	if err != nil {
		return err
	}
	for i, di := range derivedIndices {
		if di != proof.QueryIndices[i] {
			return fmt.Errorf("fri: query index %d mismatch: proof has %d, transcript gives %d",
				i, proof.QueryIndices[i], di)
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
	for qi, j64 := range proof.QueryIndices {
		j := int(j64)

		// 5a. Compute the DEEP quotient values from oracle coset data and claimed values.
		// q_combined[t] = Σ_r β^r · (f_r(ω^{j+t·(N/k)}) − y_r) / (ω^{j+t·(N/k)} − z_r)
		qCheck := make([]koalabear.Element, k)
		var betaPow koalabear.Element
		betaPow.SetOne()
		for r, dp := range v.deepPoints {
			oi := dp.oracleI
			comm := proof.Commitments[oi]

			polyIdx := -1
			for pi, name := range comm.PolynomialNames {
				if name == dp.name {
					polyIdx = pi
					break
				}
			}
			if polyIdx < 0 {
				return fmt.Errorf("fri: polynomial %q not found in oracle %d", dp.name, oi)
			}

			claimedY := proof.ClaimedValues[r]
			z := dp.point

			for t := range k {
				pos := j + t*nLeaves
				fVal := proof.OracleCosetData[qi][oi][polyIdx*k+t]
				denom := omegaPows[pos]
				denom.Sub(&denom, &z)
				if denom.IsZero() {
					return fmt.Errorf("fri: DEEP point lands on evaluation domain at query %d", qi)
				}
				var invDenom koalabear.Element
				invDenom.Inverse(&denom)
				var term koalabear.Element
				term.Sub(&fVal, &claimedY)
				term.Mul(&term, &invDenom)
				term.Mul(&term, &betaPow)
				qCheck[t].Add(&qCheck[t], &term)
			}
			betaPow.Mul(&betaPow, &beta)
		}

		// Verify oracle Merkle proofs (one per oracle, not per request).
		oracleVerified := make([]bool, len(proof.Commitments))
		for _, dp := range v.deepPoints {
			oi := dp.oracleI
			if oracleVerified[oi] {
				continue
			}
			leafData := cosetLeafBytes(proof.OracleCosetData[qi][oi])
			if !merkle.Verify(proof.Commitments[oi].Root, proof.OracleOpenings[qi][oi], leafData, lh, nh) {
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
				if pos >= len(proof.FinalPolynomial) {
					return fmt.Errorf("fri: final polynomial index %d out of range (len=%d)",
						pos, len(proof.FinalPolynomial))
				}
				if !qCheck[t].Equal(&proof.FinalPolynomial[pos]) {
					return fmt.Errorf("fri: DEEP quotient mismatch against final polynomial at query %d coset offset %d", qi, t)
				}
			}
			continue
		}

		for t := range k {
			if !qCheck[t].Equal(&proof.LayerCosetData[qi][0][t]) {
				return fmt.Errorf("fri: DEEP quotient mismatch at query %d coset offset %d", qi, t)
			}
		}

		// 5c. Verify fold consistency across layers.
		jEll := j
		omegaEll := domainGen
		NellLeaves := nLeaves

		for li := range numLayers {
			leafData := cosetLeafBytes(proof.LayerCosetData[qi][li])
			if !merkle.Verify(proof.LayerCommitments[li], proof.LayerOpenings[qi][li], leafData, lh, nh) {
				return fmt.Errorf("fri: layer %d Merkle proof failed at query %d", li, qi)
			}

			cosetBase := elementPow(omegaEll, jEll)
			foldOutput := foldCoset(proof.LayerCosetData[qi][li], alphas[li], cosetBase, kDomain)

			if li == numLayers-1 {
				if jEll >= len(proof.FinalPolynomial) {
					return fmt.Errorf("fri: final polynomial index %d out of range (len=%d)",
						jEll, len(proof.FinalPolynomial))
				}
				if !foldOutput.Equal(&proof.FinalPolynomial[jEll]) {
					return fmt.Errorf("fri: fold mismatch against final polynomial at query %d", qi)
				}
			} else {
				NellNext := NellLeaves / k
				jNext := jEll % NellNext
				tNext := jEll / NellNext
				if !foldOutput.Equal(&proof.LayerCosetData[qi][li+1][tNext]) {
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
