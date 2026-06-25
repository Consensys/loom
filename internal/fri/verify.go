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
	"fmt"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/field"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/merkle"
)

// PCS.Verify checks an OpeningProof produced by PCS.Open against:
//
//   - roots: one Merkle root per Batch (in the same declaration order the
//     prover handed to Open). The caller is responsible for assembling
//     setup roots (from a verification key) and witness roots (from the
//     outer proof) into the right slice.
//   - shapes: the per-Batch / per-Group shape descriptor (PairedLeaves,
//     BaseWidth, ExtWidth). The verifier reconstructs every Group's
//     native size from PairedLeaves and the PCS's rate.
//   - shifts: the same per-poly shift schedule the prover used.
//   - zeta: the out-of-domain evaluation point.
//   - fs: a transcript already in the same state the prover's transcript
//     was in when Open was invoked. Verify registers alpha_DEEP and the
//     FRI-internal challenge names itself; the caller MUST NOT have
//     pre-registered any of those names.
//
// Verify performs four checks in sequence:
//
//  1. Shape validation against the proof.
//  2. Re-derives alpha_DEEP by replaying the same canonical-layout
//     binding sequence Open used.
//  3. Multi-degree FRI verification on the DEEP-quotient roots.
//  4. The bridge: for every FRI query position and every distinct
//     native size, recompute DQ_N(omega^x) and DQ_N(-omega^x) from the
//     opened raw leaves and the claimed values, then compare to the
//     FRI proof's level leaves at that query.
//
// Any of the checks failing yields a non-nil error explaining the
// failure mode.
func (pcs *PCS) Verify(
	roots []hash.Digest,
	shapes []BatchShapes,
	shifts []BatchShifts,
	zeta ext.E6,
	proof OpeningProof,
	fs *fiatshamir.Transcript,
) error {
	if pcs.params == nil {
		return fmt.Errorf("fri: PCS.Verify requires Params; construct PCS via NewPCSWithParams")
	}
	if fs == nil {
		return fmt.Errorf("fri: PCS.Verify: fs transcript is required")
	}
	if len(roots) != len(shapes) {
		return fmt.Errorf("fri: PCS.Verify: roots has %d entries, shapes has %d", len(roots), len(shapes))
	}
	if len(shifts) != len(shapes) {
		return fmt.Errorf("fri: PCS.Verify: shifts has %d entries, shapes has %d", len(shifts), len(shapes))
	}
	if len(proof.ClaimedValues) != len(shapes) {
		return fmt.Errorf("fri: PCS.Verify: ClaimedValues has %d entries, shapes has %d", len(proof.ClaimedValues), len(shapes))
	}

	// 1- Canonical layout from shapes; validates the shift schedule.
	lay, err := canonicalLayoutFromShape(shapes, shifts, pcs.rate)
	if err != nil {
		return err
	}

	// 2- Validate the OpeningProof's nested shapes against shapes/shifts/layout.
	if err := validateOpeningProofShape(&proof, shapes, shifts, lay, pcs.params.NumQueries); err != nil {
		return err
	}

	// 3- Replay the prover's alpha_DEEP derivation: register, bind values
	//    in canonical order, sample.
	if err := fs.NewChallenge(deepAlphaName); err != nil {
		return fmt.Errorf("fri: PCS.Verify: register alpha_DEEP: %w", err)
	}
	if err := bindClaimedValuesInLayoutOrder(fs, proof.ClaimedValues, shifts, lay); err != nil {
		return err
	}
	alphaOut, err := fs.ComputeChallenge(deepAlphaName)
	if err != nil {
		return fmt.Errorf("fri: PCS.Verify: sample alpha_DEEP: %w", err)
	}
	alpha := hash.OutputToExt(alphaOut)

	// 4- Verify the multi-degree FRI proof on the declared DEEP roots.
	sizesDesc := make([]int, len(lay))
	for i, sb := range lay {
		sizesDesc[i] = sb.N
	}
	if err := Verify(*pcs.params, proof.DeepQuotientRoots, sizesDesc, proof.FRIProof, fs); err != nil {
		return fmt.Errorf("fri: PCS.Verify: FRI proof: %w", err)
	}

	// 5- Extract per-query FRI positions from the proof (the FRI prover
	//    embeds the query positions in the first FRI layer's path leaf
	//    index). These are the sample points used by both the Merkle-
	//    path check and the bridge.
	queryPositions, err := extractFRIQueryPositions(proof.FRIProof, pcs.params.NumQueries)
	if err != nil {
		return fmt.Errorf("fri: PCS.Verify: %w", err)
	}

	// 6- Authenticate every (query, batch) Merkle opening against the
	//    declared roots. For multi-group batches this also re-hashes the
	//    per-injection-level raw leaves and matches them against
	//    Proof.InjectionLeaves before running merkle.VerifyWithInjections.
	if err := verifyAllPointSamplings(pcs, roots, shapes, queryPositions, proof.PointSamplings); err != nil {
		return err
	}

	// 7- Bridge: recompute DQ_N(X), DQ_N(-X) from raw leaves + claimed
	//    values in canonical order, compare to FRI level leaves.
	if err := checkFRIBridge(pcs, &proof, lay, shapes, shifts, alpha, zeta, queryPositions); err != nil {
		return err
	}

	return nil
}

// validateOpeningProofShape checks that the nested ClaimedValues /
// PointSamplings / DeepQuotientRoots shapes line up with shapes/shifts
// and with the canonical layout's distinct-size count.
func validateOpeningProofShape(
	proof *OpeningProof,
	shapes []BatchShapes,
	shifts []BatchShifts,
	lay layout,
	numQueries int,
) error {
	for b, batchSh := range shifts {
		cv := proof.ClaimedValues[b]
		if len(cv) != len(batchSh) {
			return fmt.Errorf("fri: PCS.Verify: ClaimedValues[%d] has %d groups, shifts[%d] has %d", b, len(cv), b, len(batchSh))
		}
		for g, gShifts := range batchSh {
			if len(cv[g].Base) != len(gShifts.Base) {
				return fmt.Errorf("fri: PCS.Verify: ClaimedValues[%d][%d].Base width %d != %d", b, g, len(cv[g].Base), len(gShifts.Base))
			}
			if len(cv[g].Ext) != len(gShifts.Ext) {
				return fmt.Errorf("fri: PCS.Verify: ClaimedValues[%d][%d].Ext width %d != %d", b, g, len(cv[g].Ext), len(gShifts.Ext))
			}
			for i, ss := range gShifts.Base {
				if len(cv[g].Base[i]) != len(ss) {
					return fmt.Errorf("fri: PCS.Verify: ClaimedValues[%d][%d].Base[%d] = %d values, shifts %d", b, g, i, len(cv[g].Base[i]), len(ss))
				}
			}
			for i, ss := range gShifts.Ext {
				if len(cv[g].Ext[i]) != len(ss) {
					return fmt.Errorf("fri: PCS.Verify: ClaimedValues[%d][%d].Ext[%d] = %d values, shifts %d", b, g, i, len(cv[g].Ext[i]), len(ss))
				}
			}
		}
	}

	if len(proof.DeepQuotientRoots) != len(lay) {
		return fmt.Errorf("fri: PCS.Verify: DeepQuotientRoots has %d entries, expected %d (distinct sizes)", len(proof.DeepQuotientRoots), len(lay))
	}

	if len(proof.PointSamplings) != numQueries {
		return fmt.Errorf("fri: PCS.Verify: PointSamplings has %d queries, expected %d", len(proof.PointSamplings), numQueries)
	}
	for q, qSamples := range proof.PointSamplings {
		if len(qSamples) != len(shapes) {
			return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d] has %d batches, expected %d", q, len(qSamples), len(shapes))
		}
		for b, wp := range qSamples {
			if len(wp.InjectionRawLeaves) != len(shapes[b]) {
				return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d] has %d InjectionRawLeaves, expected %d", q, b, len(wp.InjectionRawLeaves), len(shapes[b]))
			}
			// InjectionRawLeaves is in decreasing-size order; match each
			// raw-leaf entry's widths against the matching shape sorted
			// by size.
			injOrder := injectionOrderForBatch(shapes[b])
			for k, declIdx := range injOrder {
				gs := shapes[b][declIdx]
				raw := wp.InjectionRawLeaves[k]
				if len(raw.RawLeafBase) != gs.BaseWidth {
					return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d].InjectionRawLeaves[%d].RawLeafBase width %d != %d", q, b, k, len(raw.RawLeafBase), gs.BaseWidth)
				}
				if len(raw.RawLeafExt) != gs.ExtWidth {
					return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d].InjectionRawLeaves[%d].RawLeafExt width %d != %d", q, b, k, len(raw.RawLeafExt), gs.ExtWidth)
				}
			}
		}
	}
	return nil
}

// injectionOrderForBatch returns, for one batch's GroupShape slice, the
// indices into shapes in *decreasing PairedLeaves* order -- the same
// order PCS.Commit places the per-Group LeafSources in Committed.Sources
// (and consequently the same order WMerkleProof.InjectionRawLeaves uses).
func injectionOrderForBatch(batchShapes BatchShapes) []int {
	order := make([]int, len(batchShapes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return batchShapes[order[a]].PairedLeaves > batchShapes[order[b]].PairedLeaves
	})
	return order
}

// extractFRIQueryPositions reads the per-query positions out of the FRI
// proof. The query position for query q is the LeafIdx of the first
// layer of FRIQueries[q] (a property the FRI prover establishes; the
// verifier re-derives the same s via the transcript inside fri.Verify
// but does not expose it, so we read it back from the proof).
func extractFRIQueryPositions(prf Proof, numQueries int) ([]int, error) {
	if len(prf.FRIQueries) != numQueries {
		return nil, fmt.Errorf("FRIQueries has %d entries, expected %d", len(prf.FRIQueries), numQueries)
	}
	out := make([]int, numQueries)
	for q := range prf.FRIQueries {
		if len(prf.FRIQueries[q].Layers) == 0 {
			return nil, fmt.Errorf("FRIQueries[%d].Layers is empty", q)
		}
		out[q] = prf.FRIQueries[q].Layers[0].Path.LeafIdx
	}
	return out, nil
}

// verifyAllPointSamplings authenticates every (query, batch) Merkle
// opening in proof.PointSamplings against the corresponding batch root.
// For multi-group batches, also re-hashes each injection-level RawLeaf
// and matches it against Proof.InjectionLeaves before running
// merkle.VerifyWithInjections.
func verifyAllPointSamplings(
	pcs *PCS,
	roots []hash.Digest,
	shapes []BatchShapes,
	queryPositions []int,
	pointSamplings [][]WMerkleProof,
) error {
	for q, sQ := range queryPositions {
		_ = sQ // pointSamplings already carries the folded position via Proof.LeafIdx
		for b, wp := range pointSamplings[q] {
			if err := verifyOneWMerkleProof(pcs.leafHasher, pcs.nodeHasher, roots[b], shapes[b], wp); err != nil {
				return fmt.Errorf("fri: PCS.Verify: query %d, batch %d: %w", q, b, err)
			}
		}
	}
	return nil
}

// verifyOneWMerkleProof checks one WMerkleProof against the batch's
// Merkle root using the batch's per-Group shapes for size routing. The
// top group's HashLeaf result is the bottom-of-tree leaf; each smaller
// group's HashLeaf result must match the matching merkle.Proof.InjectionLeaves
// entry before the path is checked via merkle.VerifyWithInjections.
func verifyOneWMerkleProof(
	leafHasher LeafHasher,
	nodeHasher NodeHasher,
	root hash.Digest,
	batchShapes BatchShapes,
	wp WMerkleProof,
) error {
	if len(wp.InjectionRawLeaves) == 0 {
		return fmt.Errorf("WMerkleProof has no InjectionRawLeaves")
	}

	// Re-order the GroupShape entries to match wp.InjectionRawLeaves'
	// decreasing-size convention.
	injOrder := injectionOrderForBatch(batchShapes)
	if len(injOrder) != len(wp.InjectionRawLeaves) {
		return fmt.Errorf("shapes-vs-WMerkleProof group count mismatch (%d vs %d)", len(injOrder), len(wp.InjectionRawLeaves))
	}

	// Top group: its HashLeaf is the merkle leaf at the bottom of the tree.
	topRaw := wp.InjectionRawLeaves[0]
	leaf := leafHasher.HashLeaf(topRaw.RawLeafBase, topRaw.RawLeafExt)

	// Smaller groups: each carries an injection level. Their HashLeaf
	// values must match the path's pre-bound InjectionLeaves entries.
	expectedInj := len(wp.InjectionRawLeaves) - 1
	if len(wp.Proof.InjectionLeaves) != expectedInj {
		return fmt.Errorf("Proof.InjectionLeaves has %d entries, expected %d (one per injection group)", len(wp.Proof.InjectionLeaves), expectedInj)
	}

	injectionWidths := make([]int, expectedInj)
	for k := 1; k < len(wp.InjectionRawLeaves); k++ {
		raw := wp.InjectionRawLeaves[k]
		computed := leafHasher.HashLeaf(raw.RawLeafBase, raw.RawLeafExt)
		if computed != wp.Proof.InjectionLeaves[k-1] {
			return fmt.Errorf("injection-leaf hash mismatch at level %d", k)
		}
		injectionWidths[k-1] = batchShapes[injOrder[k]].PairedLeaves
	}

	if !merkle.VerifyWithInjections(root, wp.Proof, leaf, injectionWidths, nodeHasher) {
		return fmt.Errorf("Merkle path does not authenticate under the given root")
	}
	return nil
}

// checkFRIBridge is the verifier-side counterpart of
// computeDeepQuotientCodewords' per-(size, shift) bundle walk. For each
// query position sFull and each distinct native size N in lay (largest
// first, i.e. level 0 of the multi-degree FRI):
//
//	sL = sFull mod (rate*N/2)
//	X = omega_{rate*N}^sL,    -X = -X    (lifted to ext)
//	DQ_P, DQ_Q := 0, 0
//	for shift s in ascending order at this size:
//	  z_s = zeta * omega_N^s
//	  v_s, C_at_X, C_at_negX := 0, 0, 0
//	  for entry in canonical order at (size, shift):
//	    v_s       += alpha^e * claimed_value(entry, s)
//	    C_at_X    += alpha^e * raw_leaf_P(entry)
//	    C_at_negX += alpha^e * raw_leaf_Q(entry)
//	    alpha^e   *= alpha   (alpha counter is per-size, monotonic)
//	  DQ_P += (v_s - C_at_X) / (z_s - X)
//	  DQ_Q += (v_s - C_at_negX) / (z_s - -X)
//	check DQ_P == FRI level-i leaf P at this query
//	check DQ_Q == FRI level-i leaf Q at this query
//
// where level i = layout size index (0 = largest), the largest size
// reads from FRIQueries[q].Layers[0], and smaller sizes from
// LevelQueries[i-1][q].
func checkFRIBridge(
	pcs *PCS,
	proof *OpeningProof,
	lay layout,
	shapes [][]GroupShape,
	shifts []BatchShifts,
	alpha ext.E6,
	zeta ext.E6,
	queryPositions []int,
) error {
	// Per-batch injection-order maps, computed once.
	injOrderByBatch := make([][]int, len(shapes))
	for b, batchShapes := range shapes {
		injOrderByBatch[b] = injectionOrderForBatch(batchShapes)
	}
	declToInjIdx := func(b, g int) int {
		for injIdx, declIdx := range injOrderByBatch[b] {
			if declIdx == g {
				return injIdx
			}
		}
		return -1
	}

	for q, sFull := range queryPositions {
		for sizeIdx, sb := range lay {
			N := sb.N
			ratN := int(pcs.rate) * N
			halfRatN := ratN / 2
			sL := sFull % halfRatN

			// X = omega_{rate*N}^sL (base), lifted; -X.
			gen, err := koalabear.Generator(uint64(ratN))
			if err != nil {
				return fmt.Errorf("fri: PCS.Verify: koalabear.Generator(%d): %w", ratN, err)
			}
			var XBase, negXBase koalabear.Element
			XBase.Exp(gen, big.NewInt(int64(sL)))
			negXBase.Neg(&XBase)
			X := hash.LiftBaseToExt(XBase)
			negX := hash.LiftBaseToExt(negXBase)

			// omega_N: trace-domain generator at this size.
			traceGen, err := koalabear.Generator(uint64(N))
			if err != nil {
				return fmt.Errorf("fri: PCS.Verify: koalabear.Generator(%d): %w", N, err)
			}

			var DQ_P, DQ_Q ext.E6
			var alphaRunning ext.E6
			alphaRunning.SetOne()

			for _, shB := range sb.Bundles {
				// z_s = zeta * omega_N^s
				var omegaShift koalabear.Element
				omegaShift.Exp(traceGen, big.NewInt(int64(shB.Shift)))
				zs := zeta
				zs.MulByElement(&zs, &omegaShift)

				var v_s, C_at_X, C_at_negX ext.E6

				for _, e := range shB.Entries {
					// Look up the claimed value.
					gShifts := shifts[e.BatchIdx][e.GroupIdx]
					gValues := proof.ClaimedValues[e.BatchIdx][e.GroupIdx]

					var v ext.E6
					if e.Field == field.Base {
						kth := containsIntIndex(gShifts.Base[e.PolyIdx], shB.Shift)
						v = gValues.Base[e.PolyIdx][kth]
					} else {
						kth := containsIntIndex(gShifts.Ext[e.PolyIdx], shB.Shift)
						v = gValues.Ext[e.PolyIdx][kth]
					}

					// Look up the raw paired evals at this query position.
					injIdx := declToInjIdx(e.BatchIdx, e.GroupIdx)
					if injIdx < 0 {
						return fmt.Errorf("fri: PCS.Verify: cannot map (batch=%d, group=%d) to InjectionRawLeaves index", e.BatchIdx, e.GroupIdx)
					}
					raw := proof.PointSamplings[q][e.BatchIdx].InjectionRawLeaves[injIdx]

					var leafP, leafQ ext.E6
					if e.Field == field.Base {
						leafP = hash.LiftBaseToExt(raw.RawLeafBase[e.PolyIdx])
						leafQ.Set(&leafP)
					} else {
						leafP.Set(&raw.RawLeafExt[e.PolyIdx])
						leafQ.Set(&leafP)
					}

					var term ext.E6
					term.Mul(&v, &alphaRunning)
					v_s.Add(&v_s, &term)
					term.Mul(&leafP, &alphaRunning)
					C_at_X.Add(&C_at_X, &term)
					term.Mul(&leafQ, &alphaRunning)
					C_at_negX.Add(&C_at_negX, &term)

					alphaRunning.Mul(&alphaRunning, &alpha)
				}

				// DQ_P += (v_s - C_at_X) / (z_s - X)
				var num, denom ext.E6
				num.Sub(&v_s, &C_at_X)
				denom.Sub(&zs, &X)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_P.Add(&DQ_P, &num)

				// DQ_Q += (v_s - C_at_negX) / (z_s - -X)
				num.Sub(&v_s, &C_at_negX)
				denom.Sub(&zs, &negX)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_Q.Add(&DQ_Q, &num)
			}

			// Read the FRI level-sizeIdx leaf at query q and compare.
			var actualP, actualQ ext.E6
			if sizeIdx == 0 {
				layer := proof.FRIProof.FRIQueries[q].Layers[0]
				if layer.Field != field.Ext {
					return fmt.Errorf("fri: PCS.Verify: bridge query %d level 0: expected ext FRI layer, got %s", q, layer.Field)
				}
				actualP = layer.LeafPExt
				actualQ = layer.LeafQExt
			} else {
				if sizeIdx-1 >= len(proof.FRIProof.LevelQueries) || q >= len(proof.FRIProof.LevelQueries[sizeIdx-1]) {
					return fmt.Errorf("fri: PCS.Verify: bridge query %d level %d: missing LevelQueries entry", q, sizeIdx)
				}
				lq := proof.FRIProof.LevelQueries[sizeIdx-1][q]
				if lq.Field != field.Ext {
					return fmt.Errorf("fri: PCS.Verify: bridge query %d level %d: expected ext FRI level query, got %s", q, sizeIdx, lq.Field)
				}
				actualP = lq.LeafPExt
				actualQ = lq.LeafQExt
			}

			if !DQ_P.Equal(&actualP) {
				return fmt.Errorf("fri: PCS.Verify: bridge query %d level %d (N=%d): DQ(X) mismatch: got %s, want %s", q, sizeIdx, N, DQ_P.String(), actualP.String())
			}
			if !DQ_Q.Equal(&actualQ) {
				return fmt.Errorf("fri: PCS.Verify: bridge query %d level %d (N=%d): DQ(-X) mismatch: got %s, want %s", q, sizeIdx, N, DQ_Q.String(), actualQ.String())
			}
		}
	}

	return nil
}
