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
)

// PCS.Verify checks an OpeningProof produced by PCS.Open against:
//
//   - roots: one Merkle root per Batch (in the same declaration order the
//     prover handed to Open). The caller is responsible for assembling
//     setup roots (from a verification key) and witness roots (from the
//     outer proof) into the right slice.
//   - shapes: the per-Batch / per-Group shape descriptor (Rows,
//     BaseWidth, ExtWidth). The verifier reconstructs every Group's
//     native size from Rows and the PCS's rate.
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
//     opened raw rows and the claimed values, then compare to the
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

	// 5- Extract per-query FRI positions from the proof. The FRI prover
	//    records each full-domain query row in the first FRI layer; these
	//    rows drive both committed-tree sampling and the DEEP bridge.
	queryPositions, err := extractFRIQueryPositions(proof.FRIProof, pcs.params.NumQueries)
	if err != nil {
		return fmt.Errorf("fri: PCS.Verify: %w", err)
	}

	// 6- Authenticate every (query, batch) Merkle opening against the
	//    declared roots. For multi-group batches this also re-hashes the
	//    per-injection-level raw rows and matches them against the
	//    Proof.InjectionLeaves crossed by each complete path.
	if err := verifyAllPointSamplings(pcs, roots, shapes, queryPositions, proof.PointSamplings); err != nil {
		return err
	}

	// 7- Bridge: recompute DQ_N(X), DQ_N(-X) from raw rows + claimed
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
			injOrder := injectionOrderForBatch(shapes[b])
			if len(injOrder) == 0 {
				return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d] has no group shapes", q, b)
			}
			if len(wp.Injections) != len(injOrder)-1 {
				return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d] has %d Injections, expected %d", q, b, len(wp.Injections), len(injOrder)-1)
			}
			topShape := shapes[b][injOrder[0]]
			if err := checkRawRowWidth(wp.TopRows.Lo, topShape); err != nil {
				return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d].TopRows.Lo: %w", q, b, err)
			}
			if err := checkRawRowWidth(wp.TopRows.Hi, topShape); err != nil {
				return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d].TopRows.Hi: %w", q, b, err)
			}
			for k, declIdx := range injOrder[1:] {
				gs := shapes[b][declIdx]
				rows := wp.Injections[k].Rows
				if err := checkRawRowWidth(rows.Lo, gs); err != nil {
					return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d].Injections[%d].Rows.Lo: %w", q, b, k, err)
				}
				if err := checkRawRowWidth(rows.Hi, gs); err != nil {
					return fmt.Errorf("fri: PCS.Verify: PointSamplings[%d][%d].Injections[%d].Rows.Hi: %w", q, b, k, err)
				}
			}
		}
	}
	return nil
}

// injectionOrderForBatch returns, for one batch's GroupShape slice, the
// indices into shapes in *decreasing row-count* order -- the same
// order PCS.Commit places the per-Group LeafSources in Committed.Sources.
// WMerkleProof stores order[0] in TopRows and order[1:] in Injections.
func injectionOrderForBatch(batchShapes BatchShapes) []int {
	order := make([]int, len(batchShapes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return batchShapes[order[a]].Rows > batchShapes[order[b]].Rows
	})
	return order
}

// extractFRIQueryPositions reads the per-query positions out of the FRI
// proof. The query position for query q is the Row of the first layer of
// FRIQueries[q] (a property the FRI prover establishes; the verifier
// re-derives the same s via the transcript inside fri.Verify but does not
// expose it, so we read it back from the proof).
func extractFRIQueryPositions(prf Proof, numQueries int) ([]int, error) {
	if len(prf.FRIQueries) != numQueries {
		return nil, fmt.Errorf("FRIQueries has %d entries, expected %d", len(prf.FRIQueries), numQueries)
	}
	out := make([]int, numQueries)
	for q := range prf.FRIQueries {
		if len(prf.FRIQueries[q].Layers) == 0 {
			return nil, fmt.Errorf("FRIQueries[%d].Layers is empty", q)
		}
		out[q] = prf.FRIQueries[q].Layers[0].Row
	}
	return out, nil
}

// verifyAllPointSamplings authenticates every (query, batch) compact Merkle
// opening in proof.PointSamplings against the corresponding batch root.
// For multi-group batches, the compact verifier folds path-side injected rows
// directly and checks companion injected rows against the sibling digest on the
// shared top Merkle path.
func verifyAllPointSamplings(
	pcs *PCS,
	roots []hash.Digest,
	shapes []BatchShapes,
	queryPositions []int,
	pointSamplings [][]WMerkleProof,
) error {
	for q, sQ := range queryPositions {
		for b, wp := range pointSamplings[q] {
			if err := verifyOneWMerkleProof(pcs.leafHasher, pcs.nodeHasher, roots[b], shapes[b], wp, sQ, pcs.params.N); err != nil {
				return fmt.Errorf("fri: PCS.Verify: query %d, batch %d: %w", q, b, err)
			}
		}
	}
	return nil
}

// verifyOneWMerkleProof checks one WMerkleProof against the batch's
// Merkle root using the batch's per-Group shapes for size routing.
func verifyOneWMerkleProof(
	leafHasher LeafHasher,
	nodeHasher NodeHasher,
	root hash.Digest,
	batchShapes BatchShapes,
	wp WMerkleProof,
	sFull int,
	maxRows int,
) error {
	if sFull < 0 {
		return fmt.Errorf("query row %d must be non-negative", sFull)
	}
	if maxRows <= 0 || maxRows&(maxRows-1) != 0 {
		return fmt.Errorf("maxRows=%d must be a positive power of two", maxRows)
	}

	// Re-order the GroupShape entries to match the compact proof's
	// decreasing-size convention.
	injOrder := injectionOrderForBatch(batchShapes)
	if len(injOrder) == 0 {
		return fmt.Errorf("WMerkleProof has no group shapes")
	}
	topRows := batchShapes[injOrder[0]].Rows
	if topRows <= 0 || topRows&(topRows-1) != 0 {
		return fmt.Errorf("top rows %d must be a positive power of two", topRows)
	}
	if topRows < 2 {
		return fmt.Errorf("top rows %d must be at least 2", topRows)
	}
	if topRows > maxRows {
		return fmt.Errorf("top rows %d exceeds maxRows %d", topRows, maxRows)
	}

	injectionWidths := make([]int, len(injOrder)-1)
	injectionByWidth := make(map[int]int, len(injOrder)-1)
	prevWidth := topRows
	for k := 1; k < len(injOrder); k++ {
		width := batchShapes[injOrder[k]].Rows
		if width <= 0 || width&(width-1) != 0 {
			return fmt.Errorf("injection %d rows %d must be a positive power of two", k-1, width)
		}
		if width < 2 {
			return fmt.Errorf("injection %d rows %d must be at least 2", k-1, width)
		}
		if width >= prevWidth {
			return fmt.Errorf("injection rows must be strictly decreasing (got %d after %d)", width, prevWidth)
		}
		injIdx := k - 1
		injectionWidths[injIdx] = width
		injectionByWidth[width] = injIdx
		prevWidth = width
	}

	if len(wp.Injections) != len(injectionWidths) {
		return fmt.Errorf("WMerkleProof has %d injections, expected %d", len(wp.Injections), len(injectionWidths))
	}
	if len(wp.Path.InjectionLeaves) != 0 && len(wp.Path.InjectionLeaves) != len(injectionWidths) {
		return fmt.Errorf("top path has %d injection leaves, expected 0 or %d", len(wp.Path.InjectionLeaves), len(injectionWidths))
	}

	topReductionGlobal := log2(maxRows) - log2(topRows)
	if topReductionGlobal < 0 {
		return fmt.Errorf("top rows %d exceeds maxRows %d", topRows, maxRows)
	}
	topRow := sFull >> topReductionGlobal
	topLo, topHi := siblingRows(topRow)
	if topHi >= topRows {
		return fmt.Errorf("top row pair (%d,%d) out of range [0,%d)", topLo, topHi, topRows)
	}
	if wp.Path.LeafIdx != topLo {
		return fmt.Errorf("top Path.LeafIdx = %d, want %d", wp.Path.LeafIdx, topLo)
	}
	depth := log2(topRows)
	if len(wp.Path.Siblings) != depth {
		return fmt.Errorf("top path has %d siblings, expected %d", len(wp.Path.Siblings), depth)
	}

	topHiDigest := hashRawRow(leafHasher, wp.TopRows.Hi)
	if wp.Path.Siblings[0] != topHiDigest {
		return fmt.Errorf("top companion row hash mismatch")
	}

	h := hashRawRow(leafHasher, wp.TopRows.Lo)
	pathIdx := wp.Path.LeafIdx
	for k, sibling := range wp.Path.Siblings {
		if pathIdx&1 == 0 {
			h = nodeHasher.HashNode(h, sibling)
		} else {
			h = nodeHasher.HashNode(sibling, h)
		}
		pathIdx >>= 1

		width := 1 << (depth - k - 1)
		injIdx, ok := injectionByWidth[width]
		if !ok {
			continue
		}

		rows, err := rawRowsForInjection(wp, injIdx)
		if err != nil {
			return err
		}
		groupIdx := injIdx + 1
		globalReduction := log2(maxRows) - log2(width)
		if globalReduction < 0 {
			return fmt.Errorf("group %d rows %d exceeds maxRows %d", groupIdx, width, maxRows)
		}
		row := sFull >> globalReduction
		lo, hi := siblingRows(row)
		if hi >= width {
			return fmt.Errorf("group %d row pair (%d,%d) out of range [0,%d)", groupIdx, lo, hi, width)
		}
		pathRowAtWidth := pathIdx
		if pathRowAtWidth != row {
			return fmt.Errorf("group %d path row at width = %d, want %d", groupIdx, pathRowAtWidth, row)
		}

		var pathRow, companionRow RawRow
		switch pathRowAtWidth {
		case lo:
			pathRow = rows.Lo
			companionRow = rows.Hi
		case hi:
			pathRow = rows.Hi
			companionRow = rows.Lo
		default:
			return fmt.Errorf("group %d path row %d is not adjacent pair (%d,%d)", groupIdx, pathRowAtWidth, lo, hi)
		}

		pathRowDigest := hashRawRow(leafHasher, pathRow)
		if len(wp.Path.InjectionLeaves) != 0 && pathRowDigest != wp.Path.InjectionLeaves[injIdx] {
			return fmt.Errorf("group %d path-side injection-row hash mismatch", groupIdx)
		}
		h = nodeHasher.HashNode(h, pathRowDigest)

		companionPost := nodeHasher.HashNode(wp.Injections[injIdx].SiblingRunning, hashRawRow(leafHasher, companionRow))
		companionSiblingIdx := k + 1
		if companionSiblingIdx >= len(wp.Path.Siblings) {
			return fmt.Errorf("group %d path has no sibling above injection width %d", groupIdx, width)
		}
		if companionPost != wp.Path.Siblings[companionSiblingIdx] {
			return fmt.Errorf("group %d companion injection-row hash mismatch", groupIdx)
		}
	}

	if h != root {
		return fmt.Errorf("Merkle path does not authenticate under the given root")
	}

	return nil
}

func checkRawRowWidth(row RawRow, shape GroupShape) error {
	if len(row.RawRowBase) != shape.BaseWidth {
		return fmt.Errorf("RawRowBase width %d != %d", len(row.RawRowBase), shape.BaseWidth)
	}
	if len(row.RawRowExt) != shape.ExtWidth {
		return fmt.Errorf("RawRowExt width %d != %d", len(row.RawRowExt), shape.ExtWidth)
	}
	return nil
}

func hashRawRow(leafHasher LeafHasher, row RawRow) hash.Digest {
	return leafHasher.HashLeaf(row.RawRowBase, row.RawRowExt)
}

func rawRowsForInjection(wp WMerkleProof, injIdx int) (RawRowPair, error) {
	if injIdx < 0 || injIdx >= len(wp.Injections) {
		return RawRowPair{}, fmt.Errorf("injection index %d out of compact proof range", injIdx)
	}
	return wp.Injections[injIdx].Rows, nil
}

func rawRowsForGroup(wp WMerkleProof, groupIdx int) (RawRowPair, error) {
	if groupIdx == 0 {
		return wp.TopRows, nil
	}
	rows, err := rawRowsForInjection(wp, groupIdx-1)
	if err != nil {
		return RawRowPair{}, fmt.Errorf("group index %d: %w", groupIdx, err)
	}
	return rows, nil
}

// checkFRIBridge is the verifier-side counterpart of
// computeDeepQuotientCodewords' per-(size, shift) bundle walk. For each
// query position sFull and each distinct native size N in lay (largest
// first, i.e. level 0 of the multi-degree FRI):
//
//	row = sFull >> (log2(maxRows) - log2(rate*N))
//	lo  = row &^ 1
//	hi  = lo + 1
//	X   = omega_{rate*N}^bitrev(lo)
//	-X  = omega_{rate*N}^bitrev(hi)
//	DQ_P, DQ_Q := 0, 0
//	for shift s in ascending order at this size:
//	  z_s = zeta * omega_N^s
//	  v_s, C_at_X, C_at_negX := 0, 0, 0
//	  for entry in canonical order at (size, shift):
//	    v_s       += alpha^e * claimed_value(entry, s)
//	    C_at_X    += alpha^e * raw_row_lo(entry)
//	    C_at_negX += alpha^e * raw_row_hi(entry)
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
			bitsReduced := log2(pcs.params.N) - log2(ratN)
			if bitsReduced < 0 {
				return fmt.Errorf("fri: PCS.Verify: bridge size %d has ratN=%d larger than max rows %d", N, ratN, pcs.params.N)
			}
			row := sFull >> bitsReduced
			lo, hi := siblingRows(row)

			// X = omega_{rate*N}^bitrev(lo) (base), lifted; -X is the
			// companion row hi under bit-reversed row ordering.
			gen, err := koalabear.Generator(uint64(ratN))
			if err != nil {
				return fmt.Errorf("fri: PCS.Verify: koalabear.Generator(%d): %w", ratN, err)
			}
			var XBase, negXBase, hiBase koalabear.Element
			XBase.ExpInt64(gen, int64(bitReverseIndex(lo, ratN)))
			hiBase.ExpInt64(gen, int64(bitReverseIndex(hi, ratN)))
			negXBase.Neg(&XBase)
			if !hiBase.Equal(&negXBase) {
				return fmt.Errorf("fri: PCS.Verify: bridge row companion mismatch for ratN=%d lo=%d hi=%d", ratN, lo, hi)
			}
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

					// Look up the authenticated raw row pair at this query position.
					injIdx := declToInjIdx(e.BatchIdx, e.GroupIdx)
					if injIdx < 0 {
						return fmt.Errorf("fri: PCS.Verify: cannot map (batch=%d, group=%d) to compact proof group index", e.BatchIdx, e.GroupIdx)
					}
					raw, err := rawRowsForGroup(proof.PointSamplings[q][e.BatchIdx], injIdx)
					if err != nil {
						return fmt.Errorf("fri: PCS.Verify: compact proof group %d: %w", injIdx, err)
					}

					var leafP, leafQ ext.E6
					if e.Field == field.Base {
						leafP = hash.LiftBaseToExt(raw.Lo.RawRowBase[e.PolyIdx])
						leafQ = hash.LiftBaseToExt(raw.Hi.RawRowBase[e.PolyIdx])
					} else {
						leafP.Set(&raw.Lo.RawRowExt[e.PolyIdx])
						leafQ.Set(&raw.Hi.RawRowExt[e.PolyIdx])
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
