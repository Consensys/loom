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

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/field"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/poly"
)

// deepAlphaName is the transcript challenge name under which Open binds
// the canonical-layout-ordered claimed evaluations and from which the
// DEEP batching challenge alpha_DEEP is sampled. Kept as a private
// constant so the existing outer-prover code (which uses
// constants.DEEP_ALPHA with the same string value) remains source-
// compatible until the migration PR rewires it.
const deepAlphaName = "alpha_DEEP"

// OpenConfig configures an Open call.
type OpenConfig struct {
	DomainCache *poly.DomainCache
}

// OpenOption configures Open.
type OpenOption func(c *OpenConfig) error

// WithOpenDomainCache lets Open reuse a domain cache shared with Commit
// so FFT-domain pre-computations are not duplicated across calls.
func WithOpenDomainCache(cache *poly.DomainCache) OpenOption {
	return func(c *OpenConfig) error {
		c.DomainCache = cache
		return nil
	}
}

// ClaimedValuesOnly evaluates every polynomial in batches at every shift
// listed in shifts and returns the per-batch BatchClaimedValues. No
// transcript activity, no DEEP-quotient construction, no FRI. Suited to
// SkipFRI-style smoke tests where the caller wants the AIR-check-side
// values without paying for the PCS proof.
//
// The output shape mirrors shifts: a value per (batch, group, base/ext
// rail, polyIdx, kth_shift) tuple, evaluated at zeta * omega_N^shift.
// Identical content to the OpeningProof.ClaimedValues that pcs.Open
// would have produced for the same inputs.
func (pcs *PCS) ClaimedValuesOnly(
	batches []Batch,
	shifts []BatchShifts,
	zeta ext.E6,
	opts ...OpenOption,
) ([]BatchClaimedValues, error) {
	var config OpenConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return nil, err
		}
	}
	domainCache := config.DomainCache
	if domainCache == nil {
		domainCache = &poly.DomainCache{}
	}
	if _, err := canonicalLayout(batches, shifts); err != nil {
		return nil, err
	}
	return computeClaimedValues(batches, shifts, zeta, domainCache)
}

// Open produces an OpeningProof that every polynomial in batches
// evaluates to the listed values at zeta and at the rotation shifts in
// shifts. committed[b] must have been returned by Commit(batches[b], ...).
// The shared Fiat-Shamir transcript fs must already have absorbed each
// committed[b].Tree.Root() at the round the caller chose, and must have
// sampled zeta.
//
// Open registers alpha_DEEP and FRI-internal challenge names on fs
// itself; the caller MUST NOT pre-register any of those names. Open is
// responsible for binding claimed values in canonical layout order,
// sampling alpha_DEEP, building per-size DEEP-quotient codewords,
// committing them as multi-degree FRI levels, running fri.Prove, and
// packaging per-query / per-batch Merkle openings.
func (pcs *PCS) Open(
	batches []Batch,
	committed []Committed,
	shifts []BatchShifts,
	zeta ext.E6,
	fs *fiatshamir.Transcript,
	opts ...OpenOption,
) (OpeningProof, error) {
	if pcs.params == nil {
		return OpeningProof{}, fmt.Errorf("fri: PCS.Open requires Params; construct PCS via NewPCSWithParams")
	}
	if len(committed) != len(batches) {
		return OpeningProof{}, fmt.Errorf("fri: PCS.Open: committed has %d entries, batches has %d", len(committed), len(batches))
	}
	if fs == nil {
		return OpeningProof{}, fmt.Errorf("fri: PCS.Open: fs transcript is required")
	}

	var config OpenConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return OpeningProof{}, err
		}
	}
	domainCache := config.DomainCache
	if domainCache == nil {
		domainCache = &poly.DomainCache{}
	}

	// 1- Canonical layout: validates shape alignment + per-poly shift
	//    invariants (non-empty, no duplicates).
	lay, err := canonicalLayout(batches, shifts)
	if err != nil {
		return OpeningProof{}, err
	}

	// 2- Claimed values at zeta * omega_N^s for every (b, g, i, s) in
	//    the schedule.
	claimedValues, err := computeClaimedValues(batches, shifts, zeta, domainCache)
	if err != nil {
		return OpeningProof{}, err
	}

	// 3- Pre-register alpha_DEEP. FRI-internal names (fri_fold_*,
	//    fri_level_*_gamma, fri_query_*) are registered inside fri.Prove.
	if err := fs.NewChallenge(deepAlphaName); err != nil {
		return OpeningProof{}, fmt.Errorf("fri: PCS.Open: register alpha_DEEP: %w", err)
	}

	// 4- Bind every claimed value to alpha_DEEP in canonical layout
	//    order (size desc, shift asc, batch decl order, base-then-ext,
	//    per-rail decl order).
	if err := bindClaimedValuesInLayoutOrder(fs, claimedValues, shifts, lay); err != nil {
		return OpeningProof{}, err
	}

	// 5- Sample alpha_DEEP.
	alphaOut, err := fs.ComputeChallenge(deepAlphaName)
	if err != nil {
		return OpeningProof{}, fmt.Errorf("fri: PCS.Open: sample alpha_DEEP: %w", err)
	}
	alpha := hash.OutputToExt(alphaOut)

	// 6- Build one DEEP-quotient codeword per distinct native size, on
	//    the RS-encoded subgroup of size rate*N.
	deepEvalsBySize, sizesDesc, err := computeDeepQuotientCodewords(
		batches, shifts, claimedValues, lay, alpha, zeta, pcs.rate, domainCache,
	)
	if err != nil {
		return OpeningProof{}, err
	}

	// 7- Commit each DQ_N as a fresh FRI level. Largest size becomes
	//    level 0; smaller sizes enter at the round whose running
	//    polynomial bound matches their D.
	levels := make([]Level, len(sizesDesc))
	deepRoots := make([]hash.Digest, len(sizesDesc))
	for i, N := range sizesDesc {
		tree, err := pcs.params.BuildLevelTreeExt(deepEvalsBySize[N])
		if err != nil {
			return OpeningProof{}, fmt.Errorf("fri: PCS.Open: BuildLevelTreeExt N=%d: %w", N, err)
		}
		levels[i] = Level{
			D:     N,
			Evals: LevelEvals{Ext: deepEvalsBySize[N]},
			Tree:  tree,
		}
		deepRoots[i] = tree.Root()
	}

	// 8- Run multi-degree FRI on the level set.
	friProof, queryPositions, err := Prove(*pcs.params, levels, fs)
	if err != nil {
		return OpeningProof{}, fmt.Errorf("fri: PCS.Open: fri.Prove: %w", err)
	}

	// 9- For each query position, open every committed batch's tree at
	//    the matching folded position and package one compact Merkle proof.
	pointSamplings := make([][]WMerkleProof, len(queryPositions))
	for q, sQ := range queryPositions {
		pointSamplings[q] = make([]WMerkleProof, len(committed))
		for b := range committed {
			wp, err := openCommittedAt(committed[b], sQ, pcs.params.N)
			if err != nil {
				return OpeningProof{}, fmt.Errorf("fri: PCS.Open: query %d, batch %d: %w", q, b, err)
			}
			pointSamplings[q][b] = wp
		}
	}

	return OpeningProof{
		ClaimedValues:     claimedValues,
		DeepQuotientRoots: deepRoots,
		FRIProof:          friProof,
		PointSamplings:    pointSamplings,
	}, nil
}

// bindClaimedValuesInLayoutOrder walks lay in canonical order and binds
// each entry's claimed value to alpha_DEEP. The order MUST match the
// order in which computeDeepQuotientCodewords consumes alpha-powers,
// otherwise the prover and verifier disagree on the binding sequence and
// reject each other's transcript.
func bindClaimedValuesInLayoutOrder(
	fs *fiatshamir.Transcript,
	claimedValues []BatchClaimedValues,
	shifts []BatchShifts,
	lay layout,
) error {
	for _, sb := range lay {
		for _, shB := range sb.Bundles {
			for _, e := range shB.Entries {
				gShifts := shifts[e.BatchIdx][e.GroupIdx]
				gValues := claimedValues[e.BatchIdx][e.GroupIdx]
				var v ext.E6
				if e.Field == field.Base {
					kth := containsIntIndex(gShifts.Base[e.PolyIdx], shB.Shift)
					v = gValues.Base[e.PolyIdx][kth]
				} else {
					kth := containsIntIndex(gShifts.Ext[e.PolyIdx], shB.Shift)
					v = gValues.Ext[e.PolyIdx][kth]
				}
				if err := fs.Bind(deepAlphaName, hash.ExtToElements(v)); err != nil {
					return fmt.Errorf("fri: bind claimed value (batch=%d group=%d poly=%d field=%s shift=%d): %w",
						e.BatchIdx, e.GroupIdx, e.PolyIdx, e.Field, shB.Shift, err)
				}
			}
		}
	}
	return nil
}

// openCommittedAt opens a Committed batch at the full FRI query row sQ. It
// builds the compact proof shape: one top-level row pair, one Merkle path from
// the top lo row, and one raw row pair per injected smaller group.
func openCommittedAt(c Committed, sQ int, maxRows int) (WMerkleProof, error) {
	if c.Tree.Tree == nil {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: WMerkleTree is uninitialised")
	}
	topLeafCount := c.Tree.NumLeaves()
	if topLeafCount == 0 {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: empty WMerkleTree")
	}
	if len(c.Sources) == 0 {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: no LeafSources retained")
	}
	if maxRows <= 0 || maxRows&(maxRows-1) != 0 {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: maxRows=%d must be a positive power of two", maxRows)
	}
	if topLeafCount > maxRows {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: top rows %d exceeds maxRows %d", topLeafCount, maxRows)
	}

	topRows := leafSourceRows(c.Sources[0])
	if topRows != topLeafCount {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: top source rows %d != tree leaves %d", topRows, topLeafCount)
	}

	topGlobalReduction := log2(maxRows) - log2(topRows)
	if topGlobalReduction < 0 {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: top rows %d exceeds maxRows %d", topRows, maxRows)
	}
	topRow := sQ >> topGlobalReduction
	topLo, topHi := siblingRows(topRow)
	topRowPair, err := rawRowPairFromSource(c.Sources[0], topLo, topHi)
	if err != nil {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: top rows: %w", err)
	}
	path, err := c.Tree.OpenProof(topLo)
	if err != nil {
		return WMerkleProof{}, fmt.Errorf("openCommittedAt: top proof row=%d: %w", topLo, err)
	}

	injections := make([]WMerkleInjectionOpening, 0, len(c.Sources)-1)
	for k, src := range c.Sources[1:] {
		sourceIdx := k + 1
		groupRows := leafSourceRows(src)
		if groupRows <= 0 {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d has insufficient encoded rows %d", sourceIdx, groupRows)
		}
		if groupRows > maxRows {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d rows %d exceeds maxRows %d", sourceIdx, groupRows, maxRows)
		}
		if groupRows&(groupRows-1) != 0 {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d rows %d is not a power of two", sourceIdx, groupRows)
		}

		globalReduction := log2(maxRows) - log2(groupRows)
		row := sQ >> globalReduction
		lo, hi := siblingRows(row)
		rows, err := rawRowPairFromSource(src, lo, hi)
		if err != nil {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d rows: %w", sourceIdx, err)
		}

		topReduction := log2(topRows) - log2(groupRows)
		if topReduction < 0 {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d rows %d exceeds top rows %d", sourceIdx, groupRows, topRows)
		}
		pathRowAtWidth := topLo >> topReduction
		siblingRunning, err := c.Tree.Tree.PreInjectionSibling(groupRows, pathRowAtWidth)
		if err != nil {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d pre-injection sibling: %w", sourceIdx, err)
		}

		injections = append(injections, WMerkleInjectionOpening{
			Rows:           rows,
			SiblingRunning: siblingRunning,
		})
	}

	return WMerkleProof{
		TopRows:    topRowPair,
		Path:       path,
		Injections: injections,
	}, nil
}

func leafSourceRows(src LeafSource) int {
	if len(src.Base) > 0 {
		return len(src.Base[0])
	}
	if len(src.Ext) > 0 {
		return len(src.Ext[0])
	}
	return 0
}

func rawRowPairFromSource(src LeafSource, lo int, hi int) (RawRowPair, error) {
	loRow, err := rawRowFromSource(src, lo)
	if err != nil {
		return RawRowPair{}, fmt.Errorf("lo row %d: %w", lo, err)
	}
	hiRow, err := rawRowFromSource(src, hi)
	if err != nil {
		return RawRowPair{}, fmt.Errorf("hi row %d: %w", hi, err)
	}
	return RawRowPair{Lo: loRow, Hi: hiRow}, nil
}

func rawRowFromSource(src LeafSource, row int) (RawRow, error) {
	rows := leafSourceRows(src)
	if row < 0 || row >= rows {
		return RawRow{}, fmt.Errorf("row out of range [0, %d)", rows)
	}
	baseRow := make([]koalabear.Element, len(src.Base))
	for i, p := range src.Base {
		baseRow[i].Set(&p[row])
	}
	extRow := make([]ext.E6, len(src.Ext))
	for i, p := range src.Ext {
		extRow[i].Set(&p[row])
	}
	return RawRow{RawRowBase: baseRow, RawRowExt: extRow}, nil
}
