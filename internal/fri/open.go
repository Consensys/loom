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
	//    the matching folded position and package per-Group raw pairs.
	pointSamplings := make([][]WMerkleProof, len(queryPositions))
	for q, sQ := range queryPositions {
		pointSamplings[q] = make([]WMerkleProof, len(committed))
		for b := range committed {
			wp, err := openCommittedAt(committed[b], sQ)
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

// openCommittedAt opens a Committed batch at the query position sQ. The
// query position is reduced into the batch's top-group leaf count; from
// there each smaller Group's raw pairs sit at the corresponding folded
// position (idx >> bitsReduced), matching merkle.Tree.OpenProof's own
// indexing of injection leaves.
//
// Returns one RawLeaf per Group in decreasing-size order (same order as
// Committed.Sources and merkle.Proof.InjectionLeaves). Today, every
// Committed carries exactly one Group, so InjectionRawLeaves has length
// 1; the multi-group code path is fully wired and will activate when the
// outer prover starts batching multiple sizes per Commit.
func openCommittedAt(c Committed, sQ int) (WMerkleProof, error) {
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

	topPos := sQ % topLeafCount
	pth, err := c.Tree.OpenProof(topPos)
	if err != nil {
		return WMerkleProof{}, err
	}

	rawLeaves := make([]RawLeaf, len(c.Sources))
	for k, src := range c.Sources {
		groupHalfN := src.PairOffset
		if groupHalfN <= 0 {
			return WMerkleProof{}, fmt.Errorf("openCommittedAt: source %d has non-positive PairOffset %d", k, groupHalfN)
		}
		// Position in the group's own encoded coset. For the top group
		// (k=0, groupHalfN == topLeafCount), bitsReduced = 0 and pos =
		// topPos. For smaller groups, pos = topPos >> bitsReduced, the
		// same projection merkle.Tree.OpenProof uses for injection-leaf
		// lookups.
		bitsReduced := log2(topLeafCount) - log2(groupHalfN)
		pos := topPos >> bitsReduced

		baseLeaf := make([]PairBase, len(src.Base))
		for i, p := range src.Base {
			baseLeaf[i][0].Set(&p[pos])
			baseLeaf[i][1].Set(&p[pos+groupHalfN])
		}
		extLeaf := make([]PairExt, len(src.Ext))
		for i, p := range src.Ext {
			extLeaf[i][0].Set(&p[pos])
			extLeaf[i][1].Set(&p[pos+groupHalfN])
		}
		rawLeaves[k] = RawLeaf{RawLeafBase: baseLeaf, RawLeafExt: extLeaf}
	}

	return WMerkleProof{
		InjectionRawLeaves: rawLeaves,
		Proof:              pth,
	}, nil
}
