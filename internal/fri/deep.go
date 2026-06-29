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

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/parallel"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

// deepQuotientBundle bundles one (size, shift) worth of pre-multiplied
// alpha-power scales and the original Lagrange-form column data they
// reference, so the per-row accumulator loop has no cross-column data
// dependency and can be chunked across goroutines.
//
// Mirrors the existing prover-side deepQuotientBundle minus the
// constContrib slot: the new PCS API has no length-1 ("constant") columns
// inside a Group -- every polynomial shares one native size -- so
// per-bundle constants don't exist anymore.
type deepQuotientBundle struct {
	zs ext.E6 // z_s = zeta * omega_N^shift
	vs ext.E6 // sum_k alpha^e_k * v_k for the entries in this bundle

	baseCols   []poly.Polynomial    // each of length N (original Lagrange form on the trace subgroup)
	baseScales []ext.E6             // alpha^e_k for the matching baseCols entry
	extCols    []poly.ExtPolynomial // each of length N
	extScales  []ext.E6
}

// deepShiftTerm is one requested opening point for one polynomial in the
// per-polynomial DEEP quotient path.
type deepShiftTerm struct {
	zs    ext.E6 // z_s = zeta * omega_N^shift
	value ext.E6 // claimed value P(z_s)
}

// deepPolyBundle is the target D2 grouping: all shift terms of one polynomial
// are summed deterministically, then one alpha_DEEP power folds the resulting
// per-polynomial quotient with the other polynomials of the same native size.
type deepPolyBundle struct {
	field field.Kind
	scale ext.E6

	baseCol poly.Polynomial
	extCol  poly.ExtPolynomial
	shifts  []deepShiftTerm
}

// computeDeepQuotientCodewords builds one DEEP-quotient codeword DQ_N per
// distinct native size in lay, on the RS-encoded subgroup of size rate*N.
//
// The DEEP quotient polynomial has degree < N and is built directly on
// the trace subgroup (Lagrange form, N points), then encoded once to the
// size-rate*N subgroup. Working on N points instead of rate*N halves the
// per-row arithmetic; the encoding FFT cost is amortised against the
// shared domain cache.
//
// Canonical layout walked: size descending, shift ascending, batch
// declaration order, base-then-ext rail, per-rail declaration order. The
// alpha-power counter resets to 0 at each new size and is monotonic
// within the size across all shifts (the convention frozen in pcs.txt).
//
// For each (N, shift s) bundle, the size-N contribution is
//
//	deepLagrange[x] += sum_{e in bundle} alpha^e_e * (v_e - p_e[x])
//	                   / (z_s - omega_N^x)
//
// for x = 0..N-1. After all bundles for a given size are folded in,
// deepLagrange is RS-encoded to size rate*N for FRI consumption.
//
// Returns (deepEvalsBySize map[N -> codeword], sizesDesc) so the caller
// can feed multi-degree FRI levels in descending-size order.
func computeDeepQuotientCodewords(
	batches []Batch,
	shifts []BatchShifts,
	claimedValues []BatchClaimedValues,
	lay layout,
	alpha ext.E6,
	zeta ext.E6,
	rate uint64,
	domainCache *poly.DomainCache,
) (map[int][]ext.E6, []int, error) {
	if len(shifts) != len(batches) {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewords: shifts has %d entries, batches has %d", len(shifts), len(batches))
	}
	if len(claimedValues) != len(batches) {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewords: claimedValues has %d entries, batches has %d", len(claimedValues), len(batches))
	}
	if rate == 0 || rate&(rate-1) != 0 {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewords: rate %d must be a positive power of two", rate)
	}

	deepEvalsBySize := make(map[int][]ext.E6, len(lay))
	sizesDesc := make([]int, 0, len(lay))

	for _, sb := range lay {
		N := sb.N
		ratN := uint64(rate) * uint64(N)
		traceDomain := domainCache.Get(uint64(N))

		// Walk lay's per-shift bundles, gather the original (Lagrange-form)
		// columns and pre-multiplied alpha-power scales. The alpha-power
		// counter resets at the start of each size and runs monotonically
		// across all shifts within the size.
		bundles := make([]deepQuotientBundle, 0, len(sb.Bundles))
		var alphaRunning ext.E6
		alphaRunning.SetOne() // alpha^0

		for _, shB := range sb.Bundles {
			// z_s = zeta * omega_N^s
			var omegaShift koalabear.Element
			omegaShift.Exp(traceDomain.Generator, big.NewInt(int64(shB.Shift)))
			var zs ext.E6
			zs.MulByElement(&zeta, &omegaShift)

			bun := deepQuotientBundle{zs: zs}
			for _, e := range shB.Entries {
				group := batches[e.BatchIdx][e.GroupIdx]
				gShifts := shifts[e.BatchIdx][e.GroupIdx]
				gValues := claimedValues[e.BatchIdx][e.GroupIdx]

				var scale ext.E6
				scale.Set(&alphaRunning)

				if e.Field == field.Base {
					kth := containsIntIndex(gShifts.Base[e.PolyIdx], shB.Shift)
					v := gValues.Base[e.PolyIdx][kth]
					var term ext.E6
					term.Mul(&v, &scale)
					bun.vs.Add(&bun.vs, &term)
					bun.baseCols = append(bun.baseCols, group.Base[e.PolyIdx])
					bun.baseScales = append(bun.baseScales, scale)
				} else { // field.Ext
					kth := containsIntIndex(gShifts.Ext[e.PolyIdx], shB.Shift)
					v := gValues.Ext[e.PolyIdx][kth]
					var term ext.E6
					term.Mul(&v, &scale)
					bun.vs.Add(&bun.vs, &term)
					bun.extCols = append(bun.extCols, group.Ext[e.PolyIdx])
					bun.extScales = append(bun.extScales, scale)
				}
				alphaRunning.Mul(&alphaRunning, &alpha)
			}
			bundles = append(bundles, bun)
		}

		// Build DQ in Lagrange form on the size-N trace subgroup.
		deepLagrange := make(poly.ExtPolynomial, N)
		accumulateDeepQuotientOnTrace(deepLagrange, bundles, traceDomain)

		// Encode the size-N Lagrange representation to the size-rate*N RS
		// subgroup. The shared domain cache means the encoder picks up
		// pre-built FFT domains and does not pay a cold-cache cost.
		encoder := reedsolomon.NewEncoder(ratN, reedsolomon.WithCache(domainCache))
		deepEncoded := encoder.EncodeExt(deepLagrange, traceDomain)
		deepEvalsBySize[N] = deepEncoded
		sizesDesc = append(sizesDesc, N)
	}
	return deepEvalsBySize, sizesDesc, nil
}

// computeDeepQuotientCodewordsByPolynomial builds one DEEP-quotient codeword
// per distinct native size using the per-polynomial D2 convention. For each
// polynomial P_i, all requested shifts are first summed:
//
//	B_i(X) = sum_s (v_i,s - P_i(X)) / (z_i,s - X)
//
// Then the per-size quotient folds those polynomial bundles with alpha powers:
//
//	DQ_N(X) = sum_i alpha^i * B_i(X)
//
// The alpha counter resets at each native size and runs in deterministic order:
// size descending, batch declaration order, group declaration order, base rail
// then extension rail.
func computeDeepQuotientCodewordsByPolynomial(
	batches []Batch,
	shifts []BatchShifts,
	claimedValues []BatchClaimedValues,
	alpha ext.E6,
	zeta ext.E6,
	rate uint64,
	domainCache *poly.DomainCache,
) (map[int][]ext.E6, []int, error) {
	if len(claimedValues) != len(batches) {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: claimedValues has %d entries, batches has %d", len(claimedValues), len(batches))
	}
	if rate == 0 || rate&(rate-1) != 0 {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: rate %d must be a positive power of two", rate)
	}
	if err := validateBatchShifts(batches, shifts); err != nil {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: %w", err)
	}
	sizes, err := groupNativeSizesFromBatches(batches)
	if err != nil {
		return nil, nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: %w", err)
	}
	sizesDesc := sizesDescFromSizes(sizes)

	deepEvalsBySize := make(map[int][]ext.E6, len(sizesDesc))
	for _, N := range sizesDesc {
		ratN := uint64(rate) * uint64(N)
		traceDomain := domainCache.Get(uint64(N))

		bundles, err := deepPolyBundlesForSize(N, batches, sizes, shifts, claimedValues, alpha, zeta, traceDomain)
		if err != nil {
			return nil, nil, err
		}

		deepLagrange := make(poly.ExtPolynomial, N)
		accumulateDeepQuotientByPolynomialOnTrace(deepLagrange, bundles, traceDomain)

		encoder := reedsolomon.NewEncoder(ratN, reedsolomon.WithCache(domainCache))
		deepEncoded := encoder.EncodeExt(deepLagrange, traceDomain)
		deepEvalsBySize[N] = deepEncoded
	}
	return deepEvalsBySize, sizesDesc, nil
}

func deepPolyBundlesForSize(
	N int,
	batches []Batch,
	sizes [][]int,
	shifts []BatchShifts,
	claimedValues []BatchClaimedValues,
	alpha ext.E6,
	zeta ext.E6,
	traceDomain *fft.Domain,
) ([]deepPolyBundle, error) {
	var bundles []deepPolyBundle
	var alphaRunning ext.E6
	alphaRunning.SetOne()

	for b, batch := range batches {
		if len(claimedValues[b]) != len(batch) {
			return nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: claimedValues[%d] has %d groups, batches[%d] has %d", b, len(claimedValues[b]), b, len(batch))
		}
		for g, group := range batch {
			if sizes[b][g] != N {
				continue
			}
			gShifts := shifts[b][g]
			gValues := claimedValues[b][g]
			if len(gValues.Base) != len(group.Base) {
				return nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: claimedValues[%d][%d].Base has %d entries, group has %d base polys", b, g, len(gValues.Base), len(group.Base))
			}
			if len(gValues.Ext) != len(group.Ext) {
				return nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: claimedValues[%d][%d].Ext has %d entries, group has %d ext polys", b, g, len(gValues.Ext), len(group.Ext))
			}

			for i, col := range group.Base {
				if len(gValues.Base[i]) != len(gShifts.Base[i]) {
					return nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: claimedValues[%d][%d].Base[%d] has %d values, shifts has %d", b, g, i, len(gValues.Base[i]), len(gShifts.Base[i]))
				}
				bundles = append(bundles, deepPolyBundle{
					field:   field.Base,
					scale:   alphaRunning,
					baseCol: col,
					shifts:  deepShiftTerms(gShifts.Base[i], gValues.Base[i], N, zeta, traceDomain),
				})
				alphaRunning.Mul(&alphaRunning, &alpha)
			}
			for i, col := range group.Ext {
				if len(gValues.Ext[i]) != len(gShifts.Ext[i]) {
					return nil, fmt.Errorf("fri: computeDeepQuotientCodewordsByPolynomial: claimedValues[%d][%d].Ext[%d] has %d values, shifts has %d", b, g, i, len(gValues.Ext[i]), len(gShifts.Ext[i]))
				}
				bundles = append(bundles, deepPolyBundle{
					field:  field.Ext,
					scale:  alphaRunning,
					extCol: col,
					shifts: deepShiftTerms(gShifts.Ext[i], gValues.Ext[i], N, zeta, traceDomain),
				})
				alphaRunning.Mul(&alphaRunning, &alpha)
			}
		}
	}
	return bundles, nil
}

func deepShiftTerms(shifts []int, values []ext.E6, N int, zeta ext.E6, traceDomain *fft.Domain) []deepShiftTerm {
	terms := make([]deepShiftTerm, len(shifts))
	for i, s := range shifts {
		var omegaShift koalabear.Element
		omegaShift.Exp(traceDomain.Generator, big.NewInt(int64(normalizeShift(s, N))))
		terms[i].zs.MulByElement(&zeta, &omegaShift)
		terms[i].value = values[i]
	}
	return terms
}

func accumulateDeepQuotientByPolynomialOnTrace(deep poly.ExtPolynomial, bundles []deepPolyBundle, traceDomain *fft.Domain) {
	N := len(deep)
	if N == 0 || len(bundles) == 0 {
		return
	}

	parallel.Execute(N, func(start, end int) {
		chunkLen := end - start

		xs := make([]ext.E6, chunkLen)
		var omegaX koalabear.Element
		if start == 0 {
			omegaX.SetOne()
		} else {
			omegaX.Exp(traceDomain.Generator, big.NewInt(int64(start)))
		}
		for x := range xs {
			xs[x] = hash.LiftBaseToExt(omegaX)
			omegaX.Mul(&omegaX, &traceDomain.Generator)
		}

		for b := range bundles {
			bun := &bundles[b]
			denoms := make([]ext.E6, chunkLen*len(bun.shifts))
			for t, sh := range bun.shifts {
				for x := 0; x < chunkLen; x++ {
					denoms[t*chunkLen+x].Sub(&sh.zs, &xs[x])
				}
			}
			invs := ext.BatchInvertE6(denoms)

			for x := start; x < end; x++ {
				var px ext.E6
				if bun.field == field.Base {
					px = hash.LiftBaseToExt(bun.baseCol[x])
				} else {
					px.Set(&bun.extCol[x])
				}

				row := x - start
				var sum ext.E6
				for t, sh := range bun.shifts {
					var num, term ext.E6
					num.Sub(&sh.value, &px)
					term.Mul(&num, &invs[t*chunkLen+row])
					sum.Add(&sum, &term)
				}
				sum.Mul(&sum, &bun.scale)
				deep[x].Add(&deep[x], &sum)
			}
		}
	})
}

// accumulateDeepQuotientOnTrace adds every bundle's DEEP-quotient
// contribution into deep on the size-N trace subgroup. Uses a single
// row-chunked parallel pass: per chunk it computes (z_s - omega_N^x) for
// every bundle in one BatchInvertE6 call, then sweeps the bundles to
// fold each (vs - sum_k scale_k * col_k[x]) numerator and multiply by
// the matching inverse.
//
// Mirrors the existing prover-side accumulateDeepQuotient minus the
// const-column contribution (the new API has no length-1 columns inside
// a Group, so per-bundle constants don't exist).
func accumulateDeepQuotientOnTrace(deep poly.ExtPolynomial, bundles []deepQuotientBundle, traceDomain *fft.Domain) {
	N := len(deep)
	if N == 0 || len(bundles) == 0 {
		return
	}

	parallel.Execute(N, func(start, end int) {
		chunkLen := end - start

		// Denominators (z_s - omega_N^x) for every bundle, all flattened
		// into one buffer so a single BatchInvertE6 call amortises the
		// inversion cost.
		denoms := make([]ext.E6, chunkLen*len(bundles))
		var omegaX koalabear.Element
		if start == 0 {
			omegaX.SetOne()
		} else {
			omegaX.Exp(traceDomain.Generator, big.NewInt(int64(start)))
		}
		for x := 0; x < chunkLen; x++ {
			omegaExt := hash.LiftBaseToExt(omegaX)
			for b := range bundles {
				denoms[b*chunkLen+x].Sub(&bundles[b].zs, &omegaExt)
			}
			omegaX.Mul(&omegaX, &traceDomain.Generator)
		}
		invs := ext.BatchInvertE6(denoms)

		// Sweep bundles into deep row by row.
		for b := range bundles {
			bun := &bundles[b]
			invRow := invs[b*chunkLen : (b+1)*chunkLen]
			for x := start; x < end; x++ {
				var Cx ext.E6
				for k, col := range bun.extCols {
					var term ext.E6
					term.Mul(&bun.extScales[k], &col[x])
					Cx.Add(&Cx, &term)
				}
				for k, col := range bun.baseCols {
					var term ext.E6
					term.MulByElement(&bun.baseScales[k], &col[x])
					Cx.Add(&Cx, &term)
				}
				var num, dqx ext.E6
				num.Sub(&bun.vs, &Cx)
				dqx.Mul(&num, &invRow[x-start])
				deep[x].Add(&deep[x], &dqx)
			}
		}
	})
}

// containsIntIndex returns the position of v in xs, or panics if absent.
// Used to locate the kth_shift index of an entry's shift inside its
// polynomial's shift list. canonicalLayout's enumeration guarantees the
// shift IS present (entries are emitted only for polys whose shift list
// contains the bundle's shift), so a missing v signals a layout/shifts
// drift bug rather than caller input -- panic is the right loud failure.
func containsIntIndex(xs []int, v int) int {
	for i, x := range xs {
		if x == v {
			return i
		}
	}
	panic(fmt.Sprintf("fri: shift %d not found in shift list %v (canonical-layout/shifts mismatch)", v, xs))
}
