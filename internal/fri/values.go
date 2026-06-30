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
	"github.com/consensys/loom/internal/poly"
)

// computeClaimedValues evaluates every polynomial in batches at every
// rotation shift declared in shifts. The output shape mirrors shifts
// exactly: out[b][g].Base[i][k] is batches[b][g].Base[i] evaluated at
// zeta * omega_N^shifts[b][g].Base[i][k], where N is the native size of
// batches[b][g]. Same for the .Ext rail.
//
// Per-size Lagrange-at-zeta caches are built once via poly.LagrangesAtZeta
// and reused across every polynomial of that size, regardless of which
// batch, group, or shift it belongs to. The supplied domainCache is
// retained as a parameter for forward compatibility with future helpers
// that may need it; LagrangesAtZeta itself does not consult it.
//
// Shift normalization: shifts are integers and Open's contract says they
// represent the integer s such that the polynomial is evaluated at
// zeta * omega_N^s. computeClaimedValues normalizes s into [0, N) via
// mathematical modulo so the underlying EvaluateLagrangeAtExt index
// arithmetic (uses Go's `%`) stays in bounds for negative and
// large-positive shifts alike.
//
// computeClaimedValues only enforces shape alignment (lengths match across
// batches/shifts and per-rail widths match). The empty-list and duplicate-shift
// invariants are enforced by validateBatchShifts / validateBatchShiftsFromShapes,
// which Open and Verify call before deriving alpha_DEEP.
func computeClaimedValues(batches []Batch, shifts []BatchShifts, zeta ext.E6, domainCache *poly.DomainCache) ([]BatchClaimedValues, error) {
	_ = domainCache // reserved for forward compatibility

	if len(shifts) != len(batches) {
		return nil, fmt.Errorf("fri: computeClaimedValues: shifts has %d entries, batches has %d", len(shifts), len(batches))
	}

	// Build per-size Lagrange-at-zeta caches once. Reused by every
	// polynomial of that size, across batches, groups, and rails.
	lagrangesByN := make(map[int][]ext.E6)
	groupSizes := make([][]int, len(batches))
	for b, batch := range batches {
		if len(shifts[b]) != len(batch) {
			return nil, fmt.Errorf("fri: computeClaimedValues: shifts[%d] has %d Groups, batches[%d] has %d", b, len(shifts[b]), b, len(batch))
		}
		groupSizes[b] = make([]int, len(batch))
		for g, group := range batch {
			N, err := groupNativeSize(group)
			if err != nil {
				return nil, fmt.Errorf("fri: computeClaimedValues: batches[%d][%d]: %w", b, g, err)
			}
			groupSizes[b][g] = N
			if _, ok := lagrangesByN[N]; !ok {
				lagrangesByN[N] = poly.LagrangesAtZeta(zeta, N)
			}
			if len(shifts[b][g].Base) != len(group.Base) {
				return nil, fmt.Errorf("fri: computeClaimedValues: shifts[%d][%d].Base has %d entries, group has %d base polys", b, g, len(shifts[b][g].Base), len(group.Base))
			}
			if len(shifts[b][g].Ext) != len(group.Ext) {
				return nil, fmt.Errorf("fri: computeClaimedValues: shifts[%d][%d].Ext has %d entries, group has %d ext polys", b, g, len(shifts[b][g].Ext), len(group.Ext))
			}
		}
	}

	out := make([]BatchClaimedValues, len(batches))
	for b, batch := range batches {
		out[b] = make(BatchClaimedValues, len(batch))
		for g, group := range batch {
			N := groupSizes[b][g]
			lagranges := lagrangesByN[N]
			gShifts := shifts[b][g]

			out[b][g].Base = make([][]ext.E6, len(group.Base))
			for i, p := range group.Base {
				ss := gShifts.Base[i]
				values := make([]ext.E6, len(ss))
				for k, s := range ss {
					values[k] = poly.EvaluateLagrangeAtExt(p, lagranges, normalizeShift(s, N))
				}
				out[b][g].Base[i] = values
			}

			out[b][g].Ext = make([][]ext.E6, len(group.Ext))
			for i, p := range group.Ext {
				ss := gShifts.Ext[i]
				values := make([]ext.E6, len(ss))
				for k, s := range ss {
					values[k] = poly.ExtEvaluateLagrangeAtExt(p, lagranges, normalizeShift(s, N))
				}
				out[b][g].Ext[i] = values
			}
		}
	}
	return out, nil
}

// normalizeShift reduces s into the range [0, N) using mathematical
// modulo so the underlying Lagrange-evaluation helpers' internal
// `(n+i-shift)%n` indexing stays in bounds for negative shifts and for
// shifts whose magnitude exceeds N.
func normalizeShift(s, N int) int {
	return ((s % N) + N) % N
}
