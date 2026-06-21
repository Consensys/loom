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

// Canonical DEEP-quotient layout enumeration. Walking the canonical layout
// in order gives both prover and verifier the same per-(size, shift) bundle
// schedule and the same alpha_DEEP power assignment. The frozen ordering is:
//
//   for native size N in DECREASING order:
//     for shift s in ASCENDING order:
//       for batch b in DECLARATION order:
//         for the unique size-N group g in batches[b] (skip if absent):
//           for poly i in g.Base then g.Ext (declaration order):
//             if s in shifts[b][g].Base|Ext[i]:
//               emit a deepEntry; consume the next alpha_DEEP power.
//
// The alpha_DEEP power counter resets to 0 at each new size. Within one
// size, the counter is monotonic across shifts -- consecutive (N, s)
// bundles share the per-size sequence.
//
// canonicalLayout is the only producer of layout values; later PRs consume
// them inside PCS.Open / PCS.Verify.

import (
	"fmt"
	"sort"

	"github.com/consensys/loom/field"
)

// deepEntry identifies a single (batch, group, polynomial) triple that
// participates in the DEEP quotient at the parent shiftBundle's shift.
type deepEntry struct {
	BatchIdx int
	GroupIdx int
	PolyIdx  int
	Field    field.Kind
}

// shiftBundle is the set of deepEntries sharing one rotation shift inside a
// sizeBundle. Every polynomial in Entries is opened at zeta * omega_N^Shift
// for the parent sizeBundle's N.
type shiftBundle struct {
	Shift   int
	Entries []deepEntry
}

// sizeBundle is the canonical enumeration of polynomials of one native
// size that participate in the DEEP quotient. Bundles is sorted by
// ascending Shift. Walking Bundles in order, then Entries in order, yields
// the alpha_DEEP power assignment for this size's DEEP polynomial DQ_N.
type sizeBundle struct {
	N       int
	Bundles []shiftBundle
}

// layout is the full canonical enumeration of every committed polynomial
// across all batches. Indexed by descending native size, then by ascending
// shift, then by batch declaration order, then by per-Group poly
// declaration order (base rail before ext rail).
type layout []sizeBundle

// canonicalLayout walks batches + shifts and produces the canonical
// enumeration described above. It also validates the shift schedule:
//
//   - shape alignment: len(shifts) == len(batches), per-batch group counts
//     match, per-group base/ext widths match;
//   - every poly's shift list is non-empty (every committed polynomial
//     must be opened at least once);
//   - no duplicate shifts inside a single poly's shift list.
//
// Per-batch group sizes are not re-validated here -- distinct sizes within
// one batch are an invariant enforced by PCS.Commit. Group sizes are
// inferred from the polynomial lengths in batches.
//
// canonicalLayout returns an empty layout (and nil error) when batches and
// shifts are both empty; that degenerate case represents "nothing to
// commit / open" and is up to the caller to disallow if needed.
func canonicalLayout(batches []Batch, shifts []BatchShifts) (layout, error) {
	if len(shifts) != len(batches) {
		return nil, fmt.Errorf("fri: shifts has %d entries, batches has %d", len(shifts), len(batches))
	}

	// 1- Validate shape alignment + per-poly shift schedules; record per-group sizes.
	sizes := make([][]int, len(batches))
	for b, batch := range batches {
		if len(shifts[b]) != len(batch) {
			return nil, fmt.Errorf("fri: shifts[%d] has %d Groups, batches[%d] has %d", b, len(shifts[b]), b, len(batch))
		}
		sizes[b] = make([]int, len(batch))
		for g, group := range batch {
			N, err := groupNativeSize(group)
			if err != nil {
				return nil, fmt.Errorf("fri: batches[%d][%d]: %w", b, g, err)
			}
			sizes[b][g] = N
			gShifts := shifts[b][g]
			if len(gShifts.Base) != len(group.Base) {
				return nil, fmt.Errorf("fri: shifts[%d][%d].Base has %d entries, batches[%d][%d].Base has %d", b, g, len(gShifts.Base), b, g, len(group.Base))
			}
			if len(gShifts.Ext) != len(group.Ext) {
				return nil, fmt.Errorf("fri: shifts[%d][%d].Ext has %d entries, batches[%d][%d].Ext has %d", b, g, len(gShifts.Ext), b, g, len(group.Ext))
			}
			if err := validatePolyShifts(b, g, "Base", gShifts.Base); err != nil {
				return nil, err
			}
			if err := validatePolyShifts(b, g, "Ext", gShifts.Ext); err != nil {
				return nil, err
			}
		}
	}

	// 2- Helper: locate the unique size-N Group inside batch b (-1 if absent).
	//    PCS.Commit guarantees distinct sizes per batch, so at most one g
	//    per (b, N).
	groupOfSize := func(b, N int) int {
		for g, n := range sizes[b] {
			if n == N {
				return g
			}
		}
		return -1
	}

	// 3- Collect distinct sizes across all batches; sort descending.
	sizeSet := make(map[int]struct{})
	for _, sb := range sizes {
		for _, n := range sb {
			sizeSet[n] = struct{}{}
		}
	}
	sizesDesc := make([]int, 0, len(sizeSet))
	for n := range sizeSet {
		sizesDesc = append(sizesDesc, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizesDesc)))

	// 4- For each size, collect the union of shifts that appear (across all
	//    batches contributing a size-N group), sort ascending, then
	//    enumerate entries in the canonical order.
	out := make(layout, 0, len(sizesDesc))
	for _, N := range sizesDesc {
		shiftSet := make(map[int]struct{})
		for b := range batches {
			g := groupOfSize(b, N)
			if g == -1 {
				continue
			}
			for _, polyShifts := range shifts[b][g].Base {
				for _, s := range polyShifts {
					shiftSet[s] = struct{}{}
				}
			}
			for _, polyShifts := range shifts[b][g].Ext {
				for _, s := range polyShifts {
					shiftSet[s] = struct{}{}
				}
			}
		}
		shiftsAsc := make([]int, 0, len(shiftSet))
		for s := range shiftSet {
			shiftsAsc = append(shiftsAsc, s)
		}
		sort.Ints(shiftsAsc)

		bundles := make([]shiftBundle, 0, len(shiftsAsc))
		for _, s := range shiftsAsc {
			var entries []deepEntry
			for b := range batches {
				g := groupOfSize(b, N)
				if g == -1 {
					continue
				}
				for i, polyShifts := range shifts[b][g].Base {
					if containsInt(polyShifts, s) {
						entries = append(entries, deepEntry{
							BatchIdx: b, GroupIdx: g, PolyIdx: i, Field: field.Base,
						})
					}
				}
				for i, polyShifts := range shifts[b][g].Ext {
					if containsInt(polyShifts, s) {
						entries = append(entries, deepEntry{
							BatchIdx: b, GroupIdx: g, PolyIdx: i, Field: field.Ext,
						})
					}
				}
			}
			bundles = append(bundles, shiftBundle{Shift: s, Entries: entries})
		}
		out = append(out, sizeBundle{N: N, Bundles: bundles})
	}
	return out, nil
}

// validatePolyShifts enforces the per-poly invariants on one rail's
// shift schedule: every shift list non-empty, no duplicate shifts inside
// a single list. Returns descriptive errors for both failure modes.
func validatePolyShifts(b, g int, rail string, polyShifts [][]int) error {
	for i, ss := range polyShifts {
		if len(ss) == 0 {
			return fmt.Errorf("fri: shifts[%d][%d].%s[%d] is empty (every committed polynomial must be opened at least once)", b, g, rail, i)
		}
		seen := make(map[int]struct{}, len(ss))
		for _, s := range ss {
			if _, dup := seen[s]; dup {
				return fmt.Errorf("fri: shifts[%d][%d].%s[%d] contains duplicate shift %d", b, g, rail, i, s)
			}
			seen[s] = struct{}{}
		}
	}
	return nil
}

// containsInt reports whether v appears in xs. xs is expected to be very
// short (typically 1-2 shifts per polynomial), so a linear scan beats any
// hashed-set overhead.
func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
