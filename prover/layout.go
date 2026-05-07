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

package prover

import (
	"sort"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
)

// Slot identifies the position of a single committed polynomial inside the
// flat (canonical) tree array used by the multi-degree commitment scheme.
//
//	TreeIdx = index into the canonical tree order
//	          (setup → trace-round-0 → … → trace-round-{r-1} → AIR)
//	PolyIdx = index of this polynomial inside that tree's RawLeaf entries
type Slot struct {
	TreeIdx int
	PolyIdx int
}

// Layout describes the canonical order of WMerkleTrees produced by the
// prover and consumed by the verifier. Both sides build it from the current
// `program` (so module sizes can be changed via program.SetSize between
// Compile and Prove and the layout adapts).
//
// Tree order (flat):
//
//	[setup, decreasing N] [trace-round-0, decreasing N] … [trace-round-{r-1}] [AIR, decreasing N]
//
// The setup section length is given by the verifier's PublicKey (i.e. the
// number of distinct sizes among program.PublicColumns).
type Layout struct {
	NumTrees int // total number of trees in the canonical order

	// Section boundaries, expressed as tree indices. SectionEnd is one past
	// the last tree of the section.
	SetupBegin int // = 0
	SetupEnd   int
	TraceBegin []int // [round] start of trace round r (== SetupEnd for round 0)
	TraceEnd   []int // [round] end of trace round r
	AIRBegin   int
	AIREnd     int // = NumTrees

	// Per-tree polynomial size N (the encoded tree has 2·N·RATE/2 leaves).
	TreeSize []int

	// Column-name → Slot for trace columns and setup public columns.
	ColSlot map[string]Slot

	// "module.chunkIdx" name → Slot for AIR-quotient chunks.
	AIRChunkSlot map[string]Slot
}

// BuildLayout builds the canonical commitment layout for a Prove/Verify run.
// `numSetupSizes` is the number of distinct sizes among the program's public
// columns (i.e. len(setup) on the prover side).
//
// The function is deterministic in `program` and `numSetupSizes`; it does not
// look at the trace.
func BuildLayout(program board.Program, numSetupSizes int) Layout {
	var layout Layout
	layout.ColSlot = make(map[string]Slot)
	layout.AIRChunkSlot = make(map[string]Slot)

	treeIdx := 0

	// ---- Setup section ----
	layout.SetupBegin = treeIdx
	{
		// Group public columns by size, decreasing N.
		colsByN := map[int][]string{}
		for _, c := range program.PublicColumns {
			m, ok := program.Modules[c.Module]
			if !ok {
				continue
			}
			colsByN[m.N] = append(colsByN[m.N], c.Name)
		}
		sizes := sortedSizesDesc(colsByN)
		for _, N := range sizes {
			cols := colsByN[N]
			sort.Strings(cols)
			for polyIdx, name := range cols {
				layout.ColSlot[name] = Slot{TreeIdx: treeIdx, PolyIdx: polyIdx}
			}
			layout.TreeSize = append(layout.TreeSize, N)
			treeIdx++
		}
	}
	layout.SetupEnd = treeIdx
	// Sanity: caller said how many setup sizes there should be. If it
	// disagrees with what we computed, prefer the caller's count for the
	// purpose of slicing PointSamplings; but the slot table is what we built.
	_ = numSetupSizes

	// ---- Trace section, per FS round ----
	numRounds := len(program.FScolumnsDependencies)
	layout.TraceBegin = make([]int, numRounds)
	layout.TraceEnd = make([]int, numRounds)
	for r, deps := range program.FScolumnsDependencies {
		layout.TraceBegin[r] = treeIdx

		// Group dependencies by size, decreasing N. Stable order within a
		// size group (matches prover's commit order).
		depsByN := map[int][]board.ColumnRef{}
		for _, dep := range deps {
			m, ok := program.Modules[dep.Module]
			if !ok {
				continue
			}
			depsByN[m.N] = append(depsByN[m.N], dep)
		}
		sizes := sortedSizesDesc(depsByN)
		for _, N := range sizes {
			group := depsByN[N]
			// Preserve iteration order of FScolumnsDependencies[r] within a
			// size by NOT re-sorting here — matches prover's polysByN append
			// order in ExecuteSteps.
			for polyIdx, dep := range group {
				layout.ColSlot[dep.Name] = Slot{TreeIdx: treeIdx, PolyIdx: polyIdx}
			}
			layout.TreeSize = append(layout.TreeSize, N)
			treeIdx++
		}

		layout.TraceEnd[r] = treeIdx
	}

	// ---- AIR section ----
	layout.AIRBegin = treeIdx
	{
		// Modules contributing AIR-quotient chunks: those with non-trivial
		// vanishing relation. Iterate in deterministic name order.
		moduleNames := make([]string, 0, len(program.Modules))
		for name := range program.Modules {
			moduleNames = append(moduleNames, name)
		}
		sort.Strings(moduleNames)

		// chunksByN[N] is the ordered list of (moduleName, chunkIdx) pairs
		// of size N, in (sortedModule × chunkIdx) order — must match
		// ComputeAIRQuotients in the prover.
		type airEntry struct {
			module string
			idx    int
		}
		chunksByN := map[int][]airEntry{}
		for _, moduleName := range moduleNames {
			m := program.Modules[moduleName]
			if m.VanishingRelation == nil || m.VanishingRelation.Degree() <= 0 {
				continue
			}
			N := m.N
			eDeg := m.VanishingRelation.Degree()
			bigSize := poly.NextPowerOfTwo(eDeg * N)
			numChunks := bigSize / N
			for i := 0; i < numChunks; i++ {
				chunksByN[N] = append(chunksByN[N], airEntry{module: moduleName, idx: i})
			}
		}
		sizes := sortedSizesDesc(chunksByN)
		for _, N := range sizes {
			for polyIdx, e := range chunksByN[N] {
				chunkName := constants.QuotientChunkName(e.module, e.idx)
				layout.AIRChunkSlot[chunkName] = Slot{TreeIdx: treeIdx, PolyIdx: polyIdx}
			}
			layout.TreeSize = append(layout.TreeSize, N)
			treeIdx++
		}
	}
	layout.AIREnd = treeIdx

	layout.NumTrees = treeIdx
	return layout
}

// sortedSizesDesc returns the keys of m sorted in decreasing order.
func sortedSizesDesc[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

