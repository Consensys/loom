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

package idxselect_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/bits"
	"github.com/consensys/loom/recursion/gadgets/idxselect"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randExt() ext.E6 {
	var v ext.E6
	v.MustSetRandom()
	return v
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	r := 1
	for r < n {
		r <<= 1
	}
	return r
}

func buildIdxSelect(t *testing.T, name string, table []ext.E6, indices []uint64) (board.Builder, trace.Trace, idxselect.ColumnNames) {
	t.Helper()
	k := 0
	for v := len(table); v > 1; v >>= 1 {
		k++
	}
	n := nextPow2(len(indices))

	mod := board.NewModule(name)
	mod.N = n
	bitsCN := bits.Register(&mod, name+".idx", k)
	selCN := idxselect.Register(&mod, name+".sel", table, bitsCN)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	bitsCols := bits.GenerateTrace(bitsCN, n, indices)
	selCols := idxselect.GenerateTrace(selCN, n, table, indices)

	tr := trace.New()
	for k, v := range bitsCols {
		tr.SetBase(k, v)
	}
	for k, v := range selCols {
		tr.SetBase(k, v)
	}
	return builder, tr, selCN
}

// TestIdxSelectGadgetTable4 exercises a 4-entry table (k=2) with two
// different indices.
func TestIdxSelectGadgetTable4(t *testing.T) {
	table := []ext.E6{randExt(), randExt(), randExt(), randExt()}
	indices := []uint64{0, 1, 2, 3, 1, 3, 0, 2}

	builder, tr, _ := buildIdxSelect(t, "sel4", table, indices)
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestIdxSelectGadgetTable16 exercises a 16-entry table (k=4) — larger
// depth pushes the polynomial degree to 4.
func TestIdxSelectGadgetTable16(t *testing.T) {
	table := make([]ext.E6, 16)
	for i := range table {
		table[i] = randExt()
	}
	indices := []uint64{0, 1, 7, 15, 9, 4, 12, 13}

	builder, tr, _ := buildIdxSelect(t, "sel16", table, indices)
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestIdxSelectMatchesNative cross-checks each row's selected output limb
// against table[index] directly.
func TestIdxSelectMatchesNative(t *testing.T) {
	table := []ext.E6{randExt(), randExt(), randExt(), randExt()}
	indices := []uint64{0, 1, 2, 3}

	_, tr, cn := buildIdxSelect(t, "selmatch", table, indices)

	for row, idx := range indices {
		want := extfield.FromE6(table[idx])
		for i := 0; i < extfield.Limbs; i++ {
			got := tr.Base[cn.Out[i]][row]
			if !got.Equal(&want[i]) {
				t.Fatalf("row %d limb %d: got %s, want %s", row, i, got.String(), want[i].String())
			}
		}
	}
}

// TestIdxSelectRejectsCorruption flips the output and confirms the proof
// breaks.
func TestIdxSelectRejectsCorruption(t *testing.T) {
	table := []ext.E6{randExt(), randExt()}
	indices := []uint64{0}

	builder, tr, cn := buildIdxSelect(t, "sel_corrupt", table, indices)
	var one koalabear.Element
	one.SetOne()
	col := tr.Base[cn.Out[0]]
	col[0].Add(&col[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
