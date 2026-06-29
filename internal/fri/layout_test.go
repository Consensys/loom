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
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/poly"
)

// TestCanonicalLayoutThreeBatches walks the frozen ordering on a fixture
// with three batches at sizes {8, 4, 8} sharing some shifts. The
// resulting enumeration must be:
//   - size 8 first, then size 4 (descending);
//   - within size 8: shifts 0, 1, 2 (ascending);
//   - within each shift: batch-declaration order, then base rail
//     before ext rail in declaration order.
func TestCanonicalLayoutThreeBatches(t *testing.T) {
	// batches[0] : size 8 with two base polys
	// batches[1] : size 4 with one base poly
	// batches[2] : size 8 with one base + one ext poly
	batches := []Batch{
		{{
			Base: []poly.Polynomial{makeBasePoly(8), makeBasePoly(8)},
		}},
		{{
			Base: []poly.Polynomial{makeBasePoly(4)},
		}},
		{{
			Base: []poly.Polynomial{makeBasePoly(8)},
			Ext:  []poly.ExtPolynomial{makeExtPoly(8)},
		}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1}, {0}}}},
		{{Base: [][]int{{0}}}},
		{{Base: [][]int{{1}}, Ext: [][]int{{2}}}},
	}

	got, err := canonicalLayout(batches, shifts)
	if err != nil {
		t.Fatalf("canonicalLayout: %v", err)
	}

	want := layout{
		{N: 8, Bundles: []shiftBundle{
			{Shift: 0, Entries: []deepEntry{
				{BatchIdx: 0, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
				{BatchIdx: 0, GroupIdx: 0, PolyIdx: 1, Field: field.Base},
			}},
			{Shift: 1, Entries: []deepEntry{
				{BatchIdx: 0, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
				{BatchIdx: 2, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
			}},
			{Shift: 2, Entries: []deepEntry{
				{BatchIdx: 2, GroupIdx: 0, PolyIdx: 0, Field: field.Ext},
			}},
		}},
		{N: 4, Bundles: []shiftBundle{
			{Shift: 0, Entries: []deepEntry{
				{BatchIdx: 1, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
			}},
		}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical layout mismatch:\n  got: %#v\n want: %#v", got, want)
	}
}

// TestCanonicalLayoutMixedSizeBatch verifies the inner "skip if absent"
// rule: a batch may carry multiple Groups of different sizes, and a
// per-size walk only picks up the matching Group from each batch.
func TestCanonicalLayoutMixedSizeBatch(t *testing.T) {
	batches := []Batch{
		{
			{Base: []poly.Polynomial{makeBasePoly(8)}}, // batches[0][0] -- size 8
			{Base: []poly.Polynomial{makeBasePoly(4)}}, // batches[0][1] -- size 4
		},
		{
			{Base: []poly.Polynomial{makeBasePoly(8)}}, // batches[1][0] -- size 8
		},
	}
	shifts := []BatchShifts{
		{
			{Base: [][]int{{0}}},
			{Base: [][]int{{0}}},
		},
		{
			{Base: [][]int{{0}}},
		},
	}

	got, err := canonicalLayout(batches, shifts)
	if err != nil {
		t.Fatalf("canonicalLayout: %v", err)
	}

	want := layout{
		{N: 8, Bundles: []shiftBundle{
			{Shift: 0, Entries: []deepEntry{
				{BatchIdx: 0, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
				{BatchIdx: 1, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
			}},
		}},
		{N: 4, Bundles: []shiftBundle{
			{Shift: 0, Entries: []deepEntry{
				{BatchIdx: 0, GroupIdx: 1, PolyIdx: 0, Field: field.Base},
			}},
		}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical layout mismatch:\n  got: %#v\n want: %#v", got, want)
	}
}

// TestCanonicalLayoutBaseBeforeExt pins down that base-rail entries
// precede ext-rail entries within a single (batch, group, shift), in
// declaration order on each rail.
func TestCanonicalLayoutBaseBeforeExt(t *testing.T) {
	batches := []Batch{
		{{
			Base: []poly.Polynomial{makeBasePoly(8), makeBasePoly(8)},
			Ext:  []poly.ExtPolynomial{makeExtPoly(8)},
		}},
	}
	shifts := []BatchShifts{
		{{
			Base: [][]int{{0}, {0}},
			Ext:  [][]int{{0}},
		}},
	}

	got, err := canonicalLayout(batches, shifts)
	if err != nil {
		t.Fatalf("canonicalLayout: %v", err)
	}

	wantEntries := []deepEntry{
		{BatchIdx: 0, GroupIdx: 0, PolyIdx: 0, Field: field.Base},
		{BatchIdx: 0, GroupIdx: 0, PolyIdx: 1, Field: field.Base},
		{BatchIdx: 0, GroupIdx: 0, PolyIdx: 0, Field: field.Ext},
	}
	if !reflect.DeepEqual(got[0].Bundles[0].Entries, wantEntries) {
		t.Fatalf("ordering mismatch:\n  got: %#v\n want: %#v", got[0].Bundles[0].Entries, wantEntries)
	}
}

// TestCanonicalLayoutEmptyShiftListErrors rejects a polynomial with no
// shifts (every committed polynomial must be opened at least once).
func TestCanonicalLayoutEmptyShiftListErrors(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{makeBasePoly(4)}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{nil}}},
	}
	_, err := canonicalLayout(batches, shifts)
	if err == nil {
		t.Fatal("expected error for empty shift list")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error message should mention 'empty', got %q", err.Error())
	}
}

// TestCanonicalLayoutDuplicateShiftErrors rejects a shift list containing
// the same shift twice.
func TestCanonicalLayoutDuplicateShiftErrors(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{makeBasePoly(4)}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1, 0}}}},
	}
	_, err := canonicalLayout(batches, shifts)
	if err == nil {
		t.Fatal("expected error for duplicate shift")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error message should mention 'duplicate', got %q", err.Error())
	}
}

// TestCanonicalLayoutDuplicateModuloShiftErrors rejects distinct integer shifts
// that address the same opening point on the size-N subgroup.
func TestCanonicalLayoutDuplicateModuloShiftErrors(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{makeBasePoly(4)}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 4}}}},
	}
	_, err := canonicalLayout(batches, shifts)
	if err == nil {
		t.Fatal("expected error for duplicate modulo shift")
	}
	if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "modulo") {
		t.Fatalf("error message should mention duplicate modulo shift, got %q", err.Error())
	}
}

// TestCanonicalLayoutShapeMismatchErrors covers the three shape-alignment
// failures: shifts length, per-batch group count, per-group rail width.
func TestCanonicalLayoutShapeMismatchErrors(t *testing.T) {
	t.Run("len(shifts) != len(batches)", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{{Base: [][]int{{0}}}},
			{},
		}
		if _, err := canonicalLayout(batches, shifts); err == nil {
			t.Fatal("expected error for top-level shape mismatch")
		}
	})

	t.Run("per-batch group count mismatch", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{
				{Base: [][]int{{0}}},
				{Base: [][]int{{0}}}, // extra
			},
		}
		if _, err := canonicalLayout(batches, shifts); err == nil {
			t.Fatal("expected error for per-batch group count mismatch")
		}
	})

	t.Run("base rail width mismatch", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4), makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{{Base: [][]int{{0}}}}, // one entry, want two
		}
		if _, err := canonicalLayout(batches, shifts); err == nil {
			t.Fatal("expected error for base rail width mismatch")
		}
	})

	t.Run("ext rail width mismatch", func(t *testing.T) {
		batches := []Batch{
			{{
				Base: []poly.Polynomial{makeBasePoly(4)},
				Ext:  []poly.ExtPolynomial{makeExtPoly(4)},
			}},
		}
		shifts := []BatchShifts{
			{{
				Base: [][]int{{0}},
				// Ext schedule missing entirely; want one entry
			}},
		}
		if _, err := canonicalLayout(batches, shifts); err == nil {
			t.Fatal("expected error for ext rail width mismatch")
		}
	})
}

// TestCanonicalLayoutEmptyBatches treats the degenerate "nothing to
// commit" call as a valid input that yields an empty layout.
func TestCanonicalLayoutEmptyBatches(t *testing.T) {
	got, err := canonicalLayout(nil, nil)
	if err != nil {
		t.Fatalf("canonicalLayout(nil, nil): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty input should yield empty layout, got %d sizeBundles", len(got))
	}
}

// makeBasePoly returns a length-n base polynomial. Only the length is
// load-bearing for the layout's tests; values are arbitrary.
func makeBasePoly(n int) poly.Polynomial {
	p := make(poly.Polynomial, n)
	for i := range p {
		p[i] = baseElement(uint64(i + 1))
	}
	return p
}

// makeExtPoly returns a length-n extension polynomial with arbitrary
// values.
func makeExtPoly(n int) poly.ExtPolynomial {
	p := make(poly.ExtPolynomial, n)
	for i := range p {
		v := uint64(10*(i+1) + 1)
		p[i] = extElement(v, v+1, v+2, v+3)
	}
	return p
}
