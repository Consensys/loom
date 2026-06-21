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
	"testing"

	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/poly"
)

// TestComputeClaimedValuesShape pins down the output-vs-input shape
// contract: for every (b, g, rail, i, k) in shifts, the output exposes
// exactly one ext.E6 at the matching position. No extra entries, no
// missing entries.
func TestComputeClaimedValuesShape(t *testing.T) {
	batches := []Batch{
		{
			{Base: []poly.Polynomial{makeBasePoly(4), makeBasePoly(4)}},
		},
		{
			{
				Base: []poly.Polynomial{makeBasePoly(8)},
				Ext:  []poly.ExtPolynomial{makeExtPoly(8)},
			},
		},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0}, {0, 1}}}},
		{{Base: [][]int{{2}}, Ext: [][]int{{0, 1, 5}}}},
	}

	var zeta ext.E6
	zeta.B0.A0.SetUint64(42)

	var cache poly.DomainCache
	got, err := computeClaimedValues(batches, shifts, zeta, &cache)
	if err != nil {
		t.Fatalf("computeClaimedValues: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if len(got[0]) != 1 || len(got[1]) != 1 {
		t.Fatalf("per-batch group counts wrong: got[0]=%d got[1]=%d", len(got[0]), len(got[1]))
	}
	if got, want := len(got[0][0].Base), 2; got != want {
		t.Fatalf("got[0][0].Base width = %d, want %d", got, want)
	}
	if got, want := len(got[0][0].Base[0]), 1; got != want {
		t.Fatalf("got[0][0].Base[0] length = %d, want %d", got, want)
	}
	if got, want := len(got[0][0].Base[1]), 2; got != want {
		t.Fatalf("got[0][0].Base[1] length = %d, want %d", got, want)
	}
	if got, want := len(got[1][0].Base[0]), 1; got != want {
		t.Fatalf("got[1][0].Base[0] length = %d, want %d", got, want)
	}
	if got, want := len(got[1][0].Ext[0]), 3; got != want {
		t.Fatalf("got[1][0].Ext[0] length = %d, want %d", got, want)
	}
}

// TestComputeClaimedValuesAllOnesEvaluatesToOne uses the Lagrange-basis
// partition-of-unity property: a polynomial whose Lagrange-form vector is
// all-ones evaluates to 1 at every point (since sum_i L_i(x) = 1 for all
// x). The same must hold on both rails and at every shift.
func TestComputeClaimedValuesAllOnesEvaluatesToOne(t *testing.T) {
	const N = 8

	basePoly := make(poly.Polynomial, N)
	for i := range basePoly {
		basePoly[i] = baseElement(1)
	}
	extPoly := make(poly.ExtPolynomial, N)
	for i := range extPoly {
		extPoly[i] = extElement(1, 0, 0, 0)
	}

	batches := []Batch{
		{{
			Base: []poly.Polynomial{basePoly},
			Ext:  []poly.ExtPolynomial{extPoly},
		}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1, 3, 7}}, Ext: [][]int{{0, 2, 5}}}},
	}

	var zeta ext.E6
	zeta.B0.A0.SetUint64(13)
	zeta.B1.A1.SetUint64(7)

	var cache poly.DomainCache
	got, err := computeClaimedValues(batches, shifts, zeta, &cache)
	if err != nil {
		t.Fatalf("computeClaimedValues: %v", err)
	}

	var one ext.E6
	one.SetOne()

	for k, v := range got[0][0].Base[0] {
		if !v.Equal(&one) {
			t.Fatalf("base shift %d: got %s, want 1", shifts[0][0].Base[0][k], v.String())
		}
	}
	for k, v := range got[0][0].Ext[0] {
		if !v.Equal(&one) {
			t.Fatalf("ext shift %d: got %s, want 1", shifts[0][0].Ext[0][k], v.String())
		}
	}
}

// TestComputeClaimedValuesMatchesDirectEval checks parity with the
// underlying helpers: for a chosen polynomial and zeta, the value at each
// declared shift must equal poly.EvaluateLagrangeAtExt called directly
// with the same arguments. This locks the contract that the public
// shape-walker only delegates and does no arithmetic of its own.
func TestComputeClaimedValuesMatchesDirectEval(t *testing.T) {
	const N = 4
	basePoly := poly.Polynomial{
		baseElement(2), baseElement(3), baseElement(5), baseElement(7),
	}
	extPoly := poly.ExtPolynomial{
		extElement(11, 13, 17, 19),
		extElement(23, 29, 31, 37),
		extElement(41, 43, 47, 53),
		extElement(59, 61, 67, 71),
	}

	batches := []Batch{
		{{
			Base: []poly.Polynomial{basePoly},
			Ext:  []poly.ExtPolynomial{extPoly},
		}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1, 2}}, Ext: [][]int{{1, 3}}}},
	}

	var zeta ext.E6
	zeta.B0.A0.SetUint64(101)
	zeta.B2.A0.SetUint64(13)

	var cache poly.DomainCache
	got, err := computeClaimedValues(batches, shifts, zeta, &cache)
	if err != nil {
		t.Fatalf("computeClaimedValues: %v", err)
	}

	lagranges := poly.LagrangesAtZeta(zeta, N)
	for k, s := range shifts[0][0].Base[0] {
		want := poly.EvaluateLagrangeAtExt(basePoly, lagranges, normalizeShift(s, N))
		if !got[0][0].Base[0][k].Equal(&want) {
			t.Fatalf("base shift %d: got %s, want %s", s, got[0][0].Base[0][k].String(), want.String())
		}
	}
	for k, s := range shifts[0][0].Ext[0] {
		want := poly.ExtEvaluateLagrangeAtExt(extPoly, lagranges, normalizeShift(s, N))
		if !got[0][0].Ext[0][k].Equal(&want) {
			t.Fatalf("ext shift %d: got %s, want %s", s, got[0][0].Ext[0][k].String(), want.String())
		}
	}
}

// TestComputeClaimedValuesShiftWraparound verifies the modular-shift
// behavior: shift N is equivalent to shift 0, and shift -1 is equivalent
// to shift N-1.
func TestComputeClaimedValuesShiftWraparound(t *testing.T) {
	const N = 4
	basePoly := poly.Polynomial{
		baseElement(2), baseElement(3), baseElement(5), baseElement(7),
	}

	batches := []Batch{
		{{Base: []poly.Polynomial{basePoly}}},
	}
	// Compare (0, N) and (N-1, -1): each pair should produce equal values.
	shifts := []BatchShifts{
		{{Base: [][]int{{0, N, N - 1, -1}}}},
	}

	var zeta ext.E6
	zeta.B0.A0.SetUint64(101)

	var cache poly.DomainCache
	got, err := computeClaimedValues(batches, shifts, zeta, &cache)
	if err != nil {
		t.Fatalf("computeClaimedValues: %v", err)
	}

	vals := got[0][0].Base[0]
	if !vals[0].Equal(&vals[1]) {
		t.Fatalf("shift 0 and shift N should match: %s vs %s", vals[0].String(), vals[1].String())
	}
	if !vals[2].Equal(&vals[3]) {
		t.Fatalf("shift N-1 and shift -1 should match: %s vs %s", vals[2].String(), vals[3].String())
	}
}

// TestComputeClaimedValuesShapeMismatchErrors covers the shape-alignment
// failure paths. Per-poly validation (empty / duplicate shift list) is
// the responsibility of canonicalLayout and is exercised in layout_test.go.
func TestComputeClaimedValuesShapeMismatchErrors(t *testing.T) {
	t.Run("len(shifts) != len(batches)", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{{Base: [][]int{{0}}}},
			{},
		}
		if _, err := computeClaimedValues(batches, shifts, ext.E6{}, nil); err == nil {
			t.Fatal("expected error for top-level length mismatch")
		}
	})

	t.Run("per-batch group count mismatch", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{
				{Base: [][]int{{0}}},
				{Base: [][]int{{0}}},
			},
		}
		if _, err := computeClaimedValues(batches, shifts, ext.E6{}, nil); err == nil {
			t.Fatal("expected error for per-batch group count mismatch")
		}
	})

	t.Run("base rail width mismatch", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4), makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{{Base: [][]int{{0}}}},
		}
		if _, err := computeClaimedValues(batches, shifts, ext.E6{}, nil); err == nil {
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
			{{Base: [][]int{{0}}}},
		}
		if _, err := computeClaimedValues(batches, shifts, ext.E6{}, nil); err == nil {
			t.Fatal("expected error for ext rail width mismatch")
		}
	})
}
