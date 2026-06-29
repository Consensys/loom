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

	"github.com/consensys/loom/internal/poly"
)

func TestLayoutFreeHelpersMatchBatchesAndShapes(t *testing.T) {
	const rate uint64 = 2

	batches := []Batch{
		{
			{Base: []poly.Polynomial{makeBasePoly(8)}},
			{
				Base: []poly.Polynomial{makeBasePoly(4), makeBasePoly(4)},
				Ext:  []poly.ExtPolynomial{makeExtPoly(4)},
			},
		},
		{
			{
				Base: []poly.Polynomial{makeBasePoly(8)},
				Ext:  []poly.ExtPolynomial{makeExtPoly(8)},
			},
		},
	}
	shifts := []BatchShifts{
		{
			{Base: [][]int{{0}}},
			{Base: [][]int{{0}, {1}}, Ext: [][]int{{0}}},
		},
		{
			{Base: [][]int{{2}}, Ext: [][]int{{3}}},
		},
	}
	shapes := []BatchShapes{
		{
			{Rows: 16, BaseWidth: 1},
			{Rows: 8, BaseWidth: 2, ExtWidth: 1},
		},
		{
			{Rows: 16, BaseWidth: 1, ExtWidth: 1},
		},
	}

	batchSizes, err := groupNativeSizesFromBatches(batches)
	if err != nil {
		t.Fatalf("groupNativeSizesFromBatches: %v", err)
	}
	shapeSizes, err := groupNativeSizesFromShapes(shapes, rate)
	if err != nil {
		t.Fatalf("groupNativeSizesFromShapes: %v", err)
	}
	if !reflect.DeepEqual(batchSizes, shapeSizes) {
		t.Fatalf("native sizes mismatch:\n  batches: %#v\n   shapes: %#v", batchSizes, shapeSizes)
	}

	batchSizesDesc, err := sizesDescFromBatches(batches)
	if err != nil {
		t.Fatalf("sizesDescFromBatches: %v", err)
	}
	shapeSizesDesc, err := sizesDescFromShapes(shapes, rate)
	if err != nil {
		t.Fatalf("sizesDescFromShapes: %v", err)
	}
	wantSizesDesc := []int{8, 4}
	if !reflect.DeepEqual(batchSizesDesc, wantSizesDesc) {
		t.Fatalf("sizesDescFromBatches = %v, want %v", batchSizesDesc, wantSizesDesc)
	}
	if !reflect.DeepEqual(shapeSizesDesc, wantSizesDesc) {
		t.Fatalf("sizesDescFromShapes = %v, want %v", shapeSizesDesc, wantSizesDesc)
	}

	if err := validateBatchShifts(batches, shifts); err != nil {
		t.Fatalf("validateBatchShifts: %v", err)
	}
	if err := validateBatchShiftsFromShapes(shapes, shifts, rate); err != nil {
		t.Fatalf("validateBatchShiftsFromShapes: %v", err)
	}
}

func TestLayoutFreeHelpersRejectDuplicateRawShift(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{makeBasePoly(8)}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1, 0}}}},
	}
	err := validateBatchShifts(batches, shifts)
	if err == nil {
		t.Fatal("expected duplicate raw shift error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error message should mention duplicate, got %q", err.Error())
	}
}

func TestLayoutFreeHelpersRejectDuplicateModuloShift(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{makeBasePoly(8)}}},
		{{Base: []poly.Polynomial{makeBasePoly(8)}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 8}}}},
		{{Base: [][]int{{-1, 7}}}},
	}

	for b := range batches {
		err := validateBatchShifts(batches[b:b+1], shifts[b:b+1])
		if err == nil {
			t.Fatalf("batch %d: expected duplicate modulo shift error", b)
		}
		if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "modulo") {
			t.Fatalf("batch %d: error should mention duplicate modulo shift, got %q", b, err.Error())
		}
	}
}

func TestLayoutFreeShapeHelpersRejectDuplicateModuloShift(t *testing.T) {
	const rate uint64 = 2
	shapes := []BatchShapes{
		{{Rows: 16, BaseWidth: 1}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 8}}}},
	}

	err := validateBatchShiftsFromShapes(shapes, shifts, rate)
	if err == nil {
		t.Fatal("expected duplicate modulo shift error")
	}
	if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "modulo") {
		t.Fatalf("error should mention duplicate modulo shift, got %q", err.Error())
	}
}
