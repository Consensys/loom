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
	"strings"
	"testing"

	"github.com/consensys/loom/internal/poly"
)

// TestValidateBatchShiftsEmptyShiftListErrors rejects a polynomial with no
// shifts. Every committed polynomial must be opened at least once.
func TestValidateBatchShiftsEmptyShiftListErrors(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{makeBasePoly(4)}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{nil}}},
	}

	err := validateBatchShifts(batches, shifts)
	if err == nil {
		t.Fatal("expected error for empty shift list")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error message should mention empty, got %q", err.Error())
	}
}

// TestValidateBatchShiftsShapeMismatchErrors covers the shape-alignment
// failures checked before the DEEP quotient traversal starts.
func TestValidateBatchShiftsShapeMismatchErrors(t *testing.T) {
	t.Run("len(shifts) != len(batches)", func(t *testing.T) {
		batches := []Batch{
			{{Base: []poly.Polynomial{makeBasePoly(4)}}},
		}
		shifts := []BatchShifts{
			{{Base: [][]int{{0}}}},
			{},
		}
		if err := validateBatchShifts(batches, shifts); err == nil {
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
				{Base: [][]int{{0}}},
			},
		}
		if err := validateBatchShifts(batches, shifts); err == nil {
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
		if err := validateBatchShifts(batches, shifts); err == nil {
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
			}},
		}
		if err := validateBatchShifts(batches, shifts); err == nil {
			t.Fatal("expected error for ext rail width mismatch")
		}
	})
}

func TestLayoutFreeHelpersEmptyBatches(t *testing.T) {
	if err := validateBatchShifts(nil, nil); err != nil {
		t.Fatalf("validateBatchShifts(nil, nil): %v", err)
	}
	got, err := sizesDescFromBatches(nil)
	if err != nil {
		t.Fatalf("sizesDescFromBatches(nil): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty input should yield no sizes, got %v", got)
	}
}

// makeBasePoly returns a length-n base polynomial. Only the length is
// load-bearing for shape-helper tests; values are arbitrary.
func makeBasePoly(n int) poly.Polynomial {
	p := make(poly.Polynomial, n)
	for i := range p {
		p[i] = baseElement(uint64(i + 1))
	}
	return p
}

// makeExtPoly returns a length-n extension polynomial with arbitrary values.
func makeExtPoly(n int) poly.ExtPolynomial {
	p := make(poly.ExtPolynomial, n)
	for i := range p {
		v := uint64(10*(i+1) + 1)
		p[i] = extElement(v, v+1, v+2, v+3)
	}
	return p
}
