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

// Package deepbridge implements gadgets for the DEEP-quotient bridge
// step of Loom's verifier (verifier.checkFRIBridge). The bridge ties
// the FRI level-0 evaluations to the AIR claims at zeta:
//
//	DQ(X) = sum_s (v_s - C_s(X)) / (z_s - X)
//
// where each summand corresponds to one shift group of opened columns,
// with v_s and C_s(X) being alpha-batched sums of column-at-zeta and
// column-at-X values respectively. The verifier checks that DQ
// evaluated at the FRI query position matches the FRI proof's level-0
// values (LeafP, LeafQ).
//
// This package provides two primitives:
//
//   - RegisterDivExt: in-circuit E6 division via a witness column and
//     the constraint result * denom == num. Used wherever the bridge
//     needs to invert a denominator like (z_s - X).
//
//   - RegisterSummand: convenience wrapper that computes one DEEP
//     summand (v - C) / (z - X) and returns the resulting E6Expr.
//
// Together these let a caller assemble the full DQ_P / DQ_Q sums by
// iterating over shift groups and adding summands. Asserting equality
// against the FRI proof's level-0 layer values closes the bridge.
package deepbridge

import (
	"fmt"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
)

// DivColName is the i-th E6 limb of a division-result witness column.
func DivColName(prefix string, i int) string {
	return fmt.Sprintf("%s.div_%d", prefix, i)
}

// RegisterDivExt allocates four base-field witness columns under prefix
// and constrains them to hold num/denom in E6. Returns an E6Expr
// referencing the witness columns.
//
// The caller's trace generator must fill the witness columns with
// native E6 division (num.Inverse(&denom).Mul(...)). If denom is
// identically zero on some row, no valid witness exists and the proof
// will fail to verify; callers must ensure denom != 0 wherever the
// constraint is meaningful.
func RegisterDivExt(mod *board.Module, prefix string, num, denom extfield.E6Expr) extfield.E6Expr {
	var result extfield.E6Expr
	for i := 0; i < extfield.Limbs; i++ {
		result.Limb[i] = expr.Col(DivColName(prefix, i))
	}

	// result * denom == num
	product := result.Mul(denom)
	for _, rel := range num.EqualityConstraints(product) {
		mod.AssertZero(rel)
	}
	return result
}

// RegisterSummand computes one DEEP-quotient summand
//
//	(v - C) / (z - X)
//
// inside mod under prefix. v, C, z, X are caller-supplied E6Expr
// inputs (typically pre-computed via alpha-batching across columns).
// Returns an E6Expr referencing the underlying witness columns.
func RegisterSummand(mod *board.Module, prefix string, v, C, z, X extfield.E6Expr) extfield.E6Expr {
	num := v.Sub(C)
	denom := z.Sub(X)
	return RegisterDivExt(mod, prefix, num, denom)
}
