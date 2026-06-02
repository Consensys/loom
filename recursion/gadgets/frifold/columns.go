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

// Package frifold implements an in-circuit gadget for one FRI fold step.
//
// FRI verifies, at each query and each folding round j, that a "fold"
// equation holds between two opened values (P, Q) at sibling positions in
// the round-j evaluation domain, a fold challenge alpha, and the resulting
// folded value:
//
//	folded = (P + Q)/2 + alpha * (P - Q) / (2 * omega_j^base)
//
// where:
//   - omega_j is the round-j domain generator (base field, constant per
//     round);
//   - base = s mod (N_j / 2), a per-query position;
//   - alpha is the round-j fold challenge (Fiat-Shamir, lives in E6);
//   - 1/2 is a precomputed base-field constant.
//
// The gadget treats xInv = omega_j^{-base} as a witness column supplied by
// the trace generator; computing xInv from omega_j and base (via bit
// decomposition + binary exponentiation) is a separate concern that will be
// addressed in a follow-up gadget.
//
// Two rails are supported via separate Build functions:
//
//   - BuildExtModule    (E6 P, Q, alpha; base xInv): the dominant case in
//     Loom because FRI challenges live in E6.
//   - BuildBaseModule   (base P, Q, alpha, xInv): used when all values live
//     in the base field (rare in Loom but useful for unit tests).
//
// Each row of either module is one independent fold check; the module's N is
// rounded up to the next power of two by the caller's helper (BuildModule
// itself requires the caller to pre-pad). Padding rows can be filled with
// P = Q = 0, alpha = 0, xInv = 1, folded = 0, which trivially satisfies the
// constraints.
package frifold

import "fmt"

// Ext column names (E6-rail fold).
func ExtPColName(name string, limb int) string     { return fmt.Sprintf("%s.P_%d", name, limb) }
func ExtQColName(name string, limb int) string     { return fmt.Sprintf("%s.Q_%d", name, limb) }
func ExtAlphaColName(name string, limb int) string { return fmt.Sprintf("%s.alpha_%d", name, limb) }
func ExtFoldedColName(name string, limb int) string {
	return fmt.Sprintf("%s.folded_%d", name, limb)
}

// XInv is a base-field column on both rails.
func XInvColName(name string) string { return fmt.Sprintf("%s.xInv", name) }

// Base column names (single-element rail).
func BasePColName(name string) string      { return fmt.Sprintf("%s.P", name) }
func BaseQColName(name string) string      { return fmt.Sprintf("%s.Q", name) }
func BaseAlphaColName(name string) string  { return fmt.Sprintf("%s.alpha", name) }
func BaseFoldedColName(name string) string { return fmt.Sprintf("%s.folded", name) }
