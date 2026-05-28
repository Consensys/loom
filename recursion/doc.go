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

// Package recursion builds Loom programs that verify other Loom proofs.
//
// Two top-level entry points are planned:
//
//   - BuildVerifierCore  compiles a verifier circuit for a single inner proof
//     (used for proof compression by repeated wrapping).
//   - buildAggregationCore  compiles a verifier circuit that verifies two
//     inner proofs at once (used for tree-based aggregation of segmented
//     traces).
//
// Recursion is only meaningful with an algebraic hash, so the inner proof
// must use the Poseidon2 backend.
//
// This milestone delivers only the primitive gadget layer:
//
//   - gadgets/poseidon2  in-circuit Poseidon2 permutation (width-16 MD variant)
//   - gadgets/merkle     Merkle-path verification on top of the Poseidon2 gadget
//   - gadgets/challenger Fiat-Shamir sponge layered over the Poseidon2 gadget
//   - extfield           E4 arithmetic helpers inlined as expr.Expr trees
//
// The BuildVerifierCore / buildAggregationCore wiring is intentionally left as
// stubs returning an error; subsequent milestones will assemble these gadgets
// into a complete verifier circuit (AIR-at-zeta check, FRI verification,
// Merkle-opening verification, DEEP-quotient bridge).
package recursion
