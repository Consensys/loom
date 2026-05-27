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

// Package challenger implements an in-circuit Fiat-Shamir sponge layered
// over the Poseidon2 gadget.
//
// IMPORTANT LIMITATION (milestone 1): this gadget uses the width-16
// Poseidon2-MD permutation that Loom employs for Merkle node hashing. Loom's
// real Fiat-Shamir transcript (internal/fiat-shamir + Poseidon2SpongeHasher)
// uses the width-24/rate-16 variant. The actual recursive verifier will
// require a width-24 Poseidon2 gadget; until then this package exposes the
// challenger structure on the width-16 sponge for design validation and
// architectural testing.
//
// The challenger holds a State (rate + capacity) and offers:
//
//   - Init()                       new transcript
//   - Absorb(values...)            absorb base-field elements (lazy permute)
//   - Squeeze() / SqueezeExt()     extract a fresh base element / E4 element
//
// The gadget version of these operations works in expr.Expr space: it
// accumulates per-permutation in/out column references in a Poseidon2 gadget
// module and links them through the State's permutation-counter index.
package challenger

import (
	"fmt"

	"github.com/consensys/loom/internal/hash"
)

// Rate and Capacity describe the width-16 MD sponge: state = rate || capacity
// with capacity = 8 (= DIGEST_NB_ELEMENTS).
const (
	StateWidth = hash.WIDTH
	Capacity   = hash.DIGEST_NB_ELEMENTS
	Rate       = StateWidth - Capacity
)

// PermInColName / PermOutColName are the column-name conventions used to
// reference the underlying Poseidon2 gadget's I/O for a specific permutation
// slot in the challenger trace.
func PermInColName(name string, slot, i int) string {
	return fmt.Sprintf("%s.perm_in[%d][%d]", name, slot, i)
}

func PermOutColName(name string, slot, i int) string {
	return fmt.Sprintf("%s.perm_out[%d][%d]", name, slot, i)
}
