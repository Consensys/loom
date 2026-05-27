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

// Package merkle implements an in-circuit Merkle-path verification gadget.
//
// One row of the gadget module represents one Merkle step along a path. The
// witness columns are:
//
//   - current_0..current_7   : the digest being lifted up the tree at this
//     step (= leaf at step 0, = parent at later steps)
//   - sibling_0..sibling_7   : the sibling digest provided by the path
//   - bit                     : direction bit; bit=0 means current is the
//     left child, bit=1 means current is the right child
//   - left_0..left_7         : derived = (1-bit)*current + bit*sibling
//   - right_0..right_7       : derived = bit*current + (1-bit)*sibling
//   - parent_0..parent_7     : HashNode(left, right) — supplied by the trace
//
// Constraints (see constraints.go):
//
//   - bit * (1 - bit) = 0                      // bit is binary
//   - left[i]   - (current[i] + bit*(sibling[i]-current[i])) = 0
//   - right[i]  - (sibling[i] + bit*(current[i]-sibling[i])) = 0
//   - chaining: at row r > 0, current[i] = parent[i] at row r-1
//
// HASH EQUALITY: parent[i] = HashNode(left, right)[i] is NOT yet enforced in
// this gadget. The trace generator computes the correct value, so an honest
// prover passes; a malicious prover that lies about a parent without also
// lying about the chain of currents would be caught by the chaining
// constraint at the next step. To make the gadget closed under any
// adversarial behaviour, a future milestone will add a logup lookup into the
// Poseidon2 gadget module asserting that (left, right) → parent matches a
// valid Poseidon2-MD compression. See the TODO in constraints.go.
package merkle

import (
	"fmt"

	"github.com/consensys/loom/internal/hash"
)

// DigestWidth is the number of base-field limbs per Merkle digest.
const DigestWidth = hash.DIGEST_NB_ELEMENTS

// CurrentColName is the digest being hashed up the tree at this row.
func CurrentColName(name string, i int) string { return fmt.Sprintf("%s.current_%d", name, i) }

// SiblingColName is the sibling digest provided by the Merkle path.
func SiblingColName(name string, i int) string { return fmt.Sprintf("%s.sibling_%d", name, i) }

// BitColName is the binary direction column.
func BitColName(name string) string { return fmt.Sprintf("%s.bit", name) }

// LeftColName / RightColName are the derived child digests fed to HashNode.
func LeftColName(name string, i int) string  { return fmt.Sprintf("%s.left_%d", name, i) }
func RightColName(name string, i int) string { return fmt.Sprintf("%s.right_%d", name, i) }

// ParentColName is the result of HashNode(left, right) at this row.
func ParentColName(name string, i int) string { return fmt.Sprintf("%s.parent_%d", name, i) }
