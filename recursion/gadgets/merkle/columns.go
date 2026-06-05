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

// Package merkle implements an in-circuit Merkle-path verification gadget
// for FRI openings.
//
// One row of the gadget module represents one Merkle step along a path. The
// witness columns are:
//
//   - leafP_0..leafP_3 / leafQ_0..leafQ_3 : extension-field opening pair at
//     this layer (extfield limb order). The pair is meaningful only at
//     row 0 — at other rows it is filled with arbitrary self-consistent
//     values to satisfy the per-row leafhash constraints.
//   - current_0..current_7   : digest being lifted up the tree at this step.
//     At row 0 it equals leafhash.Digest(LeafP, LeafQ); at row k>0 it
//     equals row (k-1)'s parent.
//   - sibling_0..sibling_7   : the sibling digest provided by the path
//   - bit                     : direction bit (0=current is left child)
//   - left_0..left_7 / right_0..right_7 : derived child digests fed to
//     HashNode via the bit-selector
//   - parent_0..parent_7     : HashNode(left, right) at this step
//
// Constraints (see constraints.go):
//
//   - bit * (1 - bit) = 0                                  // bit is binary
//   - left[i]   = current[i] + bit*(sibling[i] - current[i])
//   - right[i]  = sibling[i] + bit*(current[i] - sibling[i])
//   - chaining at row k > 0: current[i] = parent[i] at row k-1
//   - leafhash at row 0    : current[i] = leafhash.Digest(LeafP, LeafQ)[i]
//   - hash binding at every row: parent[i] = nodehash.Digest(left, right)[i]
//
// The leafhash + nodehash bindings make the gadget closed under any
// adversarial witness: the only way to satisfy every per-row constraint
// is to produce a trace consistent with the real Poseidon2 leaf/node
// hashing, all the way from (LeafP, LeafQ) up to the final root.
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

// LeafPColName / LeafQColName are the ext-rail opening pair limbs (in
// extfield limb order: B0.A0, B1.A0, B0.A1, B1.A1).
func LeafPColName(name string, i int) string { return fmt.Sprintf("%s.leafP_%d", name, i) }
func LeafQColName(name string, i int) string { return fmt.Sprintf("%s.leafQ_%d", name, i) }
