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

package recursion

import (
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/proof"
)

// RecursionInput is a single inner proof together with the program it
// satisfies. The verifier circuit produced by buildVerifierCore checks the
// proof against the program.
type RecursionInput struct {
	Program board.Program
	Proof   proof.Proof
}

// AggregationInput pairs two inner proofs so that a single outer verifier
// circuit can check both. Programs need not be identical; this enables
// tree-based aggregation where the leaves of the tree may have different
// shapes (e.g. distinct trace segments).
type AggregationInput struct {
	Left  RecursionInput
	Right RecursionInput
}
