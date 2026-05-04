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

package prover

import (
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

type PublicKey = merkle.Tree

func Setup(t trace.Trace, program board.Program) (*PublicKey, error) {

	maxN := 0
	for _, m := range program.Modules {
		if m.N > maxN {
			maxN = m.N
		}
	}
	committer := commitment.NewRSCommit(uint64(maxN), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)

	polys := make([]poly.Polynomial, len(program.PublicColumns))
	for i, name := range program.PublicColumns {
		polys[i] = t[name]
	}
	tree, err := committer.Commit(polys)
	if err != nil {
		return nil, err
	}

	return tree, nil
}
