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
	"sort"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

// PublicKey is the per-size set of WMerkleTrees over the program's public
// columns: PublicKey[s] is the commitment for the s-th size group, sizes
// ordered by decreasing N. An empty/nil PublicKey means "no setup".
type PublicKey = []commitment.WMerkleTree

func Setup(t trace.Trace, program board.Program) (PublicKey, error) {
	if len(program.PublicColumns) == 0 {
		return nil, nil
	}

	// Group public columns by their owning module's domain size.
	colsByN := map[int][]poly.Polynomial{}
	for _, c := range program.PublicColumns {
		m, ok := program.Modules[c.Module]
		if !ok {
			continue
		}
		colsByN[m.N] = append(colsByN[m.N], t[c.Name])
	}
	sizes := make([]int, 0, len(colsByN))
	for n := range colsByN {
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	res := make(PublicKey, len(sizes))
	for i, N := range sizes {
		committer := commitment.NewRSCommit(uint64(N), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)
		tree, err := committer.Commit(colsByN[N])
		if err != nil {
			return nil, err
		}
		res[i] = tree
	}
	return res, nil
}
