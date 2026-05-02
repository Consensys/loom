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
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
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
	polys := make([]poly.Polynomial, len(program.PublicColumns))
	for i, name := range program.PublicColumns {
		polys[i] = t[name]
	}

	if len(polys) == 0 {
		return nil, fmt.Errorf("setup: no public columns to commit")
	}

	encoder := reedsolomon.Encoder{Domain: fft.NewDomain(uint64(maxN))}
	codewords := make([]poly.Polynomial, len(polys))
	for i, pol := range polys {
		if len(pol) == 0 {
			return nil, fmt.Errorf("setup: empty public column polynomial")
		}
		codewords[i] = encoder.Encode(pol, fft.NewDomain(uint64(len(pol))))
	}

	tree, err := merkle.New(maxN, commitment.LeafHash, commitment.NodeHash)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, koalabear.Bytes*len(codewords))
	for i := range maxN {
		for j := range codewords {
			copy(buf[j*koalabear.Bytes:], codewords[j][i].Marshal())
		}
		tree.BuildIthLeaf(buf, i)
	}
	tree.BuildNodes()

	return tree, nil
}
