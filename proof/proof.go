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

package proof

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/fri"
)

type Commitment struct {
	// Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	ValuesAtZeta  map[string]koalabear.Element // map string -> evaluation of the column whose String() is the key at zeta
	PublicColumns map[string]PublicInput       // extracted values from columns of the trace, those values are passed as public inputs

	// Commitments holds the Merkle roots of every WMerkleTree the prover
	// commits during the protocol, in canonical order:
	//   trace-round-0 (decreasing N) → trace-round-1 → … → trace-round-{r-1} → AIR (decreasing N)
	// Setup roots are NOT stored here — they live in the verifier's PublicKey.
	Commitments [][]byte

	DeepQuotientFriProof fri.Proof

	// DeepQuotientCommitment[l] holds the Merkle root of the FRI level-l
	// deep-quotient polynomial (level 0 = largest size). Same ordering as
	// the levels passed to fri.Prove.
	DeepQuotientCommitment [][]byte

	// PointSamplings[q][i] is the opening at FRI query position q of the i-th
	// committed tree in the FULL canonical order, INCLUDING setup at the front:
	//   setup (decreasing N) → trace-round-0 (decreasing N) → … → trace-round-{r-1} → AIR (decreasing N).
	PointSamplings [][]commitment.WMerkleProof
}

func NewProof() Proof {
	var res Proof
	res.ValuesAtZeta = make(map[string]koalabear.Element)
	res.PublicColumns = make(map[string]PublicInput)
	return res
}
