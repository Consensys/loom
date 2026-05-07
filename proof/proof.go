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

	// TraceCommitments[round][s] holds the Merkle root of the trace polynomials
	// committed at round `round` whose size matches the s-th entry in the
	// per-round size group (sizes ordered by decreasing N).
	TraceCommitments [][][]byte

	// AIRQuotientsCommitment[s] holds the Merkle root of all AIR-quotient
	// chunks of size group s (decreasing N).
	AIRQuotientsCommitment [][]byte

	DeepQuotientFriProof fri.Proof

	// DeepQuotientCommitment[l] holds the Merkle root of the FRI level-l
	// deep-quotient polynomial (level 0 = largest size). Same ordering as
	// the levels passed to fri.Prove.
	DeepQuotientCommitment [][]byte

	// PointSamplingsSetup[q][s] holds the merkle proof for the list of values {f(w^i),f(-w^i)}
	// for the setup polynomials of size s (decreasing order) used to bridge the q-th FRI query
	PointSamplingsSetup [][]commitment.WMerkleProof

	// PointSamplingsTrace[q][round][s] holds the merkle proof for the list of values {f(w^i),f(-w^i)}
	// for the trace polynomials of size group s (decreasing N), round `round`, used to bridge the q-th FRI query
	PointSamplingsTrace [][][]commitment.WMerkleProof

	// PointSamplingsAIRQuotients[q][s] holds the merkle proof for the list of values {f(w^i),f(-w^i)}
	// for the air quotients polynomials of size group s (decreasing N), used to bridge the q-th FRI query
	PointSamplingsAIRQuotients [][]commitment.WMerkleProof
}

func NewProof() Proof {
	var res Proof
	res.ValuesAtZeta = make(map[string]koalabear.Element)
	res.PublicColumns = make(map[string]PublicInput)
	res.TraceCommitments = make([][][]byte, 0)
	return res
}
