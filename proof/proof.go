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
	ValuesAtZeta           map[string]koalabear.Element // map string -> evaluation of the column whose String() is the key at zeta
	PublicColumns          map[string]PublicInput       // extracted values from columns of the trace, those values are passed as public inputs
	TraceCommitments       [][]byte                     // rounds of FS, entry i stores the data to hash at round i to derive 'challenge@loom_<i>'
	AIRQuotientsCommitment []byte
	DeepQuotientFriProof   fri.Proof
	DeepQuotientCommitment []byte
	PointSamplings         [][]commitment.WMerkleProof // list of values {f(w^i),f(-w^i)} for the trace polynomials and the air polynomials, for some i. One entry per query position, entry i stores the Merkle proofs of the trees storing the relevant polynomials
}

func NewProof() Proof {
	var res Proof
	res.ValuesAtZeta = make(map[string]koalabear.Element)
	res.PublicColumns = make(map[string]PublicInput)
	res.TraceCommitments = make([][]byte, 0)
	res.PointSamplings = make([][]commitment.WMerkleProof, 0)
	return res
}
