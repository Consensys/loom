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

import "github.com/consensys/loom/internal/commitment/fri"

type Commitment struct {
	// Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	PublicColumns      map[string]PublicInput // extracted values from columns of the trace, those values are passed as public inputs
	CommitmentOpenings fri.OpeningProof
}

func NewProof() Proof {
	var res Proof
	res.PublicColumns = make(map[string]PublicInput)
	return res
}
