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

import "github.com/consensys/gnark-crypto/field/koalabear"

type PublicEntry struct {
	Idx   int
	Value koalabear.Element
}

type PublicInput struct {
	N       int // N = size of the module that the public column corresponding to this publicEntry belongs to
	Entries []PublicEntry
}

type PublicInputs map[string]PublicInput

// Bus stores the running sums of the sender and receiver
// participating in a log derivative based interaction, for instance a lookup
// The logup must satisfy Σ_i Logup_Sender_val_i - Σ_i Logup_Receiver_val_i=0
type LogupBus struct {
	Positive []string // Positive[i] = name of the public column whose n-1-th entry is the logup of the i-th positive logup column (the corresponding public column is in PublicInputs[name])
	Negative []string // Negative[i] = name of the public column whose n-1-th entry is the logup of the i-th negative logup column (the corresponding public column is in PublicInputs[name])
}
