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
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/hash"
)

type Commitment struct {
	// Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	ValuesAtZeta  map[string]extensions.E4 // map string -> evaluation of the column whose String() is the key at zeta
	ExposedValues ExposedValues            // map column name -> values exposed to the verifier

	// Commitments holds the Merkle roots of every WMerkleTree the prover
	// commits during the protocol, in canonical order:
	//   trace-round-0 (decreasing N) → trace-round-1 → … → trace-round-{r-1} → AIR (decreasing N)
	// Setup roots are NOT stored here; they live in the verifier's VerificationKey.
	Commitments []hash.Digest

	DeepQuotientFriProof fri.Proof

	// DeepQuotientCommitment[l] holds the Merkle root of the FRI level-l
	// deep-quotient polynomial (level 0 = largest size). Same ordering as
	// the levels passed to fri.Prove.
	DeepQuotientCommitment []hash.Digest

	// PointSamplings[q][i] is the opening at FRI query position q of the i-th
	// committed tree in the FULL canonical order, INCLUDING setup at the front:
	//   setup (decreasing N) → trace-round-0 (decreasing N) → … → trace-round-{r-1} → AIR (decreasing N).
	PointSamplings [][]commitment.WMerkleProof
}

func NewProof() Proof {
	var res Proof
	res.ValuesAtZeta = make(map[string]extensions.E4)
	res.ExposedValues = make(map[string]ExposedValue)
	return res
}

func (p *Proof) SetValueAtZetaBase(name string, v koalabear.Element) {
	var ext extensions.E4
	ext.Lift(&v)
	p.ValuesAtZeta[name] = ext
}

func (p *Proof) SetValueAtZetaExt(name string, v extensions.E4) {
	p.ValuesAtZeta[name] = v
}

func (p Proof) ValueAtZetaBase(name string) (koalabear.Element, bool, error) {
	v, ok := p.ValuesAtZeta[name]
	if !ok {
		return koalabear.Element{}, false, nil
	}
	if !v.B0.A1.IsZero() || !v.B1.IsZero() {
		return koalabear.Element{}, true, fmt.Errorf("ValuesAtZeta[%q] is not a base-field value", name)
	}
	return v.B0.A0, true, nil
}

func (p Proof) ValueAtZetaExt(name string) (extensions.E4, bool) {
	v, ok := p.ValuesAtZeta[name]
	return v, ok
}

func (p Proof) BaseValuesAtZeta() (map[string]koalabear.Element, error) {
	values := make(map[string]koalabear.Element, len(p.ValuesAtZeta))
	for name := range p.ValuesAtZeta {
		v, _, err := p.ValueAtZetaBase(name)
		if err != nil {
			return nil, err
		}
		values[name] = v
	}
	return values, nil
}

func (p Proof) ExtValuesAtZeta() map[string]extensions.E4 {
	values := make(map[string]extensions.E4, len(p.ValuesAtZeta))
	for name, v := range p.ValuesAtZeta {
		values[name] = v
	}
	return values
}
