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

package hash

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/zeebo/blake3"
)

// Blake3FieldHasher implements FieldHasher using Blake3. It serializes field
// elements to bytes (same encoding as SHA256FieldHasher) and is intended for
// non-recursive workflows that prefer Blake3 over SHA-256 or Poseidon2.
type Blake3FieldHasher struct {
	h *blake3.Hasher
}

func NewBlake3FieldHasher() *Blake3FieldHasher {
	return &Blake3FieldHasher{h: blake3.New()}
}

func (h *Blake3FieldHasher) Reset() {
	h.ensure()
	h.h.Reset()
}

func (h *Blake3FieldHasher) WriteElements(elmts ...koalabear.Element) {
	h.ensure()
	for i := range elmts {
		b := elmts[i].Bytes()
		_, _ = h.h.Write(b[:])
	}
}

func (h *Blake3FieldHasher) WriteExt(elmts ...ext.E6) {
	for _, elmt := range elmts {
		h.WriteElements(elmt.B0.A0, elmt.B0.A1, elmt.B1.A0, elmt.B1.A1, elmt.B2.A0, elmt.B2.A1)
	}
}

func (h *Blake3FieldHasher) Sum() Digest {
	h.ensure()
	var b [32]byte
	copy(b[:], h.h.Sum(nil))
	return DigestFromBytes32(b)
}

func (h *Blake3FieldHasher) ensure() {
	if h.h == nil {
		h.h = blake3.New()
	}
}
