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
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
)

func TestValueAtZetaBase(t *testing.T) {
	p := NewProof()

	var want koalabear.Element
	want.SetUint64(42)
	p.SetValueAtZetaBase("x", want)

	got, ok, err := p.ValueAtZetaBase("x")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("x not found")
	}
	if !got.Equal(&want) {
		t.Fatalf("got %s, want %s", got.String(), want.String())
	}

	var ext extensions.E6
	ext.B0.A1.SetOne()
	p.ValuesAtZeta["not_base"] = ext
	if _, _, err := p.ValueAtZetaBase("not_base"); err == nil {
		t.Fatal("expected non-base value to return an error")
	}
}

func TestBaseValuesAtZeta(t *testing.T) {
	p := NewProof()
	var x koalabear.Element
	x.SetUint64(7)
	p.SetValueAtZetaBase("x", x)

	values, err := p.BaseValuesAtZeta()
	if err != nil {
		t.Fatal(err)
	}
	got := values["x"]
	if !got.Equal(&x) {
		t.Fatalf("got %s, want %s", got.String(), x.String())
	}
}
