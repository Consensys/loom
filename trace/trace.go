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

package trace

import (
	"fmt"

	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/poly"
)

// RawTrace list of columns with the size N of each column
// type RawTrace = map[string]*poly.Polynomial

// ExtPolynomial is a column whose coefficients live in the Koalabear E4
// extension field.
type ExtPolynomial = poly.ExtPolynomial

// Trace contains base-field and extension-field columns. Base columns are the
// user-supplied trace and the current runtime path; extension columns are
// added by later mixed-field refactor steps.
type Trace struct {
	Base map[string]poly.Polynomial
	Ext  map[string]ExtPolynomial
}

func New(capacity ...int) Trace {
	baseCap := 0
	if len(capacity) > 0 {
		baseCap = capacity[0]
	}
	return Trace{
		Base: make(map[string]poly.Polynomial, baseCap),
		Ext:  make(map[string]ExtPolynomial),
	}
}

// ShallowClone returns a trace with copied maps and shared polynomial slices.
func (t Trace) ShallowClone() Trace {
	res := New(len(t.Base))
	for name, col := range t.Base {
		res.Base[name] = col
	}
	for name, col := range t.Ext {
		res.Ext[name] = col
	}
	return res
}

// MergeMatching overlays rhs into lhs. If a column exists in both traces, the
// values must match exactly. Polynomial slices are shared with the inputs.
func MergeMatching(lhs, rhs Trace) (Trace, error) {
	res := lhs.ShallowClone()
	for name, col := range rhs.Base {
		if existing, ok := res.Base[name]; ok {
			if !sameBasePolynomial(existing, col) {
				return Trace{}, fmt.Errorf("trace: base column %q already exists with different values", name)
			}
			continue
		}
		if _, ok := res.Ext[name]; ok {
			return Trace{}, fmt.Errorf("trace: column %q exists as extension column", name)
		}
		res.Base[name] = col
	}
	for name, col := range rhs.Ext {
		if existing, ok := res.Ext[name]; ok {
			if !sameExtPolynomial(existing, col) {
				return Trace{}, fmt.Errorf("trace: extension column %q already exists with different values", name)
			}
			continue
		}
		if _, ok := res.Base[name]; ok {
			return Trace{}, fmt.Errorf("trace: column %q exists as base column", name)
		}
		res.Ext[name] = col
	}
	return res, nil
}

func (t Trace) GetField(name string) (field.Kind, bool) {
	if _, ok := t.Ext[name]; ok {
		return field.Ext, true
	}
	if _, ok := t.Base[name]; ok {
		return field.Base, true
	}
	return field.Base, false
}

// checked registration
func (t Trace) PutBase(name string, c poly.Polynomial) error {
	if _, ok := t.Base[name]; ok {
		return fmt.Errorf("%s already registered in the trace", name)
	}
	if _, ok := t.Ext[name]; ok {
		return fmt.Errorf("%s already registered in the trace", name)
	}
	t.Base[name] = c
	return nil
}

// raw map assignment
func (t Trace) SetBase(name string, c poly.Polynomial) {
	t.Base[name] = c
}

// checked registration
func (t Trace) PutExt(name string, c ExtPolynomial) error {
	if _, ok := t.Base[name]; ok {
		return fmt.Errorf("%s already registered in the trace", name)
	}
	if _, ok := t.Ext[name]; ok {
		return fmt.Errorf("%s already registered in the trace", name)
	}
	t.Ext[name] = c
	return nil
}

// raw map assignment
func (t Trace) SetExt(name string, c ExtPolynomial) {
	t.Ext[name] = c
}

func sameBasePolynomial(lhs, rhs poly.Polynomial) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	for i := range lhs {
		if !lhs[i].Equal(&rhs[i]) {
			return false
		}
	}
	return true
}

func sameExtPolynomial(lhs, rhs ExtPolynomial) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	for i := range lhs {
		if !lhs[i].Equal(&rhs[i]) {
			return false
		}
	}
	return true
}
