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

	"github.com/consensys/loom/internal/poly"
)

// RawTrace list of columns with the size N of each column
// type RawTrace = map[string]*poly.Polynomial

// RawTrace contains a list of columns, which are interpreted as interpolated polynomials.
// E.g: RawTrace[i] is a polynomial such that RawTrace[i](\omega^j) = RawTrace[i][j]
type Trace = map[string]poly.Polynomial

func RegisterColumn(t Trace, name string, c poly.Polynomial) error {
	if _, ok := t[name]; ok {
		return fmt.Errorf("%s already registered in the trace", name)
	}
	t[name] = c
	return nil
}
