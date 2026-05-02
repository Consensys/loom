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

package expr

import "github.com/consensys/gnark-crypto/field/koalabear"

// Fold returns \Sigma_{i} v^iC[i].
// v can be any Expr (Var, Placeholder, etc.).
// Returns the zero constant when C is empty.
func Fold(v Expr, C []Expr) Expr {
	if len(C) == 0 {
		return Const(koalabear.Element{})
	}
	res := C[0]
	for i := 1; i < len(C); i++ {
		res = res.Add(C[i].Mul(v.Pow(uint32(i))))
	}
	return res
}
