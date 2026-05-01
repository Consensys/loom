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

package prover

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

func CheckVanishingRelation(tr trace.Trace, md board.CompiledModule) error {
	ev, err := poly.Eval(tr, *md.VanishingRelation, md.N)
	if err != nil {
		return err
	}
	for i, v := range ev {
		if !v.IsZero() {
			return fmt.Errorf("vanishing relation doesn hold at %d, got %s", i, v.String())
		}
	}
	return nil
}

func MergeTrace(t1 trace.Trace, t2 ...trace.Trace) trace.Trace {
	res := t1
	for _, t := range t2 {
		for k, v := range t {
			res[k] = v
		}
	}
	return res
}

// TraceFibonacci traces a Fibonacci sequence, encoded with 3 columns
// A, B, C subject to the following constraints:
// C = A + B
// A_shifted = B, except at the last entry
// B_shifted = C, except at the last entry
// with A[0]=a, B[0]=b
func TraceFibonacci(n int, a, b koalabear.Element) trace.Trace {

	n = int(ecc.NextPowerOfTwo(uint64(n)))

	res := make(trace.Trace)
	A := make([]koalabear.Element, n)
	B := make([]koalabear.Element, n)
	C := make([]koalabear.Element, n)

	A[0].Set(&a)
	B[0].Set(&b)
	for i := 0; i < n; i++ {
		C[i].Add(&A[i], &B[i])
		if i < n-1 {
			A[i+1].Set(&B[i])
			B[i+1].Set(&C[i])
		}
	}
	res["A"] = A
	res["B"] = B
	res["C"] = C

	return res
}

func TraceRange(n int) trace.Trace {
	n = int(ecc.NextPowerOfTwo(uint64(n)))
	res := make(trace.Trace)
	col := make([]koalabear.Element, 2*n) // to handle modules of different size
	for i := 0; i < 2*n; i++ {
		col[i].SetUint64(uint64(i))
	}
	res["Lookup"] = col
	return res
}
