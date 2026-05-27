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

package merkle

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

// ColumnNames lists every witness column the trace generator must fill.
type ColumnNames struct {
	ModuleName string
	Current    [DigestWidth]string
	Sibling    [DigestWidth]string
	Bit        string
	Left       [DigestWidth]string
	Right      [DigestWidth]string
	Parent     [DigestWidth]string
}

func makeColumnNames(name string) ColumnNames {
	cn := ColumnNames{ModuleName: name, Bit: BitColName(name)}
	for i := 0; i < DigestWidth; i++ {
		cn.Current[i] = CurrentColName(name, i)
		cn.Sibling[i] = SiblingColName(name, i)
		cn.Left[i] = LeftColName(name, i)
		cn.Right[i] = RightColName(name, i)
		cn.Parent[i] = ParentColName(name, i)
	}
	return cn
}

// BuildModule registers the Merkle-step module in the builder. capacity is
// the number of Merkle steps the gadget will accommodate; the module size is
// rounded up to the next power of two (FFT-domain constraint). Step 0 is the
// lowest level (leaf-side); step nRounded-1 is just below the root, with
// trailing rows padded by the trace generator.
//
// The chaining constraint links step k's current to step k-1's parent —
// except at step 0 where current is left unconstrained (it must equal the
// leaf supplied by the caller; in a full integration this would be either an
// exposed value or a cross-module lookup).
func BuildModule(builder *board.Builder, name string, capacity int) ColumnNames {
	if capacity <= 0 {
		panic("merkle.BuildModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := makeColumnNames(name)

	bit := expr.Col(cn.Bit)
	one := expr.Const(koalabear.One())

	// bit is binary: bit * (1 - bit) = 0
	mod.AssertZero(bit.Mul(one.Sub(bit)))

	// Selector relations:
	//   left[i]  = current[i] + bit*(sibling[i] - current[i])
	//   right[i] = sibling[i] + bit*(current[i] - sibling[i])
	for i := 0; i < DigestWidth; i++ {
		cur := expr.Col(cn.Current[i])
		sib := expr.Col(cn.Sibling[i])
		lhs := expr.Col(cn.Left[i])
		rhs := cur.Add(bit.Mul(sib.Sub(cur)))
		mod.AssertZero(lhs.Sub(rhs))

		rlhs := expr.Col(cn.Right[i])
		rrhs := sib.Add(bit.Mul(cur.Sub(sib)))
		mod.AssertZero(rlhs.Sub(rrhs))
	}

	// Chaining: for every row except row 0, current[i] equals the previous
	// row's parent[i]. We encode this with a "rotated" reference to the
	// parent column and exclude row 0 from the constraint.
	for i := 0; i < DigestWidth; i++ {
		cur := expr.Col(cn.Current[i])
		prevParent := expr.Rot(cn.Parent[i], -1)
		mod.AssertZeroExceptAt(cur.Sub(prevParent), 0)
	}

	// TODO (next milestone): assert parent[i] = Poseidon2-MD-HashNode(left, right)[i]
	// via a cross-module lookup into the Poseidon2 gadget. Without that
	// constraint, the gadget only checks structural consistency of the path,
	// not the cryptographic hash binding.

	builder.AddModule(mod)
	return cn
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	r := 1
	for r < n {
		r <<= 1
	}
	return r
}
