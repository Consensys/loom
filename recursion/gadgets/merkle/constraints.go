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
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/leafhash"
	"github.com/consensys/loom/recursion/gadgets/nodehash"
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
	// LeafP / LeafQ are the ext-rail opening pair limbs (extfield order:
	// B0.A0, B1.A0, B0.A1, B1.A1). Only the row-0 values are meaningful;
	// other rows are filled with arbitrary self-consistent values to
	// satisfy the per-row leafhash constraints.
	LeafP [extfield.Limbs]string
	LeafQ [extfield.Limbs]string
	// LeafHash exposes the in-module width-24 Poseidon2 sponge sub-
	// columns used to bind (LeafP, LeafQ) to a digest. The gadget
	// enforces Current[i] == LeafHash.Digest[i] at row 0.
	LeafHash leafhash.ColumnNames
	// NodeHash exposes the per-row in-module Poseidon2-MD HashNode
	// sub-columns. The gadget enforces Parent[i] == NodeHash.Digest[i]
	// at every row.
	NodeHash nodehash.ColumnNames
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
	for i := 0; i < extfield.Limbs; i++ {
		cn.LeafP[i] = LeafPColName(name, i)
		cn.LeafQ[i] = LeafQColName(name, i)
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

	// Hash equality: per-row in-circuit HashNode(left, right) check.
	// Registers two width-16 Poseidon2 sub-groups inside this module and
	// constrains parent[i] to equal the resulting digest. A malicious
	// prover can no longer claim arbitrary parent digests; every parent
	// must be the real Poseidon2-MD compression of (left, right).
	cn.NodeHash = nodehash.Register(&mod, name+".nh", cn.Left, cn.Right)
	for i := 0; i < DigestWidth; i++ {
		mod.AssertZero(expr.Col(cn.Parent[i]).Sub(expr.Col(cn.NodeHash.Digest[i])))
	}

	// Leaf binding: register an ext-rail leafhash in this module and
	// constrain current[i] at row 0 to equal the leafhash digest. The
	// leafhash applies at every row (its sponge sub-columns are part of
	// the AIR), but the digest equality is gated to row 0 via
	// AssertZeroAt — leafP/leafQ at other rows can be arbitrary.
	cn.LeafHash = leafhash.RegisterExtLeafHash(&mod, name+".lh", cn.LeafP, cn.LeafQ)
	for i := 0; i < DigestWidth; i++ {
		mod.AssertZeroAt(
			expr.Col(cn.Current[i]).Sub(expr.Col(cn.LeafHash.Digest[i])),
			0,
		)
	}

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
