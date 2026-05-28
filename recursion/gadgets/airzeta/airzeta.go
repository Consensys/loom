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

// Package airzeta implements the in-circuit equivalent of
// dag.EvalExt — given the inner program's vanishing-relation DAG and a
// per-leaf E4Expr that holds the column's value at zeta, the gadget
// produces an E4Expr that evaluates to V(zeta).
//
// This is a pure expression-builder helper: it adds no columns or
// constraints on its own. The caller wires the returned E4Expr to an
// AIR-relation check by constraining
//
//	V(zeta) == (zeta^N - 1) * Q(zeta)
//
// per module, where Q(zeta) is reconstructed from the per-chunk
// values at zeta and zeta^N from PowExt.
//
// Limb ordering matches gadgets/extfield: {B0.A0, B1.A0, B0.A1, B1.A1}.
package airzeta

import (
	"fmt"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/dag"
	"github.com/consensys/loom/recursion/extfield"
)

// EvalDAG walks d in topological order and returns an E4Expr whose value
// is dag.EvalExt(values). leafValues maps each non-constant leaf's
// String() key (the same key dag.EvalExt uses) to the E4Expr representing
// that leaf's value at zeta.
//
// Missing values panic — leaf coverage must be complete.
func EvalDAG(d *dag.DAG, leafValues map[string]extfield.E4Expr) extfield.E4Expr {
	cache := make(map[*dag.DAGNode]extfield.E4Expr, len(d.Nodes))
	for _, node := range d.Nodes {
		switch node.Kind {
		case dag.KindLeaf:
			if node.IsConst {
				cache[node] = extfield.FromBase(expr.Const(node.ConstVal))
				continue
			}
			key := node.Leaf.String()
			v, ok := leafValues[key]
			if !ok {
				panic("airzeta.EvalDAG: missing value for leaf " + key)
			}
			cache[node] = v
		case dag.KindAdd:
			acc := cache[node.Children[0]]
			for _, c := range node.Children[1:] {
				acc = acc.Add(cache[c])
			}
			cache[node] = acc
		case dag.KindSub:
			cache[node] = cache[node.Children[0]].Sub(cache[node.Children[1]])
		case dag.KindMul:
			acc := cache[node.Children[0]]
			for _, c := range node.Children[1:] {
				acc = acc.Mul(cache[c])
			}
			cache[node] = acc
		case dag.KindPow:
			cache[node] = PowExt(cache[node.Children[0]], int(node.Exp))
		default:
			panic(fmt.Sprintf("airzeta.EvalDAG: unknown NodeKind %d", node.Kind))
		}
	}
	return cache[d.Root]
}

// PowExt returns base^n as an E4Expr via square-and-multiply. n must be
// non-negative; n == 0 returns extfield.One().
func PowExt(base extfield.E4Expr, n int) extfield.E4Expr {
	if n < 0 {
		panic("airzeta.PowExt: n must be non-negative")
	}
	if n == 0 {
		return extfield.One()
	}
	// First bit of n is always 1 (n != 0), so start with res = base and
	// process the remaining bits MSB to LSB. Track curr = base^(2^bit) by
	// repeated squaring.
	res := extfield.One()
	curr := base
	for n > 0 {
		if n&1 == 1 {
			res = res.Mul(curr)
		}
		n >>= 1
		if n > 0 {
			curr = curr.Mul(curr)
		}
	}
	return res
}

// RegisterAIRCheck adds the per-module AIR-at-zeta equality constraint
//
//	V(zeta) == (zeta^N - 1) * Q(zeta)
//
// where V(zeta) is the value of the inner module's vanishing-relation
// DAG at zeta (computed via EvalDAG over leafValues) and
//
//	Q(zeta) = sum_{i=0..len(chunks)-1} chunks[i] * (zeta^N)^i
//
// is the AIR quotient reconstructed from per-chunk evaluations at zeta.
//
// Four constraints are emitted on mod, one per E4 limb. The constraint
// degree grows with N (zeta^N is inlined); for inner modules with
// N <= 16 this is comfortably within Loom's degree budget. For larger
// N a future variant should materialize the zeta-power chain as
// witness columns to flatten the constraint degree.
func RegisterAIRCheck(
	mod *board.Module,
	d *dag.DAG,
	N int,
	leafValues map[string]extfield.E4Expr,
	zeta extfield.E4Expr,
	chunks []extfield.E4Expr,
) {
	v := EvalDAG(d, leafValues)
	zetaPowN := PowExt(zeta, N)
	one := extfield.One()
	zetaPowNMinusOne := zetaPowN.Sub(one)

	var qZeta extfield.E4Expr
	switch len(chunks) {
	case 0:
		qZeta = extfield.Zero()
	default:
		qZeta = chunks[0]
		zetaPowIN := zetaPowN
		for i := 1; i < len(chunks); i++ {
			qZeta = qZeta.Add(chunks[i].Mul(zetaPowIN))
			if i+1 < len(chunks) {
				zetaPowIN = zetaPowIN.Mul(zetaPowN)
			}
		}
	}

	rhs := zetaPowNMinusOne.Mul(qZeta)
	for _, rel := range v.EqualityConstraints(rhs) {
		mod.AssertZero(rel)
	}
}

