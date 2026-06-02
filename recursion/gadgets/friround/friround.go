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

// Package friround implements an in-circuit verifier for a SINGLE FRI fold
// round across many queries.
//
// One row of the module verifies one query's fold step at this round:
//
//	expected = (P + Q)/2 + alpha * (P - Q) * invTwo * xInv
//
// where xInv = omega^{-base} is DERIVED inside the same module via
// composition with gadgets/bits + gadgets/binexp. Because all rows share the
// same round j (and hence the same omega_j), omega_j^{-1} can be baked into
// binexp's running-product constants as a fixed base.
//
// This is the natural layout when a separate module is allocated per FRI
// round (Plonky3-style chip-per-AIR). Cross-round chaining and final-poly
// matching are NOT enforced here; they will be added as cross-module
// lookups in a follow-up milestone.
//
// Column layout per row:
//
//   - P_0..5, Q_0..5, alpha_0..5                    // E6 limbs
//   - base                                          // uint in [0, 2^kBits)
//   - <bits-decomp>.bit_0..bit_{kBits-1}            // via bits.Register
//   - <binexp>.step_1..step_{kBits}                 // via binexp.Register
//   - expected_0..5                                 // E6 limbs
//
// The xInv value used in the fold equation is the LAST step of the binexp
// chain, so corruption of any intermediate step or bit propagates into the
// fold check.
package friround

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/binexp"
	"github.com/consensys/loom/recursion/gadgets/bits"
)

// Column-name helpers.
func PColName(name string, i int) string     { return fmt.Sprintf("%s.P_%d", name, i) }
func QColName(name string, i int) string     { return fmt.Sprintf("%s.Q_%d", name, i) }
func AlphaColName(name string, i int) string { return fmt.Sprintf("%s.alpha_%d", name, i) }
func ExpColName(name string, i int) string   { return fmt.Sprintf("%s.expected_%d", name, i) }

// ColumnNames lists every witness column the trace generator must fill.
type ColumnNames struct {
	ModuleName string
	P          [extfield.Limbs]string
	Q          [extfield.Limbs]string
	Alpha      [extfield.Limbs]string
	Expected   [extfield.Limbs]string
	Bits       bits.ColumnNames
	BinExp     binexp.ColumnNames
	OmegaInv   koalabear.Element // baked into binexp's running-product constants
	KBits      int               // log2 ceiling of the round's domain half-size
}

// XInvColName returns the column holding the derived xInv = omega^{-base}.
// It is the final step of the binexp chain.
func (cn ColumnNames) XInvColName() string {
	return cn.BinExp.Result()
}

// invTwo returns 1/2 in koalabear.
func invTwo() koalabear.Element {
	var two, r koalabear.Element
	two.SetUint64(2)
	r.Inverse(&two)
	return r
}

// BuildModule registers a standalone friround module in the builder.
// capacity is the number of queries to be verified at this round; it is
// rounded up to the next power of two. omegaInv is omega_j^{-1}, the
// inverse of the round-j domain generator. kBits is the number of bits
// used to decompose `base`; it must be >= ceil(log2(N_j / 2)).
//
// Padding rows store P=Q=alpha=expected=0, base=0 (all bits 0; xInv via
// binexp = 1, which is correct for base=0). The fold equation then
// degenerates to 0 = 0 + 0*0*1*1 = 0, which holds.
//
// For composing multiple rounds in a single module (e.g. for cross-round
// chaining), use Register instead.
func BuildModule(builder *board.Builder, name string, capacity int, omegaInv koalabear.Element, kBits int) ColumnNames {
	if capacity <= 0 {
		panic("friround.BuildModule: capacity must be positive")
	}
	n := nextPow2(capacity)

	mod := board.NewModule(name)
	mod.N = n
	cn := Register(&mod, name, omegaInv, kBits)
	builder.AddModule(mod)
	return cn
}

// Register appends a friround column-group and its constraints to an
// existing module under the given prefix. The caller is responsible for
// setting mod.N (must be a power of two) and for calling
// builder.AddModule(*mod) once every group is registered.
//
// Using Register multiple times on the same module (with distinct prefixes
// and per-round omegaInv values) lets a single module hold every round of
// a per-query FRI verifier — the rows index queries, the column-groups
// index rounds. See gadgets/frichain for the cross-round linkage that
// glues consecutive groups together.
func Register(mod *board.Module, prefix string, omegaInv koalabear.Element, kBits int) ColumnNames {
	if kBits <= 0 {
		panic("friround.Register: kBits must be positive")
	}

	cn := ColumnNames{
		ModuleName: prefix,
		OmegaInv:   omegaInv,
		KBits:      kBits,
	}
	for i := 0; i < extfield.Limbs; i++ {
		cn.P[i] = PColName(prefix, i)
		cn.Q[i] = QColName(prefix, i)
		cn.Alpha[i] = AlphaColName(prefix, i)
		cn.Expected[i] = ExpColName(prefix, i)
	}

	cn.Bits = bits.Register(mod, prefix+".base", kBits)
	cn.BinExp = binexp.Register(mod, prefix+".xinv", omegaInv, cn.Bits)

	invHalf := expr.Const(invTwo())
	xInv := expr.Col(cn.XInvColName())

	P := extfield.FromLimbs(expr.Col(cn.P[0]), expr.Col(cn.P[1]), expr.Col(cn.P[2]), expr.Col(cn.P[3]), expr.Col(cn.P[4]), expr.Col(cn.P[5]))
	Q := extfield.FromLimbs(expr.Col(cn.Q[0]), expr.Col(cn.Q[1]), expr.Col(cn.Q[2]), expr.Col(cn.Q[3]), expr.Col(cn.Q[4]), expr.Col(cn.Q[5]))
	alpha := extfield.FromLimbs(expr.Col(cn.Alpha[0]), expr.Col(cn.Alpha[1]), expr.Col(cn.Alpha[2]), expr.Col(cn.Alpha[3]), expr.Col(cn.Alpha[4]), expr.Col(cn.Alpha[5]))
	expected := extfield.FromLimbs(expr.Col(cn.Expected[0]), expr.Col(cn.Expected[1]), expr.Col(cn.Expected[2]), expr.Col(cn.Expected[3]), expr.Col(cn.Expected[4]), expr.Col(cn.Expected[5]))

	sumHalf := P.Add(Q).MulByBase(invHalf)
	diff := P.Sub(Q)
	scaled := alpha.Mul(diff).MulByBase(invHalf).MulByBase(xInv)
	rhs := sumHalf.Add(scaled)

	for _, rel := range expected.EqualityConstraints(rhs) {
		mod.AssertZero(rel)
	}

	// Pin alpha constant across all rows: alpha is one FS challenge per
	// round, shared by every query. Without this constraint a malicious
	// prover could supply a different alpha per row. Applied at every row
	// except the last (the wraparound at row N-1 is excluded).
	if mod.N >= 2 {
		for i := 0; i < extfield.Limbs; i++ {
			rel := expr.Col(cn.Alpha[i]).Sub(expr.Rot(cn.Alpha[i], 1))
			mod.AssertZeroExceptAt(rel, mod.N-1)
		}
	}

	return cn
}

// Query captures one query's fold inputs at this round.
type Query struct {
	P     ext.E6
	Q     ext.E6
	Alpha ext.E6
	Base  uint64 // < 2^kBits
}

// Folded computes the native fold result, using xInv = omegaInv^base.
func (q Query) Folded(omegaInv koalabear.Element) ext.E6 {
	var xInv koalabear.Element
	xInv.SetOne()
	if q.Base > 0 {
		var x koalabear.Element
		x.Set(&omegaInv)
		v := q.Base
		// Square-and-multiply.
		xInv.SetOne()
		for v > 0 {
			if v&1 == 1 {
				xInv.Mul(&xInv, &x)
			}
			x.Mul(&x, &x)
			v >>= 1
		}
	}

	half := invTwo()
	var sum, diff, scaled, out ext.E6
	sum.Add(&q.P, &q.Q)
	sum.MulByElement(&sum, &half)
	diff.Sub(&q.P, &q.Q)
	diff.MulByElement(&diff, &half)
	diff.MulByElement(&diff, &xInv)
	scaled.Mul(&diff, &q.Alpha)
	out.Add(&sum, &scaled)
	return out
}

// GenerateTrace fills the witness columns for a friround module from a list
// of Query inputs. Padding rows have base=0 and all-zero P/Q/alpha/expected,
// satisfying the constraints trivially.
func GenerateTrace(cn ColumnNames, capacity int, queries []Query) map[string][]koalabear.Element {
	n := nextPow2(capacity)
	if len(queries) > n {
		panic("friround.GenerateTrace: more queries than module rows")
	}

	cols := make(map[string][]koalabear.Element, 4*extfield.Limbs+1+cn.KBits+cn.KBits)
	alloc := func(name string) []koalabear.Element {
		c := make([]koalabear.Element, n)
		cols[name] = c
		return c
	}

	var pCols, qCols, aCols, eCols [extfield.Limbs][]koalabear.Element
	for i := 0; i < extfield.Limbs; i++ {
		pCols[i] = alloc(cn.P[i])
		qCols[i] = alloc(cn.Q[i])
		aCols[i] = alloc(cn.Alpha[i])
		eCols[i] = alloc(cn.Expected[i])
	}

	// bits.GenerateTrace and binexp.GenerateTraceFor write their own column
	// slices; merge into cols after the per-row population.
	baseValues := make([]uint64, n)
	for row := 0; row < n; row++ {
		if row >= len(queries) {
			continue
		}
		q := queries[row]
		baseValues[row] = q.Base
		pLimbs := extfield.FromE6(q.P)
		qLimbs := extfield.FromE6(q.Q)
		aLimbs := extfield.FromE6(q.Alpha)
		folded := q.Folded(cn.OmegaInv)
		fLimbs := extfield.FromE6(folded)
		for i := 0; i < extfield.Limbs; i++ {
			pCols[i][row].Set(&pLimbs[i])
			qCols[i][row].Set(&qLimbs[i])
			aCols[i][row].Set(&aLimbs[i])
			eCols[i][row].Set(&fLimbs[i])
		}
	}

	// Fill bits trace.
	bitsCols := bits.GenerateTrace(cn.Bits, n, baseValues)
	for k, v := range bitsCols {
		cols[k] = v
	}

	// Fill binexp trace.
	bitRows := make([][]uint64, n)
	for row := 0; row < n; row++ {
		bitRows[row] = make([]uint64, cn.KBits)
		v := baseValues[row]
		for i := 0; i < cn.KBits; i++ {
			bitRows[row][i] = (v >> uint(i)) & 1
		}
	}
	binexpCols := binexp.GenerateTraceFor(cn.BinExp, bitRows)
	for k, v := range binexpCols {
		cols[k] = v
	}

	return cols
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
