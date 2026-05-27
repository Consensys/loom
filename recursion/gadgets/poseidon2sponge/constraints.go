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

package poseidon2sponge

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

// ColumnNames lists every witness column the trace generator must fill.
type ColumnNames struct {
	ModuleName string
	In         [Width]string
	SBox       [NbRounds][Width]string // partial rounds: only index 0 is meaningful
	Post       [NbRounds][Width]string
}

func makeColumnNames(name string) ColumnNames {
	cn := ColumnNames{ModuleName: name}
	for i := 0; i < Width; i++ {
		cn.In[i] = InColName(name, i)
	}
	for r := 0; r < NbRounds; r++ {
		for i := 0; i < Width; i++ {
			cn.Post[r][i] = PostColName(name, r, i)
		}
		if IsFullRound(r) {
			for i := 0; i < Width; i++ {
				cn.SBox[r][i] = SBoxColName(name, r, i)
			}
		} else {
			cn.SBox[r][0] = SBoxColName(name, r, 0)
		}
	}
	return cn
}

// BuildModule registers a standalone width-24 Poseidon2 module in the
// builder. n is the capacity in permutations; it must be a power of two.
// For composing with other gadgets in the same module, use Register.
func BuildModule(builder *board.Builder, name string, n int) ColumnNames {
	if n <= 0 || n&(n-1) != 0 {
		panic("poseidon2sponge.BuildModule: n must be a power of two")
	}

	mod := board.NewModule(name)
	mod.N = n
	cn := Register(&mod, name)
	builder.AddModule(mod)
	return cn
}

// Register appends the width-24 Poseidon2 columns and constraints to an
// existing module under the given prefix. mod.N must already be set.
func Register(mod *board.Module, prefix string) ColumnNames {
	params := Params()
	cn := makeColumnNames(prefix)

	inExpr := make([]expr.Expr, Width)
	for i := 0; i < Width; i++ {
		inExpr[i] = expr.Col(cn.In[i])
	}

	prev := matMulExternalExpr(inExpr)

	for r := 0; r < NbRounds; r++ {
		rc := params.RoundKeys[r]
		full := IsFullRound(r)

		var sboxExpr [Width]expr.Expr

		if full {
			for i := 0; i < Width; i++ {
				sboxExpr[i] = expr.Col(cn.SBox[r][i])
				rhs := prev[i].Add(expr.Const(rc[i])).Pow(3)
				mod.AssertZero(sboxExpr[i].Sub(rhs))
			}
		} else {
			sboxExpr[0] = expr.Col(cn.SBox[r][0])
			rhs := prev[0].Add(expr.Const(rc[0])).Pow(3)
			mod.AssertZero(sboxExpr[0].Sub(rhs))
			for i := 1; i < Width; i++ {
				sboxExpr[i] = prev[i]
			}
		}

		var postLinear [Width]expr.Expr
		if full {
			ext := matMulExternalExpr(sboxExpr[:])
			copy(postLinear[:], ext)
		} else {
			intl := matMulInternalExpr(sboxExpr[:])
			copy(postLinear[:], intl)
		}

		postExpr := make([]expr.Expr, Width)
		for i := 0; i < Width; i++ {
			postExpr[i] = expr.Col(cn.Post[r][i])
			mod.AssertZero(postExpr[i].Sub(postLinear[i]))
		}

		prev = postExpr
	}

	return cn
}

// matMulExternalExpr applies the circ(2 M4, M4, ..., M4) external matrix
// for width Width to s. Implementation mirrors matMulExternalInPlace in
// the native poseidon2 package: matMulM4 per 4-element chunk, then add
// per-position cross-chunk sums to each chunk.
func matMulExternalExpr(s []expr.Expr) []expr.Expr {
	if len(s) != Width {
		panic("matMulExternalExpr: length must equal Width")
	}
	nChunks := Width / 4

	t := make([]expr.Expr, Width)
	for c := 0; c < nChunks; c++ {
		s0, s1, s2, s3 := s[4*c+0], s[4*c+1], s[4*c+2], s[4*c+3]
		// M4 rows:
		// [2 3 1 1] / [1 2 3 1] / [1 1 2 3] / [3 1 1 2]
		t[4*c+0] = times(s0, 2).Add(times(s1, 3)).Add(s2).Add(s3)
		t[4*c+1] = s0.Add(times(s1, 2)).Add(times(s2, 3)).Add(s3)
		t[4*c+2] = s0.Add(s1).Add(times(s2, 2)).Add(times(s3, 3))
		t[4*c+3] = times(s0, 3).Add(s1).Add(s2).Add(times(s3, 2))
	}

	var tmp [4]expr.Expr
	for k := 0; k < 4; k++ {
		acc := t[k]
		for c := 1; c < nChunks; c++ {
			acc = acc.Add(t[4*c+k])
		}
		tmp[k] = acc
	}
	out := make([]expr.Expr, Width)
	for i := 0; i < Width; i++ {
		out[i] = t[i].Add(tmp[i%4])
	}
	return out
}

// matMulInternalExpr applies the width-24 internal matrix to s:
//
//	out[i] = (sum_j s[j]) + diag[i] * s[i]
func matMulInternalExpr(s []expr.Expr) []expr.Expr {
	if len(s) != Width {
		panic("matMulInternalExpr: length must equal Width")
	}
	sum := s[0]
	for i := 1; i < Width; i++ {
		sum = sum.Add(s[i])
	}
	diag := internalDiag()
	out := make([]expr.Expr, Width)
	for i := 0; i < Width; i++ {
		out[i] = sum.Add(s[i].Mul(expr.Const(diag[i])))
	}
	return out
}

// times returns k * e, where k is a small positive integer.
func times(e expr.Expr, k uint64) expr.Expr {
	if k == 1 {
		return e
	}
	var c koalabear.Element
	c.SetUint64(k)
	return e.Mul(expr.Const(c))
}
