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

package poseidon2

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

// BuildModule registers a Poseidon2 gadget module named `name` in the builder
// with capacity for n permutations. n must be a power of two (caller's
// responsibility) since module sizes are FFT-domain sizes.
//
// The returned ColumnNames describe every witness column the trace generator
// must fill. Consumers can wire their constraints to the input or output of
// the gadget via expr.Col(InColName(...)) / expr.Col(OutColName(...)).
func BuildModule(builder *board.Builder, name string, n int) ColumnNames {
	if n <= 0 || n&(n-1) != 0 {
		panic("poseidon2.BuildModule: n must be a power of two")
	}

	params := Params()
	mod := board.NewModule(name)
	mod.N = n

	// Input columns referenced via expr.Col by lane.
	inExpr := make([]expr.Expr, Width)
	for i := 0; i < Width; i++ {
		inExpr[i] = expr.Col(InColName(name, i))
	}

	// State going into round R (prev_state). For R == 0 this is the external
	// linear layer applied to the inputs; for R > 0 it is the previous post.
	prev := matMulExternalExpr(inExpr)

	for r := 0; r < NbRounds; r++ {
		rc := params.RoundKeys[r]
		full := IsFullRound(r)

		// sbox witness columns referenced by lane.
		var sboxExpr [Width]expr.Expr

		if full {
			// sbox[i] = (prev[i] + RC[r][i])^3
			for i := 0; i < Width; i++ {
				sboxExpr[i] = expr.Col(SBoxColName(name, r, i))
				rhs := prev[i].Add(expr.Const(rc[i])).Pow(3)
				mod.AssertZero(sboxExpr[i].Sub(rhs))
			}
		} else {
			// Partial round: only lane 0 has an S-box; other lanes pass through
			// the previous post unchanged.
			sboxExpr[0] = expr.Col(SBoxColName(name, r, 0))
			rhs := prev[0].Add(expr.Const(rc[0])).Pow(3)
			mod.AssertZero(sboxExpr[0].Sub(rhs))
			for i := 1; i < Width; i++ {
				sboxExpr[i] = prev[i]
			}
		}

		// Linear layer: post[i] = M_*(sbox)[i].
		var postLinear [Width]expr.Expr
		if full {
			ext := matMulExternalExpr(sboxExpr[:])
			copy(postLinear[:], ext)
		} else {
			intl := matMulInternalExpr(sboxExpr[:])
			copy(postLinear[:], intl)
		}

		// Bind post witness columns to the computed linear layer.
		postExpr := make([]expr.Expr, Width)
		for i := 0; i < Width; i++ {
			postExpr[i] = expr.Col(PostColName(name, r, i))
			mod.AssertZero(postExpr[i].Sub(postLinear[i]))
		}

		prev = postExpr
	}

	builder.AddModule(mod)

	return makeColumnNames(name)
}

// ColumnNames lists every witness column the trace generator must fill for
// the gadget. Provided as a flat list to make the trace API straightforward.
type ColumnNames struct {
	ModuleName string
	In         [Width]string
	SBox       [NbRounds][Width]string // only populated lanes for partial rounds matter (lane 0)
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

// matMulExternalExpr applies circ(2 M4, M4, M4, M4) to s (length Width).
//
// Equivalent to the native matMulExternalInPlace; we compute t = matMulM4(s)
// and then output[i] = t[i] + sum_{c'} t[4*c' + i%4].
func matMulExternalExpr(s []expr.Expr) []expr.Expr {
	if len(s) != Width {
		panic("matMulExternalExpr: length must equal Width")
	}
	// Apply M4 to each 4-element chunk.
	t := make([]expr.Expr, Width)
	for c := 0; c < Width/4; c++ {
		s0, s1, s2, s3 := s[4*c+0], s[4*c+1], s[4*c+2], s[4*c+3]
		// M4 rows:
		// [2 3 1 1]: 2*s0 + 3*s1 + s2 + s3
		// [1 2 3 1]: s0 + 2*s1 + 3*s2 + s3
		// [1 1 2 3]: s0 + s1 + 2*s2 + 3*s3
		// [3 1 1 2]: 3*s0 + s1 + s2 + 2*s3
		t[4*c+0] = times(s0, 2).Add(times(s1, 3)).Add(s2).Add(s3)
		t[4*c+1] = s0.Add(times(s1, 2)).Add(times(s2, 3)).Add(s3)
		t[4*c+2] = s0.Add(s1).Add(times(s2, 2)).Add(times(s3, 3))
		t[4*c+3] = times(s0, 3).Add(s1).Add(s2).Add(times(s3, 2))
	}
	// Cross-chunk sums tmp[k] = sum_c t[4*c + k].
	var tmp [4]expr.Expr
	for k := 0; k < 4; k++ {
		acc := t[k]
		for c := 1; c < Width/4; c++ {
			acc = acc.Add(t[4*c+k])
		}
		tmp[k] = acc
	}
	// output[i] = t[i] + tmp[i%4].
	out := make([]expr.Expr, Width)
	for i := 0; i < Width; i++ {
		out[i] = t[i].Add(tmp[i%4])
	}
	return out
}

// matMulInternalExpr applies the width-16 internal matrix to s.
//
// The native matrix has 1s off-diagonal and (1 + diag[i]) on the diagonal,
// where diag is internalDiag(). Equivalently:
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

// times returns k * e, where k is a small positive integer. For k = 1 it
// returns e unchanged (saves an unnecessary Mul node).
func times(e expr.Expr, k uint64) expr.Expr {
	if k == 1 {
		return e
	}
	var c koalabear.Element
	c.SetUint64(k)
	return e.Mul(expr.Const(c))
}
