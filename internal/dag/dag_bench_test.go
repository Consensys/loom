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

package dag

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
)

var benchmarkDAGNodes int

func BenchmarkExprToDAGFoldedRelations(b *testing.B) {
	for _, numRelations := range []int{128, 512, 2048} {
		b.Run(fmt.Sprintf("relations_%d", numRelations), func(b *testing.B) {
			folded, columnFields := benchmarkFoldedRelation(numRelations)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d := ExprToDAGWithColumnFields(folded, columnFields)
				benchmarkDAGNodes += len(d.Nodes)
			}
		})
	}
}

func benchmarkFoldedRelation(numRelations int) (expr.Expr, map[string]field.Kind) {
	relations := make([]expr.Expr, numRelations)
	columnFields := make(map[string]field.Kind, 4*numRelations)

	var c koalabear.Element
	c.SetUint64(17)

	for i := 0; i < numRelations; i++ {
		a := fmt.Sprintf("a_%d", i%64)
		b := fmt.Sprintf("b_%d", i%64)
		carry := fmt.Sprintf("carry_%d", i%128)
		next := fmt.Sprintf("next_%d", i%128)
		sel := fmt.Sprintf("selector_%d", i%16)
		lag := fmt.Sprintf("L_%d", i%8)

		if i%11 == 0 {
			columnFields[carry] = field.Ext
		}

		linA := expr.Col(a).Add(expr.Col(b))
		linB := expr.Col(b).Add(expr.Col(a)) // same expression as linA up to commutativity
		transition := expr.Col(carry, expr.WithShift(1)).Sub(expr.Col(next))
		gatedTransition := transition.Mul(expr.Col(sel).Add(expr.Lagrange(lag)))
		rangeLike := expr.Col(carry).Mul(expr.Col(carry).Sub(expr.Const(c)))

		relations[i] = linA.Mul(linB).Add(gatedTransition).Add(rangeLike)
	}

	return expr.Fold(expr.Challenge("alpha"), relations), columnFields
}
