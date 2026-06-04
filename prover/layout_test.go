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
	"reflect"
	"testing"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
)

// TestBuildLayoutBaseOnlySlotStability locks in the concrete (TreeIdx,
// PolyIdx, Field) assignments for a base-only program. PR8 adds Slot.Field and
// rail-relative PolyIdx values, but it must not shift existing base-only
// TreeIdx/PolyIdx assignments.
func TestBuildLayoutBaseOnlySlotStability(t *testing.T) {
	builder := board.NewBuilder()

	m := board.NewModule("m")
	m.N = 8
	mulChunk := constants.MultiplicityChunkName("mul", 0)
	// (((z + mul_0) + s) + t).LeavesFull = [z, mul_0, s, t].
	rel := expr.Col("z").Add(expr.Col(mulChunk)).
		Add(expr.Col("s")).
		Add(expr.Col("t")).
		Add(expr.Setup("pz")).
		Add(expr.Setup("pa")).
		Add(expr.Setup("pm"))
	m.AssertZero(rel)
	builder.AddModule(m)

	// AddCountMultiplicityStep is intentionally used here because it stays in
	// the base field; it does not depend on a Fiat-Shamir challenge.
	builder.AddCountMultiplicityStep(
		[]expr.Expr{expr.Col("s")},
		[]expr.Expr{expr.Col("t")},
		"mul",
	)

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	layout := BuildLayout(program, 1)

	wantColSlot := map[string]Slot{
		// Setup section (TreeIdx=0): setup columns sorted by name.
		"pa": {TreeIdx: 0, PolyIdx: 0, Field: field.Base},
		"pm": {TreeIdx: 0, PolyIdx: 1, Field: field.Base},
		"pz": {TreeIdx: 0, PolyIdx: 2, Field: field.Base},
		// Trace round 0 (TreeIdx=1): relation leaves in LeavesFull order.
		"z":      {TreeIdx: 1, PolyIdx: 0, Field: field.Base},
		mulChunk: {TreeIdx: 1, PolyIdx: 1, Field: field.Base},
		"s":      {TreeIdx: 1, PolyIdx: 2, Field: field.Base},
		"t":      {TreeIdx: 1, PolyIdx: 3, Field: field.Base},
	}
	for name, want := range wantColSlot {
		got, ok := layout.ColSlot[name]
		if !ok {
			t.Fatalf("ColSlot[%q] missing", name)
		}
		if got != want {
			t.Errorf("ColSlot[%q] = %+v, want %+v", name, got, want)
		}
	}
	if len(layout.ColSlot) != len(wantColSlot) {
		t.Errorf("ColSlot has %d entries, want %d (extras: %v)",
			len(layout.ColSlot), len(wantColSlot), extraSlotKeys(layout.ColSlot, wantColSlot))
	}

	wantAIRSlot := map[string]Slot{
		constants.QuotientChunkName("m", 0): {TreeIdx: 2, PolyIdx: 0, Field: field.Base},
	}
	for name, want := range wantAIRSlot {
		got, ok := layout.AIRChunkSlot[name]
		if !ok {
			t.Fatalf("AIRChunkSlot[%q] missing", name)
		}
		if got != want {
			t.Errorf("AIRChunkSlot[%q] = %+v, want %+v", name, got, want)
		}
	}
	if len(layout.AIRChunkSlot) != len(wantAIRSlot) {
		t.Errorf("AIRChunkSlot has %d entries, want %d",
			len(layout.AIRChunkSlot), len(wantAIRSlot))
	}

	if got := layout.NumTrees; got != 3 {
		t.Errorf("NumTrees = %d, want 3", got)
	}
	if wantTreeSize := []int{8, 8, 8}; !reflect.DeepEqual(layout.TreeSize, wantTreeSize) {
		t.Errorf("TreeSize = %v, want %v", layout.TreeSize, wantTreeSize)
	}
	if got := layout.SetupEnd - layout.SetupBegin; got != 1 {
		t.Errorf("setup section has %d trees, want 1", got)
	}
	if len(layout.TraceBegin) != 1 || len(layout.TraceEnd) != 1 {
		t.Fatalf("trace section has %d round(s), want 1", len(layout.TraceBegin))
	}
	if got := layout.TraceEnd[0] - layout.TraceBegin[0]; got != 1 {
		t.Errorf("trace round 0 has %d trees, want 1", got)
	}
	if got := layout.AIREnd - layout.AIRBegin; got != 1 {
		t.Errorf("AIR section has %d trees, want 1", got)
	}
}

func TestBuildLayoutRailRelativePolyIdx(t *testing.T) {
	baseRelation := dag.ExprToDAG(expr.Col("base_air"))
	extRelation := dag.ExprToDAG(expr.ExtCol("ext_air"))
	program := board.Program{
		Modules: map[string]board.CompiledModule{
			"base": {Name: "base", N: 8, VanishingRelation: baseRelation},
			"ext":  {Name: "ext", N: 8, VanishingRelation: extRelation},
		},
		FScolumnsDependencies: [][]board.ColumnRef{
			{
				{Name: "base_0", Module: "base", Field: field.Base},
				{Name: "ext_0", Module: "ext", Field: field.Ext},
				{Name: "base_1", Module: "base", Field: field.Base},
				{Name: "ext_1", Module: "ext", Field: field.Ext},
			},
		},
	}

	layout := BuildLayout(program, 0)

	wantColSlot := map[string]Slot{
		"base_0": {TreeIdx: 0, PolyIdx: 0, Field: field.Base},
		"base_1": {TreeIdx: 0, PolyIdx: 1, Field: field.Base},
		"ext_0":  {TreeIdx: 0, PolyIdx: 0, Field: field.Ext},
		"ext_1":  {TreeIdx: 0, PolyIdx: 1, Field: field.Ext},
	}
	for name, want := range wantColSlot {
		if got := layout.ColSlot[name]; got != want {
			t.Errorf("ColSlot[%q] = %+v, want %+v", name, got, want)
		}
	}

	wantAIRSlot := map[string]Slot{
		constants.QuotientChunkName("base", 0): {TreeIdx: 1, PolyIdx: 0, Field: field.Base},
		constants.QuotientChunkName("ext", 0):  {TreeIdx: 1, PolyIdx: 0, Field: field.Ext},
	}
	for name, want := range wantAIRSlot {
		if got := layout.AIRChunkSlot[name]; got != want {
			t.Errorf("AIRChunkSlot[%q] = %+v, want %+v", name, got, want)
		}
	}

	if wantTreeSize := []int{8, 8}; !reflect.DeepEqual(layout.TreeSize, wantTreeSize) {
		t.Errorf("TreeSize = %v, want %v", layout.TreeSize, wantTreeSize)
	}
}

func extraSlotKeys(got, want map[string]Slot) []string {
	var out []string
	for k := range got {
		if _, ok := want[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}
