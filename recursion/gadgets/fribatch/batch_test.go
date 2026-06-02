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

package fribatch_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/fribatch"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randomExt(t *testing.T) ext.E6 {
	t.Helper()
	var v ext.E6
	if _, err := v.B0.A0.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B0.A1.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B1.A0.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B1.A1.SetRandom(); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestBatchGadget exercises both selector branches (sel=0 picks LeafP,
// sel=1 picks LeafQ) and a mix of rows in one module.
func TestBatchGadget(t *testing.T) {
	batches := []fribatch.Batch{
		{Expected: randomExt(t), Gamma: randomExt(t), LeafP: randomExt(t), LeafQ: randomExt(t), Sel: 0},
		{Expected: randomExt(t), Gamma: randomExt(t), LeafP: randomExt(t), LeafQ: randomExt(t), Sel: 1},
		{Expected: randomExt(t), Gamma: randomExt(t), LeafP: randomExt(t), LeafQ: randomExt(t), Sel: 0},
		{Expected: randomExt(t), Gamma: randomExt(t), LeafP: randomExt(t), LeafQ: randomExt(t), Sel: 1},
	}

	builder := board.NewBuilder()
	cn := fribatch.BuildModule(&builder, "batch", len(batches))
	cols := fribatch.GenerateTrace(cn, len(batches), batches)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestBatchGadgetRejectsSelectorFlip flips sel on the first row and confirms
// the proof breaks (the unfolded "next" value no longer matches with the
// other branch).
func TestBatchGadgetRejectsSelectorFlip(t *testing.T) {
	b := fribatch.Batch{Expected: randomExt(t), Gamma: randomExt(t), LeafP: randomExt(t), LeafQ: randomExt(t), Sel: 0}

	builder := board.NewBuilder()
	cn := fribatch.BuildModule(&builder, "batch_flip", 1)
	cols := fribatch.GenerateTrace(cn, 1, []fribatch.Batch{b})

	// Flip sel from 0 to 1. The trace's "next" was computed assuming sel=0
	// (LeafP), so the constraint now demands a value computed from LeafQ —
	// which the trace doesn't hold.
	selCol := cols[cn.Sel]
	selCol[0].SetOne()

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestBatchGadgetRejectsNonBinarySelector confirms that a non-binary sel is
// caught by the sel*(1-sel)=0 constraint.
func TestBatchGadgetRejectsNonBinarySelector(t *testing.T) {
	b := fribatch.Batch{Expected: randomExt(t), Gamma: randomExt(t), LeafP: randomExt(t), LeafQ: randomExt(t), Sel: 0}

	builder := board.NewBuilder()
	cn := fribatch.BuildModule(&builder, "batch_nonbin", 1)
	cols := fribatch.GenerateTrace(cn, 1, []fribatch.Batch{b})

	// Set sel = 2 (non-binary).
	cols[cn.Sel][0].SetUint64(2)
	// Recompute next so the linear constraint still holds — leaving sel = 2 as
	// the only violation. We also need to recompute next given sel = 2 to
	// isolate the binary-check constraint:
	//   leaf = LeafP + 2*(LeafQ - LeafP) = 2*LeafQ - LeafP
	//   next = Expected + gamma * (2*LeafQ - LeafP)
	var leaf ext.E6
	leaf.Sub(&b.LeafQ, &b.LeafP)
	var two koalabear.Element
	two.SetUint64(2)
	leaf.MulByElement(&leaf, &two)
	leaf.Add(&leaf, &b.LeafP) // = LeafP + 2*(LeafQ-LeafP) = 2*LeafQ - LeafP
	var term, next ext.E6
	term.Mul(&b.Gamma, &leaf)
	next.Add(&b.Expected, &term)

	nLimbs := [4]koalabear.Element{next.B0.A0, next.B1.A0, next.B0.A1, next.B1.A1}
	for i := 0; i < 4; i++ {
		cols[cn.Next[i]][0].Set(&nLimbs[i])
	}

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
