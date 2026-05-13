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

package board

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Step func([]expr.Expr, []string, trace.Trace, *Program, *proof.Proof, *sync.Mutex, StepContext) error

type StepContext any

type ProverStep struct {
	Ctx  StepContext
	Ins  []expr.Expr
	Outs []string
	Step Step
}

func (ps *ProverStep) Execute(trace trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex) error {
	step := ps.Step
	return step(ps.Ins, ps.Outs, trace, prog, proof, mu, ps.Ctx)
}

func NewProverStep(ins []expr.Expr, outs []string, step Step, ctx StepContext) ProverStep {
	return ProverStep{
		Ins:  ins,
		Outs: outs,
		Step: step,
		Ctx:  ctx,
	}
}

type MakeEntriesPublicCtx struct {
	Idx []int // indices of the entries to make public
	N   int
}

func MakeEntriesPublicStep(ins []expr.Expr, outs []string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(MakeEntriesPublicCtx)
	if !ok {
		return fmt.Errorf("[MakeEntriesPublicStep] wrong context type")
	}

	out := outs[0]
	C := ins[0]
	res, err := poly.BuildPointwiseEvaluation(t, C, mu)
	if err != nil {
		return err
	}

	var publicColumnInfo PublicInput
	publicColumnInfo.N = _ctx.N
	publicColumnInfo.Entries = make([]PublicEntry, len(_ctx.Idx))
	for _, i := range _ctx.Idx {
		publicColumnInfo.Entries[i].Idx = i
		publicColumnInfo.Entries[i].Value.Set(&res[i])
	}
	proof.PublicColumns[out] = publicColumnInfo

	// The constraint L_pos*(E - Public(out))=0 requires Public(out) to be the sparse
	// polynomial with E[pos] at index pos and 0 elsewhere, matching what computePublicColumns
	// reconstructs on the verifier side via Lagrange interpolation.
	sparseCol := make([]koalabear.Element, _ctx.N)
	for _, i := range _ctx.Idx {
		sparseCol[i].Set(&res[i])
	}
	if err := trace.RegisterColumn(t, out, sparseCol); err != nil {
		panic(fmt.Sprintf("[MakeIthValuePublicStep] register public column %s: %v", out, err))
	}

	return nil
}

type FSCtx struct{}

func FSStep(ins []expr.Expr, outs []string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	return nil
}

type MakeRelativeIthValuePublicCtx struct {
	Module string
	Pos    int // relative position of the value to pick in a column -> the position module.N - 1 - Pos. It allows to refer to N, so N can be modified
}

// ExposeRelativeIthEntryStep adds a constraint Lagrange_pos * (expr - expr[pos]), and stores expr[pos] in the proof so the verifier has access to it
func ExposeRelativeIthEntryStep(ins []expr.Expr, outs []string, t trace.Trace, pg *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(MakeRelativeIthValuePublicCtx)
	if !ok {
		return fmt.Errorf("[PickLocalValueStep] wrong context type")
	}

	out := outs[0]
	C := ins[0]
	res, err := poly.BuildPointwiseEvaluation(t, C, mu)
	if err != nil {
		return err
	}

	var publicColumnInfo PublicInput
	m := pg.Modules[_ctx.Module]
	publicColumnInfo.N = m.N
	publicColumnInfo.Entries = make([]PublicEntry, 1)
	publicColumnInfo.Entries[0].Idx = m.N - 1 - _ctx.Pos
	publicColumnInfo.Entries[0].Value = res[m.N-1-_ctx.Pos]
	proof.PublicColumns[out] = publicColumnInfo

	// The constraint L_pos*(E - Public(out))=0 requires Public(out) to be the sparse
	// polynomial with E[m.N-1-_ctx.Pos] at index m.N-1-_ctx.Pos and 0 elsewhere, matching what computePublicColumns
	// reconstructs on the verifier side via Lagrange interpolation.
	sparseCol := make([]koalabear.Element, m.N)
	sparseCol[m.N-1-_ctx.Pos].Set(&res[m.N-1-_ctx.Pos])
	if err := trace.RegisterColumn(t, out, sparseCol); err != nil {
		panic(fmt.Sprintf("[MakeIthValuePublicStep] register public column %s: %v", out, err))
	}

	return nil
}

type ExposeIthEntryCtx struct {
	Module string
	Pos    int // position of the value to pick in a column
}

// MakeIthValuePublicStep adds a constraint Lagrange_pos * (expr - expr[pos]), and stores expr[pos] in the proof so the verifier has access to it
func MakeIthValuePublicStep(ins []expr.Expr, outs []string, t trace.Trace, pg *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(ExposeIthEntryCtx)
	if !ok {
		return fmt.Errorf("[PickLocalValueStep] wrong context type")
	}

	out := outs[0]
	C := ins[0]
	res, err := poly.BuildPointwiseEvaluation(t, C, mu)
	if err != nil {
		return err
	}

	var publicColumnInfo PublicInput
	m := pg.Modules[_ctx.Module]
	publicColumnInfo.N = m.N
	publicColumnInfo.Entries = make([]PublicEntry, 1)
	publicColumnInfo.Entries[0].Idx = _ctx.Pos
	publicColumnInfo.Entries[0].Value = res[_ctx.Pos]
	proof.PublicColumns[out] = publicColumnInfo

	// The constraint L_pos*(E - Public(out))=0 requires Public(out) to be the sparse
	// polynomial with E[pos] at index pos and 0 elsewhere, matching what computePublicColumns
	// reconstructs on the verifier side via Lagrange interpolation.
	sparseCol := make([]koalabear.Element, m.N)
	sparseCol[_ctx.Pos].Set(&res[_ctx.Pos])
	if err := trace.RegisterColumn(t, out, sparseCol); err != nil {
		panic(fmt.Sprintf("[MakeIthValuePublicStep] register public column %s: %v", out, err))
	}

	return nil
}

type CMCtx struct {
	NbSources, NbTargets int
}

// CountUnionMultiplicityStep computes the running sum M/E where
// ins[0] = S (values), ins[1] = T (table), ins[2] = Sel (selector)
func CountMultiplicityStep(ins []expr.Expr, outs []string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(CMCtx)
	if !ok {
		return fmt.Errorf("[CountUnionMultiplicityStep] wrong context type")
	}

	nbS := _ctx.NbSources
	nbT := _ctx.NbTargets
	S := make([]expr.Expr, nbS)
	T := make([]expr.Expr, nbT)
	copy(S, ins[:nbS])
	copy(T, ins[nbS:nbT+nbS])
	res, err := poly.BuildMultiplicityPolynomials(t, S, T, mu)
	if err != nil {
		return err
	}

	for i := 0; i < nbT; i++ {
		if err := trace.RegisterColumn(t, outs[i], res[i]); err != nil {
			panic(fmt.Sprintf("[CountUnionMultiplicityStep] register multiplicity column %s: %v", outs[i], err))
		}
	}

	return nil
}

type CMWCtx struct {
	NbSources, NbTargets int
}

// CountWeightedMultiplicityStep computes the running sum M/E where
// ins: [ selS || S || T]
func CountWeightedMultiplicityStep(ins []expr.Expr, outs []string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(CMWCtx)
	if !ok {
		return fmt.Errorf("[CountUnionMultiplicityStep] wrong context type")
	}

	nbS := _ctx.NbSources
	nbT := _ctx.NbTargets
	S := make([]expr.Expr, nbS)
	selS := make([]expr.Expr, nbS)
	T := make([]expr.Expr, nbT)
	copy(selS, ins[:nbS])
	copy(S, ins[nbS:nbS+nbS])
	copy(T, ins[nbS+nbS:nbS+nbS+nbT])
	res, err := poly.BuildWeightedMultiplicityPolynomial(t, selS, S, T, mu)
	if err != nil {
		return err
	}

	for i := 0; i < nbT; i++ {
		if err := trace.RegisterColumn(t, outs[i], res[i]); err != nil {
			panic(fmt.Sprintf("[CountUnionWeightedMultiplicityStep] register multiplicity column %s: %v", outs[i], err))
		}
	}

	return nil
}

type LogUpCtx struct{}

// _LogUpStep computes the running sum M/E where
// ins[0] = E, ins[1] = M
func LogUpStep(ins []expr.Expr, outs []string, t trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex, _ StepContext) error {

	out := outs[0]
	E := ins[0]
	M := ins[1]

	res, err := poly.BuildLogup(t, E, M, mu)
	if err != nil {
		return err
	}
	if err := trace.RegisterColumn(t, out, res); err != nil {
		panic(fmt.Sprintf("[_LogUpStep] register logup column %s: %v", out, err))
	}

	return nil
}

type GPCtx struct{}

// _GrandProductStep computes the running product N/D where
// ins[0] = N, ins[1] = D
func GrandProductStep(ins []expr.Expr, outs []string, t trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex, _ StepContext) error {

	out := outs[0]
	N := ins[0]
	D := ins[1]

	res, err := poly.BuildGrandProduct(t, N, D, mu)
	if err != nil {
		return err
	}
	if err := trace.RegisterColumn(t, out, res); err != nil {
		panic(fmt.Sprintf("[_GrandProductStep] register grand product column %s: %v", out, err))
	}

	return nil
}
