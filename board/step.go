package board

import (
	"fmt"
	"sync"

	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Step func([]expr.Expr, string, trace.Trace, *Program, *proof.Proof, *sync.Mutex, StepContext) error

type ProverStep struct {
	Ctx  StepContext
	Ins  []expr.Expr
	Out  string
	Step Step
}

type StepContext any

func (ps *ProverStep) Execute(trace trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {
	step := ps.Step
	return step(ps.Ins, ps.Out, trace, prog, proof, mu, ctx)
}

func NewProverStep(ins []expr.Expr, out string, step Step, ctx StepContext) ProverStep {
	return ProverStep{
		Ins:  ins,
		Out:  out,
		Step: step,
		Ctx:  ctx,
	}
}

type FSCtx struct{}

func FSStep(ins []expr.Expr, out string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {
	return nil
}

type PickValueCtx struct {
	Pos int // position of the value to pick in a column
}

// PickValueStep adds a constraint Lagrange_pos * (expr - expr[pos]), and stores expr[pos] in the proof so the verifier has access to it
func PickValueStep(ins []expr.Expr, _ string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(PickValueCtx)
	if !ok {
		return fmt.Errorf("[PickLocalValueStep] wrong context type")
	}

	C := ins[0]
	res, err := poly.PickIthValue(t, C, _ctx.Pos, mu)
	if err != nil {
		return err
	}

	var pe PublicEntry
	pe.Idx = _ctx.Pos
	pe.Value = res

	colName := C.String()
	publicColumnInfo := make([]PublicEntry, 0, 1)
	_, ok = proof.ExtractedValues[colName]
	if ok {
		publicColumnInfo = proof.ExtractedValues[colName]
	}
	publicColumnInfo = append(publicColumnInfo, pe)
	proof.ExtractedValues[colName] = publicColumnInfo

	return nil
}

type CMCtx struct{}

// _CountMultiplicityStep computes the running sum M/E where
// ins[0] = S (values), ins[1] = T (table), ins[2] = Sel (selector)
func CountMultiplicityStep(ins []expr.Expr, out string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, _ StepContext) error {

	S := ins[0]
	T := ins[1]
	res, err := poly.BuildMultiplicityPolynomial(t, S, T, mu)
	if err != nil {
		return err
	}
	if err := trace.RegisterColumn(t, out, res); err != nil {
		panic(fmt.Sprintf("[_CountMultiplicityStep] register multiplicity column %s: %v", out, err))
	}

	return nil
}

type LogUpCtx struct{}

// _LogUpStep computes the running sum M/E where
// ins[0] = E, ins[1] = M
func LogUpStep(ins []expr.Expr, out string, t trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex, _ StepContext) error {

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
func GrandProductStep(ins []expr.Expr, out string, t trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex, _ StepContext) error {

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
