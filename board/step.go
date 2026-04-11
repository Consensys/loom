package board

import (
	"fmt"
	"sync"

	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Step func([]expr.Expr, string, trace.Trace, *proof.Proof, *Program, *sync.Mutex, StepContext) error

type ProverStep struct {
	Ctx  StepContext
	Ins  []expr.Expr
	Out  string
	Step Step
}

type StepContext any

func (ps *ProverStep) Execute(trace trace.Trace, proof *proof.Proof, prog *Program, mu *sync.Mutex, ctx StepContext) error {
	step := ps.Step
	return step(ps.Ins, ps.Out, trace, proof, prog, mu, ctx)
}

func NewProverStep(ins []expr.Expr, out string, step Step) ProverStep {
	return ProverStep{
		Ins:  ins,
		Out:  out,
		Step: step,
	}
}

type PickValueCtx struct {
	Pos int // position of the value to pick in a column
}

func PickValueStep(ins []expr.Expr, out string, t trace.Trace, _ *proof.Proof, _ *Program, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(PickValueCtx)
	if !ok {
		return fmt.Errorf("[PickLocalValueStep] wrong context type")
	}

	C := ins[0]
	res, err := poly.PickIthValue(t, C, _ctx.Pos, mu)
	if err != nil {
		return err
	}
	poly := poly.Polynomial{res}
	if err = trace.RegisterColumn(t, out, poly); err != nil {
		panic(fmt.Sprintf("[PickLocalValueStep] register multiplicity column %s: %v", out, err))
	}

	return nil
}

// _CountMultiplicityStep computes the running sum M/E where
// ins[0] = S (values), ins[1] = T (table), ins[2] = Sel (selector)
func CountMultiplicityStep(ins []expr.Expr, out string, t trace.Trace, _ *proof.Proof, _ *Program, mu *sync.Mutex, _ StepContext) error {

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

// _LogUpStep computes the running sum M/E where
// ins[0] = E, ins[1] = M
func LogUpStep(ins []expr.Expr, out string, t trace.Trace, _ *proof.Proof, prog *Program, mu *sync.Mutex, _ StepContext) error {

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

// _GrandProductStep computes the running product N/D where
// ins[0] = N, ins[1] = D
func GrandProductStep(ins []expr.Expr, out string, t trace.Trace, _ *proof.Proof, prog *Program, mu *sync.Mutex, _ StepContext) error {

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
