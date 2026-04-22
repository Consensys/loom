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

type Step func([]expr.Expr, string, trace.Trace, *Program, *proof.Proof, *sync.Mutex, StepContext) error

type StepContext any

type ProverStep struct {
	Ctx  StepContext
	Ins  []expr.Expr
	Out  string
	Step Step
}

func (ps *ProverStep) Execute(trace trace.Trace, prog *Program, proof *proof.Proof, mu *sync.Mutex) error {
	step := ps.Step
	return step(ps.Ins, ps.Out, trace, prog, proof, mu, ps.Ctx)
}

func NewProverStep(ins []expr.Expr, out string, step Step, ctx StepContext) ProverStep {
	return ProverStep{
		Ins:  ins,
		Out:  out,
		Step: step,
		Ctx:  ctx,
	}
}

type MakeEntriesPublicCtx struct {
	Idx []int // indices of the entries to make public
	N   int
}

func MakeEntriesPublicStep(ins []expr.Expr, out string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(MakeEntriesPublicCtx)
	if !ok {
		return fmt.Errorf("[MakeEntriesPublicStep] wrong context type")
	}

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

	return nil
}

type FSCtx struct{}

func FSStep(ins []expr.Expr, out string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	return nil
}

type MakeIthValuePublicCtx struct {
	N   int // size of the module in which the column lives
	Pos int // position of the value to pick in a column
}

// MakeIthValuePublicStep adds a constraint Lagrange_pos * (expr - expr[pos]), and stores expr[pos] in the proof so the verifier has access to it
func MakeIthValuePublicStep(ins []expr.Expr, out string, t trace.Trace, _ *Program, proof *proof.Proof, mu *sync.Mutex, ctx StepContext) error {

	_ctx, ok := ctx.(MakeIthValuePublicCtx)
	if !ok {
		return fmt.Errorf("[PickLocalValueStep] wrong context type")
	}

	C := ins[0]
	res, err := poly.BuildPointwiseEvaluation(t, C, mu)
	if err != nil {
		return err
	}

	var publicColumnInfo PublicInput
	publicColumnInfo.N = _ctx.N
	publicColumnInfo.Entries = make([]PublicEntry, 1)
	publicColumnInfo.Entries[0].Idx = _ctx.Pos
	publicColumnInfo.Entries[0].Value = res[_ctx.Pos]
	proof.PublicColumns[out] = publicColumnInfo

	// The constraint L_pos*(E - Public(out))=0 requires Public(out) to be the sparse
	// polynomial with E[pos] at index pos and 0 elsewhere, matching what computePublicColumns
	// reconstructs on the verifier side via Lagrange interpolation.
	sparseCol := make([]koalabear.Element, _ctx.N)
	sparseCol[_ctx.Pos].Set(&res[_ctx.Pos])
	if err := trace.RegisterColumn(t, out, sparseCol); err != nil {
		panic(fmt.Sprintf("[MakeIthValuePublicStep] register public column %s: %v", out, err))
	}

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
