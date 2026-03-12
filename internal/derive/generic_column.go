package derive

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// BuildContext context for build a custom column (something public,
// like a filter)
type BuilderContext struct {
	Col []koalabear.Element
}

func NewBuilderContext(col []koalabear.Element) BuilderContext {
	return BuilderContext{Col: col}
}

func (bc BuilderContext) String() string {
	return "new_public_col"
}

func (bc BuilderContext) Key() string {
	return ""
}

func (bc BuilderContext) GetID() StepKind {
	return REGISTER_COL
}

// _ReRegisterColumngisterColumn prover action for registering a public helper column, like a filter
func RegisterColumn(trace trace.Trace, _ *Proof, mu *sync.Mutex, _ []expr.Expr, output []string, ctx StepContext) error {
	mu.Lock()
	defer mu.Unlock()
	if len(output) != 1 {
		return fmt.Errorf("len(output)=%d, expected %d", len(output), 1)
	}
	if _, ok := trace[output[0]]; ok {
		return fmt.Errorf("column %s already registered in the trace", output[0])
	}
	_ctx, ok := ctx.(BuilderContext)
	if !ok {
		return fmt.Errorf("ctx is not BuilderContext")
	}
	trace[output[0]] = _ctx.Col
	return nil
}
