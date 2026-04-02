package corset

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/trace"
	"github.com/stretchr/testify/require"
)

// TestLookupDuplicateTarget is a minimal reproduction of a lookup failure when
// the target column T contains duplicate values. The lookup S ⊆ T should hold
// trivially (S == T), but Verify returns "algebraic relation does not hold".
func TestLookupDuplicateTarget(t *testing.T) {
	N := 2

	S := make([]koalabear.Element, N)
	T := make([]koalabear.Element, N)
	T[1].SetUint64(1)
	// S = [0, 0], T = [0, 1]

	tr := trace.Trace{"S": S, "T": T}
	builder := constraint.NewBuilder(N, nil)
	require.NoError(t, arguments.LookupTuple(&builder,
		[]expr.Expr{expr.Col("S")},
		[]expr.Expr{expr.Col("T")},
	))

	program := builder.Compile(nil)
	pf, err := loom.Prove(program, tr, nil, 1)
	require.NoError(t, err)
	require.NoError(t, loom.Verify(program, &pf, nil, 1))
}
