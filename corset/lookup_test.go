package corset

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/go-corset/pkg/ir/air"
	corsetkoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"
	"github.com/consensys/loom"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/trace"
	"github.com/stretchr/testify/require"
)

// TestAddTypeTableLookup exercises AddTypeTableLookup with a hand-crafted trace.
func TestAddTypeTableLookup(t *testing.T) {
	const bitwidth = 2
	N := 4

	src := make([]koalabear.Element, N)
	src[0].SetUint64(0)
	src[1].SetUint64(3)
	src[2].SetUint64(1)
	src[3].SetUint64(2)

	table := make([]koalabear.Element, N)
	for i := range N {
		table[i].SetUint64(uint64(i))
	}

	tr := trace.Trace{
		"x":                        src,
		TypeTableColName(bitwidth): table,
	}

	builder := constraint.NewBuilder(N, nil)
	require.NoError(t, AddTypeTableLookup(&builder, "x", bitwidth))

	program := builder.Compile(nil)
	pf, err := loom.Prove(program, tr, nil, 1)
	require.NoError(t, err)
	require.NoError(t, loom.Verify(program, &pf, nil, 1))
}

// TestTranslateSingleLookup calls translateLookup on the first go-corset lookup
// from fncall_01.zkasm (the simplest typed program) and proves it with the real
// expanded trace.
func TestTranslateSingleLookup(t *testing.T) {
	stack := CompileSchema("testdata/fncall_01.zkasm")
	tr, N, err := ExpandTrace(stack, []byte(`{"id.arg": [7], "id.res": [7]}`))
	require.NoError(t, err)

	schema := stack.ConcreteSchema()
	builder := constraint.NewBuilder(N, nil)

	for _, c := range schema.Constraints().Collect() {
		lc, ok := c.(air.LookupConstraint[corsetkoalabear.Element])
		if !ok {
			continue
		}
		require.NoError(t, translateLookup(&builder, schema, lc))
		break
	}

	program := builder.Compile(nil)
	pf, err := loom.Prove(program, tr, nil, 1)
	require.NoError(t, err)
	require.NoError(t, loom.Verify(program, &pf, nil, 1))
}
