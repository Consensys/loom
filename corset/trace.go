package corset

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/trace"

	"github.com/consensys/go-corset/pkg/asm"
	"github.com/consensys/go-corset/pkg/ir/air"
	"github.com/consensys/go-corset/pkg/schema"
	corsetkoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"

	"github.com/consensys/go-corset/pkg/trace/json"
	"github.com/consensys/go-corset/pkg/trace/lt"

	cmdutil "github.com/consensys/go-corset/pkg/cmd/corset/util"
)

// ExpandTrace takes a compiled schema stack and raw input JSON (mapping
// qualified column names to value arrays), propagates outputs via the ASM
// executor, expands computed columns (pseudo-inverses, type-table
// decompositions), and returns a loom trace padded to the next power of two.
func ExpandTrace(
	stack *cmdutil.SchemaStack[corsetkoalabear.Element],
	inputJSON []byte,
) (trace.Trace, int, error) {
	// Parse the input JSON into an lt.TraceFile.
	pool, modules, err := json.FromBytes(inputJSON)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing input JSON: %w", err)
	}
	tf := lt.NewTraceFile(nil, pool, modules)

	// Propagate outputs: the ASM executor runs each function to fill in output
	// columns that were not provided in the input JSON.
	tf, propErrors := asm.Propagate(stack.BinaryFile().Schema, tf)
	if len(propErrors) > 0 {
		return nil, 0, fmt.Errorf("trace propagation: %w", propErrors[0])
	}

	// Expand the trace against the AIR schema. This fills in computed columns
	// (pseudo-inverses, type-table decompositions, etc.).
	builder := stack.TraceBuilder()
	expanded, buildErrors := builder.Build(stack.ConcreteSchema(), tf)
	if len(buildErrors) > 0 {
		return nil, 0, fmt.Errorf("trace expansion: %w", buildErrors[0])
	}

	// Determine N = next power of two large enough to hold all module data and
	// any synthetic type-table columns for range constraints.
	typeTables := collectRangeConstraintBitwidths(stack.ConcreteSchema())
	var maxHeight uint64
	for i := range expanded.Width() {
		maxHeight = max(maxHeight, uint64(expanded.Module(i).Height()))
	}
	for bw := range typeTables {
		maxHeight = max(maxHeight, uint64(1)<<bw)
	}
	N := ecc.NextPowerOfTwo(maxHeight)

	// Convert the go-corset trace to a flat loom trace, padding each column to N
	// with its declared padding value.
	result := make(trace.Trace)
	for i := range expanded.Width() {
		mod := expanded.Module(i)
		modName := mod.Name().String()

		for j := range mod.Width() {
			col := mod.Column(j)
			name := col.Name()

			var key string
			if modName == "" {
				key = name
			} else {
				key = modName + ":" + name
			}

			data := col.Data()
			height := uint64(data.Len())

			vals := make([]koalabear.Element, N)
			for k := range int(height) {
				vals[k] = toKoalabear(data.Get(uint(k)))
			}
			pad := toKoalabear(col.Padding())
			for k := height; k < N; k++ {
				vals[k].Set(&pad)
			}

			result[key] = vals
		}
	}

	// Inject synthetic type-table columns for AIR-level range constraints.
	for bw := range typeTables {
		tableSize := uint64(1) << bw
		vals := make([]koalabear.Element, N)
		for i := range tableSize {
			vals[i].SetUint64(i)
		}
		// Remaining entries are zero (0 is always in [0, 2^n)).
		result[TypeTableColName(bw)] = vals
	}

	return result, int(N), nil
}

// collectRangeConstraintBitwidths scans the AIR schema for range constraints
// and returns the set of unique bitwidths found.
func collectRangeConstraintBitwidths(airSchema schema.AnySchema[corsetkoalabear.Element]) map[uint]bool {
	bitwidths := make(map[uint]bool)
	for _, c := range airSchema.Constraints().Collect() {
		if rc, ok := c.(air.RangeConstraint[corsetkoalabear.Element]); ok {
			inner := rc.Unwrap()
			for _, bw := range inner.Bitwidths {
				bitwidths[bw] = true
			}
		}
	}
	return bitwidths
}
