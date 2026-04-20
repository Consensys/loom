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
// decompositions), and returns a loom trace plus per-module N values.
func ExpandTrace(
	stack *cmdutil.SchemaStack[corsetkoalabear.Element],
	inputJSON []byte,
) (trace.Trace, map[string]int, error) {
	// Parse the input JSON into an lt.TraceFile.
	pool, modules, err := json.FromBytes(inputJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing input JSON: %w", err)
	}
	tf := lt.NewTraceFile(nil, pool, modules)

	// Propagate outputs: the ASM executor runs each function to fill in output
	// columns that were not provided in the input JSON.
	tf, propErrors := asm.Propagate(stack.BinaryFile().Schema, tf)
	if len(propErrors) > 0 {
		return nil, nil, fmt.Errorf("trace propagation: %w", propErrors[0])
	}

	// Expand the trace against the AIR schema. This fills in computed columns
	// (pseudo-inverses, type-table decompositions, etc.).
	builder := stack.TraceBuilder()
	expanded, buildErrors := builder.Build(stack.ConcreteSchema(), tf)
	if len(buildErrors) > 0 {
		return nil, nil, fmt.Errorf("trace expansion: %w", buildErrors[0])
	}

	// Compute per-module N (next power of two of each module's height).
	// Workaround: go-corset produces a root module ("") with non-zero height
	// but zero columns. Such a module can never have any constraints, so
	// including it would produce an empty board module that board.Compile
	// cannot handle. Skip modules with no columns.
	moduleN := make(map[string]int)
	for i := range expanded.Width() {
		mod := expanded.Module(i)
		if mod.Width() == 0 {
			continue
		}
		name := mod.Name().String()
		h := uint64(mod.Height())
		if h == 0 {
			continue
		}
		moduleN[name] = int(ecc.NextPowerOfTwo(h))
	}

	// Convert the go-corset trace to a flat loom trace. Each module's columns
	// are padded to that module's N with the column's declared padding value.
	result := make(trace.Trace)
	for i := range expanded.Width() {
		mod := expanded.Module(i)
		modName := mod.Name().String()
		N := uint64(moduleN[modName])

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
	// Each type table lives in its own board module with N = 2^bitwidth.
	for bw := range collectRangeConstraintBitwidths(stack.ConcreteSchema()) {
		tableSize := uint64(1) << bw
		N := int(ecc.NextPowerOfTwo(tableSize))
		colName := typeTableColName(bw)
		moduleName := typeTableModuleName(bw)
		vals := make([]koalabear.Element, N)
		for i := range tableSize {
			vals[i].SetUint64(i)
		}
		// Padding rows beyond tableSize stay zero; 0 is always a valid value
		// so it won't appear as a duplicate that breaks the lookup.
		// More importantly, the table has exactly 2^bw distinct values filling
		// rows 0..tableSize-1, with no extra padding since N == tableSize.
		result[colName] = vals
		moduleN[moduleName] = N
	}

	return result, moduleN, nil
}

// typeTableModuleName returns the board module name for a synthetic type table.
func typeTableModuleName(bitwidth uint) string {
	return fmt.Sprintf("__type_u%d", bitwidth)
}

// typeTableColName returns the column name within a synthetic type-table module.
func typeTableColName(bitwidth uint) string {
	return fmt.Sprintf("__type_u%d:V", bitwidth)
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
