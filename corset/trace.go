package corset

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/trace"

	"github.com/consensys/go-corset/pkg/schema"
	"github.com/consensys/go-corset/pkg/schema/register"
	"github.com/consensys/go-corset/pkg/trace/lt"
	corsetkoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"
)

// TraceFromFile reads a go-corset binary .lt trace file and returns a loom
// trace.Trace together with the trace length N. The .lt format stores
// fully-materialized, AIR-expanded column data — no witness generation or
// solving is needed on the loom side.
//
// airSchema must be the AIR-level schema produced by AirSchemaFromFile for the
// matching .bin file. It supplies the schema-declared padding value for each
// column, which is used to fill the N-extension rows so that all global
// vanishing constraints remain satisfied.
//
// N is chosen as the smallest power of two ≥ the tallest column in the file.
// Pass this N to ConstraintBuilderFromSchema so both sides share the same domain.
//
// Column keys follow the "module:column" convention used by
// ConstraintBuilderFromSchema (matching go-corset's register.QualifiedName).
// Root-module columns use just their column name.
func TraceFromFile(ltPath string, airSchema schema.AnySchema[corsetkoalabear.Element]) (trace.Trace, int, error) {
	raw, err := os.ReadFile(ltPath)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", ltPath, err)
	}

	var tf lt.TraceFile
	if err = tf.UnmarshalBinary(raw); err != nil {
		return nil, 0, fmt.Errorf("parsing %s: %w", ltPath, err)
	}

	// Build a map from (module name → column name → schema-declared padding value).
	padMap := paddingMap(airSchema)

	// First pass: determine N = nextPow2(max column height).
	var maxHeight uint64
	for _, mod := range tf.RawModules() {
		for i := range mod.Width() {
			if h := uint64(mod.Columns[i].Data().Len()); h > maxHeight {
				maxHeight = h
			}
		}
	}
	N := ecc.NextPowerOfTwo(maxHeight)

	result := make(trace.Trace)

	for _, mod := range tf.RawModules() {
		modName := mod.Name().String()
		modPads := padMap[modName] // nil map if module absent from schema

		for i := range mod.Width() {
			col := mod.Columns[i]
			var key string
			if modName == "" {
				key = col.Name()
			} else {
				key = modName + ":" + col.Name()
			}

			data := col.Data()
			height := uint64(data.Len())

			vals := make([]koalabear.Element, N)
			for j := range uint(height) {
				vals[j].SetUint64(data.Get(j).Uint64())
			}
			pad := modPads[col.Name()] // zero element if column absent from schema
			for j := height; j < N; j++ {
				vals[j].Set(&pad)
			}

			result[key] = vals
		}
	}

	return result, int(N), nil
}

// paddingMap returns a two-level map (module name → column name →
// schema-declared padding value) for every module in the AIR schema.
func paddingMap(airSchema schema.AnySchema[corsetkoalabear.Element]) map[string]map[string]koalabear.Element {
	result := make(map[string]map[string]koalabear.Element, airSchema.Width())
	for i := range airSchema.Width() {
		mod := airSchema.Module(i)
		colPads := make(map[string]koalabear.Element, mod.Width())
		for j := range mod.Width() {
			reg := mod.Register(register.NewId(j))
			var el koalabear.Element
			el.SetBigInt(reg.Padding())
			colPads[reg.Name()] = el
		}
		result[mod.Name().String()] = colPads
	}
	return result
}
