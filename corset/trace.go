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

// TraceFromFile reads a fully expanded go-corset .lt trace file and returns a
// loom trace padded to the next power of two. The .lt must already contain all
// columns in their final AIR form (post-split, post-expansion).
func TraceFromFile(ltPath string, airSchema schema.AnySchema[corsetkoalabear.Element]) (trace.Trace, int, error) {
	raw, err := os.ReadFile(ltPath)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", ltPath, err)
	}

	var tf lt.TraceFile
	if err = tf.UnmarshalBinary(raw); err != nil {
		return nil, 0, fmt.Errorf("parsing %s: %w", ltPath, err)
	}

	// N = next power of two ≥ tallest column.
	var maxHeight uint64
	for _, mod := range tf.RawModules() {
		for _, col := range mod.Columns {
			maxHeight = max(maxHeight, uint64(col.Data().Len()))
		}
	}
	N := ecc.NextPowerOfTwo(maxHeight)

	// Build padding map from schema.
	padMap := paddingMap(airSchema)

	// Convert to loom trace, padding each column to N.
	result := make(trace.Trace)
	for _, mod := range tf.RawModules() {
		modName := mod.Name().String()
		modPads := padMap[modName]

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
			for j := range int(height) {
				vals[j].SetUint64(data.Get(uint(j)).Uint64())
			}
			pad := modPads[col.Name()]
			for j := height; j < N; j++ {
				vals[j].Set(&pad)
			}

			result[key] = vals
		}
	}

	return result, int(N), nil
}

// paddingMap returns module name → column name → schema-declared padding value.
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
