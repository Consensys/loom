package corset

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/trace"

	"github.com/consensys/go-corset/pkg/trace/lt"
)

// TraceFromFile reads a go-corset binary .lt trace file and returns a loom
// trace.Trace together with the trace length N. The .lt format stores
// fully-materialized, AIR-expanded column data — no witness generation or
// solving is needed on the loom side.
//
// N is chosen as the smallest power of two that is ≥ the height of the tallest
// column in the file. This N must be passed to ConstraintBuilderFromFile so that the
// constraint system and the trace are built for the same domain.
//
// Column keys follow the same "module:column" convention used by
// ConstraintBuilderFromFile (matching go-corset's register.QualifiedName). Root-module
// columns (empty module name) are stored under just their column name.
//
// Every column is padded to length N using its row-0 value, which is
// go-corset's padding row and satisfies all global constraints.
func TraceFromFile(ltPath string) (trace.Trace, int, error) {
	raw, err := os.ReadFile(ltPath)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", ltPath, err)
	}

	var tf lt.TraceFile
	if err = tf.UnmarshalBinary(raw); err != nil {
		return nil, 0, fmt.Errorf("parsing %s: %w", ltPath, err)
	}

	// First pass: find the maximum column height to determine N.
	maxHeight := 0
	for _, mod := range tf.RawModules() {
		for i := range mod.Width() {
			h := int(mod.Columns[i].Data().Len())
			if h > maxHeight {
				maxHeight = h
			}
		}
	}
	N := ecc.NextPowerOfTwo(uint64(maxHeight))

	result := make(trace.Trace)

	for _, mod := range tf.RawModules() {
		// String() returns "name" for multiplier-1 modules and "name×k" for
		// scaled modules, matching what register.QualifiedName uses in constraints.
		modName := mod.Name().String()

		for i := range mod.Width() {
			col := mod.Columns[i]

			// Construct the qualified key, mirroring register.QualifiedName.
			var key string
			if modName == "" {
				key = col.Name()
			} else {
				key = modName + ":" + col.Name()
			}

			data := col.Data()
			height := uint64(data.Len())

			// Each Koalabear value is a plain uint32 stored as a big-endian
			// word; SetUint64 converts from the canonical representation.
			vals := make([]koalabear.Element, N)
			for j := range uint(height) {
				vals[j].SetUint64(data.Get(j).Uint64())
			}
			// Rows beyond the column height are padded with the column's row-0
			// value. go-corset guarantees row 0 is its padding row, which
			// satisfies all global vanishing constraints by construction.
			var pad koalabear.Element
			if height > 0 {
				pad = vals[0]
			}
			for j := height; j < N; j++ {
				vals[j].Set(&pad)
			}

			result[key] = vals
		}
	}

	return result, int(N), nil
}
