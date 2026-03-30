package corset

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/loom"
	"github.com/stretchr/testify/require"
)

// binForLT returns the .bin path corresponding to a .lt path.
func binForLT(ltPath string) string {
	return strings.TrimSuffix(ltPath, ".lt") + ".bin"
}

func TestConstraintBuilderFromFile(t *testing.T) {
	bins, err := filepath.Glob("testdata/*.bin")
	require.NoError(t, err)
	require.NotEmpty(t, bins, "no .bin files found in testdata/")

	for _, path := range bins {
		t.Run(filepath.Base(path), func(t *testing.T) {
			_, err := ConstraintBuilderFromFile(path, 8)
			require.NoError(t, err)
		})
	}
}

func TestTraceFromFile(t *testing.T) {
	lts, err := filepath.Glob("testdata/*.lt")
	require.NoError(t, err)
	require.NotEmpty(t, lts, "no .lt files found in testdata/")

	for _, path := range lts {
		t.Run(filepath.Base(path), func(t *testing.T) {
			stack := airSchemaFromFile(binForLT(path))
			tr, _, err := TraceFromFile(path, stack.ConcreteSchema())
			require.NoError(t, err)
			require.NotEmpty(t, tr, "trace is empty")

			for key, col := range tr {
				require.NotEmpty(t, key, "empty column key")
				require.NotContains(t, key, ".", "column key %q uses dot separator; want colon", key)
				require.NotEmpty(t, col, "column %q is empty", key)
			}
		})
	}
}

func TestProve(t *testing.T) {
	lts, err := filepath.Glob("testdata/*.lt")
	require.NoError(t, err)
	require.NotEmpty(t, lts, "no .lt files found in testdata/")

	for _, ltPath := range lts {
		t.Run(filepath.Base(ltPath), func(t *testing.T) {
			stack := airSchemaFromFile(binForLT(ltPath))

			tr, N, err := TraceFromFile(ltPath, stack.ConcreteSchema())
			require.NoError(t, err)

			builder, err := ConstraintBuilderFromSchema(stack.ConcreteSchema(), N)
			require.NoError(t, err)

			program := builder.Compile(nil)

			pf, err := loom.Prove(program, tr, nil, 1)
			require.NoError(t, err)

			require.NoError(t, loom.Verify(program, &pf, nil, 1))
		})
	}
}
