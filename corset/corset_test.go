package corset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/loom"
	"github.com/stretchr/testify/require"
)

// ioForZkasm returns the _io.json path corresponding to a .zkasm path.
func ioForZkasm(zkasmPath string) string {
	return strings.TrimSuffix(zkasmPath, ".zkasm") + "_io.json"
}

func TestProve(t *testing.T) {
	zkasmFiles, err := filepath.Glob("testdata/*.zkasm")
	require.NoError(t, err)
	require.NotEmpty(t, zkasmFiles, "no .zkasm files found in testdata/")

	for _, zkasmPath := range zkasmFiles {
		name := filepath.Base(zkasmPath)
		if name != "inc.zkasm" {
			continue
		}

		t.Run(name, func(t *testing.T) {
			ioPath := ioForZkasm(zkasmPath)
			inputJSON, err := os.ReadFile(ioPath)
			require.NoError(t, err, "reading %s", ioPath)

			stack := CompileSchema(zkasmPath)

			tr, N, err := ExpandTrace(stack, inputJSON)
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
