package corset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/verifier"
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

		t.Run(name, func(t *testing.T) {
			ioPath := ioForZkasm(zkasmPath)
			inputJSON, err := os.ReadFile(ioPath)
			require.NoError(t, err, "reading %s", ioPath)

			stack := CompileSchema(zkasmPath)

			tr, moduleN, err := ExpandTrace(stack, inputJSON)
			require.NoError(t, err)

			builder, err := BuilderFromSchema(stack.ConcreteSchema(), moduleN)
			require.NoError(t, err)

			program, err := board.Compile(&builder)
			require.NoError(t, err)

			pf, err := prover.Prove(tr, nil, program, prover.EmulateFS())
			require.NoError(t, err)

			require.NoError(t, verifier.Verify(nil, program, pf))
		})
		break
	}
}
