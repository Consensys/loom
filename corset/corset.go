package corset

import (
	"fmt"

	"github.com/consensys/go-corset/pkg/asm"
	cmdutil "github.com/consensys/go-corset/pkg/cmd/corset/util"
	gckoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"
	"github.com/consensys/go-corset/pkg/util/field"
	"github.com/consensys/loom/constraint"
)

// TranslateModule reads a go-corset binary constraints file, lowers it to AIR
// for the Koalabear field, and returns a loom constraint.Builder containing all
// constraints from the module at the given index. N is the trace length.
func TranslateModule(binPath string, moduleIndex uint, N int) (constraint.Builder, error) {
	binf := cmdutil.ReadBinaryFile(binPath)
	stack := cmdutil.NewSchemaStack[gckoalabear.Element]().
		WithBinaryFile(binf).
		WithAssemblyConfig(asm.LoweringConfig{Field: field.KOALABEAR_16}).
		WithLayer(cmdutil.AIR_LAYER).
		Build()

	airSchema := stack.ConcreteSchema()
	if moduleIndex >= airSchema.Width() {
		return constraint.Builder{}, fmt.Errorf(
			"module index %d out of range (schema has %d modules)",
			moduleIndex, airSchema.Width())
	}

	builder := constraint.NewBuilder(N, nil)
	if err := translateConstraints(&builder, airSchema, moduleIndex); err != nil {
		return constraint.Builder{}, err
	}
	return builder, nil
}
