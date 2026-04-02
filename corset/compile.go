package corset

import (
	"github.com/consensys/go-corset/pkg/ir"
	corsetkoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"

	cmdutil "github.com/consensys/go-corset/pkg/cmd/corset/util"
)

// CompileSchema compiles one or more zkASM source files into an AIR-level
// schema stack. The returned stack carries both the concrete AIR schema (for
// constraint translation) and a TraceBuilder (for trace expansion).
func CompileSchema(zkasmPaths ...string) *cmdutil.SchemaStack[corsetkoalabear.Element] {
	stack := cmdutil.NewSchemaStack[corsetkoalabear.Element]().
		WithAssemblyConfig(AsmConfig).
		WithOptimisationConfig(MirConfig).
		WithTraceBuilder(ir.NewTraceBuilder[corsetkoalabear.Element]().WithBatchSize(1024)).
		Read(zkasmPaths...).
		WithLayer(cmdutil.AIR_LAYER).
		Build()
	return &stack
}
