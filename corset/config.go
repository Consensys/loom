package corset

import (
	"github.com/consensys/go-corset/pkg/asm"
	"github.com/consensys/go-corset/pkg/ir/mir"
	"github.com/consensys/go-corset/pkg/util/field"
)

var (
	// FieldConfig is the field configuration used throughout the corset package.
	FieldConfig = field.KOALABEAR_16

	// AsmConfig controls assembly-level lowering (vectorization, field selection).
	AsmConfig = asm.LoweringConfig{
		Field:     FieldConfig,
		Vectorize: true,
	}

	// MirConfig controls MIR-to-AIR lowering. An empty config lets go-corset
	// decompose all range constraints natively down to u1 (binary) checks.
	MirConfig = mir.OptimisationConfig{}
)
