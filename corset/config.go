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

	// MirConfig controls MIR-to-AIR lowering. MaxRangeConstraint=11 ensures
	// go-corset only decomposes types > 11 bits (u16 → u8+u8, byte-aligned).
	// Smaller types become AIR-level range constraints, which we translate to
	// lookups against synthetic type-table board modules.
	MirConfig = mir.OptimisationConfig{
		InverseEliminiationLevel: 1,
		MaxRangeConstraint:       11,
		ShiftNormalisation:       true,
	}
)
