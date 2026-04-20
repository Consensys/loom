package corset

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/go-corset/pkg/ir/air"
	"github.com/consensys/go-corset/pkg/schema"
	corsetkoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

// BuilderFromSchema builds a loom board.Builder from a preloaded AIR schema.
// moduleN maps module names to their padded trace length (next power of two).
func BuilderFromSchema(
	airSchema schema.AnySchema[corsetkoalabear.Element],
	moduleN map[string]int,
) (board.Builder, error) {
	builder := board.NewBuilder()

	// Create a board.Module for every entry in moduleN. This covers both
	// go-corset schema modules and synthetic type-table modules.
	for name, n := range moduleN {
		m := board.NewModule()
		m.N = n
		builder.AddModule(name, m)
	}

	// Translate each constraint.
	for _, c := range airSchema.Constraints().Collect() {
		var err error
		switch vc := c.(type) {
		case air.VanishingConstraint[corsetkoalabear.Element]:
			err = translateVanishing(&builder, airSchema, vc)
		case air.LookupConstraint[corsetkoalabear.Element]:
			err = translateLookup(&builder, airSchema, vc)
		case air.PermutationConstraint[corsetkoalabear.Element]:
			err = translatePermutation(&builder, airSchema, vc)
		case air.RangeConstraint[corsetkoalabear.Element]:
			err = translateRange(&builder, airSchema, vc)
		default:
			return board.Builder{}, fmt.Errorf("unknown AIR constraint type %T", c)
		}
		if err != nil {
			return board.Builder{}, err
		}
	}

	return builder, nil
}

// moduleName returns the string key for a go-corset module.
func moduleName(airSchema schema.AnySchema[corsetkoalabear.Element], id schema.ModuleId) string {
	return airSchema.Module(id).Name().String()
}

func translateVanishing(
	builder *board.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	vc air.VanishingConstraint[corsetkoalabear.Element],
) error {
	inner := vc.Unwrap()
	modName := moduleName(airSchema, inner.Context)
	e, err := translateTerm(inner.Constraint.Term, inner.Context, airSchema)
	if err != nil {
		return fmt.Errorf("vanishing %q: %w", inner.Handle, err)
	}
	if inner.Domain.IsEmpty() {
		return builder.AssertZero(modName, e)
	}
	row := inner.Domain.Unwrap()
	if row < 0 {
		m := builder.Modules[modName]
		row = m.N + row
	}
	return builder.AssertEqualAt(modName, e, expr.Const(koalabear.Element{}), row)
}

func translateLookup(
	builder *board.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	lc air.LookupConstraint[corsetkoalabear.Element],
) error {
	inner := lc.Unwrap()
	if len(inner.Sources) != 1 || len(inner.Targets) != 1 {
		return fmt.Errorf("lookup %q: only single source/target vector supported (got %d sources, %d targets)",
			inner.Handle, len(inner.Sources), len(inner.Targets))
	}
	src := inner.Sources[0]
	tgt := inner.Targets[0]
	if src.HasSelector() || tgt.HasSelector() {
		return fmt.Errorf("lookup %q: selector-gated vectors are not supported", inner.Handle)
	}
	srcMod := moduleName(airSchema, src.Module)
	tgtMod := moduleName(airSchema, tgt.Module)

	S := make([]board.Input, src.Len())
	for i := range src.Len() {
		S[i] = board.Input{Module: srcMod, In: colAccessExpr(airSchema, src.Module, src.Ith(i))}
	}
	T := make([]board.Input, tgt.Len())
	for i := range tgt.Len() {
		T[i] = board.Input{Module: tgtMod, In: colAccessExpr(airSchema, tgt.Module, tgt.Ith(i))}
	}
	if err := arguments.LookupTuple(builder, S, T); err != nil {
		return fmt.Errorf("lookup %q: %w", inner.Handle, err)
	}
	return nil
}

func translatePermutation(
	builder *board.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	pc air.PermutationConstraint[corsetkoalabear.Element],
) error {
	inner := pc.Unwrap()
	modName := moduleName(airSchema, inner.Context)

	mod := airSchema.Module(inner.Context)
	sources := make([]expr.Expr, len(inner.Sources))
	for i, id := range inner.Sources {
		sources[i] = expr.Col(mod.Register(id).QualifiedName(mod))
	}
	targets := make([]expr.Expr, len(inner.Targets))
	for i, id := range inner.Targets {
		targets[i] = expr.Col(mod.Register(id).QualifiedName(mod))
	}
	if err := arguments.PermutationTupleWithinModule(builder, modName, [][]expr.Expr{sources}, [][]expr.Expr{targets}); err != nil {
		return fmt.Errorf("permutation %q: %w", inner.Handle, err)
	}
	return nil
}

func translateRange(
	builder *board.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	rc air.RangeConstraint[corsetkoalabear.Element],
) error {
	inner := rc.Unwrap()
	srcMod := moduleName(airSchema, inner.Context)
	mod := airSchema.Module(inner.Context)
	for i, source := range inner.Sources {
		bw := inner.Bitwidths[i]
		if source.RelativeShift() != 0 {
			return fmt.Errorf("range constraint %q: shifted source not supported", inner.Handle)
		}
		colName := mod.Register(source.Register()).QualifiedName(mod)
		tgtMod := typeTableModuleName(bw)
		tgtCol := typeTableColName(bw)
		S := []board.Input{{Module: srcMod, In: expr.Col(colName)}}
		T := []board.Input{{Module: tgtMod, In: expr.Col(tgtCol)}}
		if err := arguments.LookupTuple(builder, S, T); err != nil {
			return fmt.Errorf("range constraint %q (u%d): %w", inner.Handle, bw, err)
		}
	}
	return nil
}

func translateTerm(
	t air.Term[corsetkoalabear.Element],
	moduleId schema.ModuleId,
	airSchema schema.AnySchema[corsetkoalabear.Element],
) (expr.Expr, error) {
	switch v := t.(type) {
	case *air.Add[corsetkoalabear.Element]:
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Add(b) },
			koalabear.Element{})
	case *air.Sub[corsetkoalabear.Element]:
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Sub(b) },
			koalabear.Element{})
	case *air.Mul[corsetkoalabear.Element]:
		var one koalabear.Element
		one.SetOne()
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Mul(b) },
			one)
	case *air.Constant[corsetkoalabear.Element]:
		return expr.Const(toKoalabear(v.Value)), nil
	case *air.ColumnAccess[corsetkoalabear.Element]:
		mod := airSchema.Module(moduleId)
		name := mod.Register(v.Register()).QualifiedName(mod)
		if v.RelativeShift() == 0 {
			return expr.Col(name), nil
		}
		return expr.Rot(name, v.RelativeShift()), nil
	default:
		return nil, fmt.Errorf("unknown AIR term type %T", t)
	}
}

func foldTerms(
	args []air.Term[corsetkoalabear.Element],
	moduleId schema.ModuleId,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	combine func(expr.Expr, expr.Expr) expr.Expr,
	identity koalabear.Element,
) (expr.Expr, error) {
	if len(args) == 0 {
		return expr.Const(identity), nil
	}
	result, err := translateTerm(args[0], moduleId, airSchema)
	if err != nil {
		return nil, err
	}
	for _, arg := range args[1:] {
		e, err := translateTerm(arg, moduleId, airSchema)
		if err != nil {
			return nil, err
		}
		result = combine(result, e)
	}
	return result, nil
}

func colAccessExpr(
	airSchema schema.AnySchema[corsetkoalabear.Element],
	moduleId schema.ModuleId,
	ca *air.ColumnAccess[corsetkoalabear.Element],
) expr.Expr {
	mod := airSchema.Module(moduleId)
	name := mod.Register(ca.Register()).QualifiedName(mod)
	if ca.RelativeShift() == 0 {
		return expr.Col(name)
	}
	return expr.Rot(name, ca.RelativeShift())
}

func toKoalabear(v corsetkoalabear.Element) koalabear.Element {
	var out koalabear.Element
	out.SetUint64(uint64(v.ToUint32()))
	return out
}
