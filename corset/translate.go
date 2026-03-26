package corset

import (
	"fmt"

	lmkoalabear "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"

	"github.com/consensys/go-corset/pkg/ir/air"
	"github.com/consensys/go-corset/pkg/schema"
	gckoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"
)

func translateConstraints(
	builder *constraint.Builder,
	airSchema schema.AnySchema[gckoalabear.Element],
	moduleIndex uint,
) error {
	constraints := airSchema.Module(moduleIndex).Constraints()
	for constraints.HasNext() {
		c := constraints.Next()
		var err error
		switch vc := c.(type) {
		case air.VanishingConstraint[gckoalabear.Element]:
			err = translateVanishing(builder, airSchema, vc)
		case air.LookupConstraint[gckoalabear.Element]:
			err = translateLookup(builder, airSchema, vc)
		case air.PermutationConstraint[gckoalabear.Element]:
			err = translatePermutation(builder, airSchema, vc)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func translateVanishing(
	builder *constraint.Builder,
	airSchema schema.AnySchema[gckoalabear.Element],
	vc air.VanishingConstraint[gckoalabear.Element],
) error {
	inner := vc.Unwrap()
	e, err := translateTerm(inner.Constraint.Term, inner.Context, airSchema)
	if err != nil {
		return fmt.Errorf("vanishing %q: %w", inner.Handle, err)
	}
	if inner.Domain.IsEmpty() {
		builder.AssertZero(e)
		return nil
	}
	row := inner.Domain.Unwrap()
	if row < 0 {
		row = builder.N + row
	}
	builder.AssertEqualAt(e, expr.Const(lmkoalabear.Element{}), row)
	return nil
}

func translateLookup(
	builder *constraint.Builder,
	airSchema schema.AnySchema[gckoalabear.Element],
	lc air.LookupConstraint[gckoalabear.Element],
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
	S := make([]expr.Expr, src.Len())
	for i := uint(0); i < src.Len(); i++ {
		S[i] = colAccessExpr(airSchema, src.Module, src.Ith(i))
	}
	T := make([]expr.Expr, tgt.Len())
	for i := uint(0); i < tgt.Len(); i++ {
		T[i] = colAccessExpr(airSchema, tgt.Module, tgt.Ith(i))
	}
	if err := arguments.LookupTuple(builder, S, T); err != nil {
		return fmt.Errorf("lookup %q: %w", inner.Handle, err)
	}
	return nil
}

func translatePermutation(
	builder *constraint.Builder,
	airSchema schema.AnySchema[gckoalabear.Element],
	pc air.PermutationConstraint[gckoalabear.Element],
) error {
	inner := pc.Unwrap()
	mod := airSchema.Module(inner.Context)
	sources := make([]expr.Expr, len(inner.Sources))
	for i, id := range inner.Sources {
		sources[i] = expr.Col(mod.Register(id).QualifiedName(mod))
	}
	targets := make([]expr.Expr, len(inner.Targets))
	for i, id := range inner.Targets {
		targets[i] = expr.Col(mod.Register(id).QualifiedName(mod))
	}
	if err := arguments.PermutationTuple(builder, [][]expr.Expr{sources}, [][]expr.Expr{targets}); err != nil {
		return fmt.Errorf("permutation %q: %w", inner.Handle, err)
	}
	return nil
}

func translateTerm(
	t air.Term[gckoalabear.Element],
	moduleId schema.ModuleId,
	airSchema schema.AnySchema[gckoalabear.Element],
) (expr.Expr, error) {
	switch v := t.(type) {
	case *air.Add[gckoalabear.Element]:
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Add(b) },
			lmkoalabear.Element{})
	case *air.Sub[gckoalabear.Element]:
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Sub(b) },
			lmkoalabear.Element{})
	case *air.Mul[gckoalabear.Element]:
		var one lmkoalabear.Element
		one.SetOne()
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Mul(b) },
			one)
	case *air.Constant[gckoalabear.Element]:
		return expr.Const(toKoalabear(v.Value)), nil
	case *air.ColumnAccess[gckoalabear.Element]:
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
	args []air.Term[gckoalabear.Element],
	moduleId schema.ModuleId,
	airSchema schema.AnySchema[gckoalabear.Element],
	combine func(expr.Expr, expr.Expr) expr.Expr,
	identity lmkoalabear.Element,
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
	airSchema schema.AnySchema[gckoalabear.Element],
	moduleId schema.ModuleId,
	ca *air.ColumnAccess[gckoalabear.Element],
) expr.Expr {
	mod := airSchema.Module(moduleId)
	name := mod.Register(ca.Register()).QualifiedName(mod)
	if ca.RelativeShift() == 0 {
		return expr.Col(name)
	}
	return expr.Rot(name, ca.RelativeShift())
}

func toKoalabear(v gckoalabear.Element) lmkoalabear.Element {
	var out lmkoalabear.Element
	out.SetUint64(uint64(v.ToUint32()))
	return out
}
