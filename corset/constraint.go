package corset

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"

	"github.com/consensys/go-corset/pkg/ir/air"
	"github.com/consensys/go-corset/pkg/schema"
	corsetkoalabear "github.com/consensys/go-corset/pkg/util/field/koalabear"

	"github.com/consensys/go-corset/pkg/asm"
	cmdutil "github.com/consensys/go-corset/pkg/cmd/corset/util"
	"github.com/consensys/go-corset/pkg/util/field"
)

// BuildFromCorsetBin reads a go-corset binary constraints file, lowers it to AIR
// for the Koalabear field, and returns a loom constraint.Builder containing all
// constraints from all modules. N is the trace length.
func BuildFromCorsetBin(binPath string, N int) (constraint.Builder, error) {
	binf := cmdutil.ReadBinaryFile(binPath)
	stack := cmdutil.NewSchemaStack[corsetkoalabear.Element]().
		WithBinaryFile(binf).
		WithAssemblyConfig(asm.LoweringConfig{Field: field.KOALABEAR_16}).
		WithLayer(cmdutil.AIR_LAYER).
		Build()

	airSchema := stack.ConcreteSchema()
	builder := constraint.NewBuilder(N, nil)
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
			return constraint.Builder{}, fmt.Errorf("range constraints are not yet supported (constraint %q)", vc.Name())
		default:
			return constraint.Builder{}, fmt.Errorf("unknown AIR constraint type %T", c)
		}
		if err != nil {
			return constraint.Builder{}, err
		}
	}
	return builder, nil
}

// translateVanishing maps a go-corset vanishing constraint to loom. Global
// constraints (empty domain) become AssertZero. Local constraints at a specific
// row become AssertEqualAt with a zero RHS; negative row indices count from the
// end of the trace.
func translateVanishing(
	builder *constraint.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	vc air.VanishingConstraint[corsetkoalabear.Element],
) error {
	inner := vc.Unwrap()
	e, err := translateTerm(inner.Constraint.Term, inner.Context, airSchema)
	if err != nil {
		return fmt.Errorf("vanishing %q: %w", inner.Handle, err)
	}
	// An empty domain means the constraint must hold on every row.
	if inner.Domain.IsEmpty() {
		builder.AssertZero(e)
		return nil
	}
	// A non-empty domain pins the constraint to one row. Negative indices are
	// relative to the end of the trace (e.g. -1 is the last row).
	row := inner.Domain.Unwrap()
	if row < 0 {
		row = builder.N + row
	}
	builder.AssertEqualAt(e, expr.Const(koalabear.Element{}), row)
	return nil
}

// translateLookup maps a go-corset lookup constraint to loom's LookupTuple.
// Only constraints with exactly one source vector and one target vector are
// supported; selector-gated vectors are not supported.
func translateLookup(
	builder *constraint.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	lc air.LookupConstraint[corsetkoalabear.Element],
) error {
	inner := lc.Unwrap()
	// go-corset allows multiple source/target vector pairs for OR-style lookups;
	// loom's LookupTuple only expresses the single-pair case.
	if len(inner.Sources) != 1 || len(inner.Targets) != 1 {
		return fmt.Errorf("lookup %q: only single source/target vector supported (got %d sources, %d targets)",
			inner.Handle, len(inner.Sources), len(inner.Targets))
	}
	src := inner.Sources[0]
	tgt := inner.Targets[0]
	// Selectors filter which rows participate in the lookup; there is no
	// equivalent in loom's LookupTuple.
	if src.HasSelector() || tgt.HasSelector() {
		return fmt.Errorf("lookup %q: selector-gated vectors are not supported", inner.Handle)
	}
	// Each vector holds one column access per element of the row-tuple.
	S := make([]expr.Expr, src.Len())
	for i := range src.Len() {
		S[i] = colAccessExpr(airSchema, src.Module, src.Ith(i))
	}
	T := make([]expr.Expr, tgt.Len())
	for i := range tgt.Len() {
		T[i] = colAccessExpr(airSchema, tgt.Module, tgt.Ith(i))
	}
	if err := arguments.LookupTuple(builder, S, T); err != nil {
		return fmt.Errorf("lookup %q: %w", inner.Handle, err)
	}
	return nil
}

// translatePermutation maps a go-corset permutation constraint to loom's
// PermutationTuple, treating the full set of source and target columns as a
// single tuple.
func translatePermutation(
	builder *constraint.Builder,
	airSchema schema.AnySchema[corsetkoalabear.Element],
	pc air.PermutationConstraint[corsetkoalabear.Element],
) error {
	inner := pc.Unwrap()
	// All source and target columns live in the same module.
	mod := airSchema.Module(inner.Context)
	// Resolve column IDs to qualified name expressions.
	sources := make([]expr.Expr, len(inner.Sources))
	for i, id := range inner.Sources {
		sources[i] = expr.Col(mod.Register(id).QualifiedName(mod))
	}
	targets := make([]expr.Expr, len(inner.Targets))
	for i, id := range inner.Targets {
		targets[i] = expr.Col(mod.Register(id).QualifiedName(mod))
	}
	// Wrap as a single tuple so PermutationTuple checks the full row-vector.
	if err := arguments.PermutationTuple(builder, [][]expr.Expr{sources}, [][]expr.Expr{targets}); err != nil {
		return fmt.Errorf("permutation %q: %w", inner.Handle, err)
	}
	return nil
}

// translateTerm recursively converts a go-corset AIR term to a loom expr.Expr.
// Column accesses are resolved to qualified names ("module:col" or "col" for
// the root module). Shifted accesses become expr.Rot.
func translateTerm(
	t air.Term[corsetkoalabear.Element],
	moduleId schema.ModuleId,
	airSchema schema.AnySchema[corsetkoalabear.Element],
) (expr.Expr, error) {
	switch v := t.(type) {
	case *air.Add[corsetkoalabear.Element]:
		// Identity for empty sums is zero.
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Add(b) },
			koalabear.Element{})
	case *air.Sub[corsetkoalabear.Element]:
		// go-corset Sub semantics: Args[0] - Args[1] - Args[2] - ...
		// Identity for an empty difference is zero.
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Sub(b) },
			koalabear.Element{})
	case *air.Mul[corsetkoalabear.Element]:
		// Identity for empty products is one.
		var one koalabear.Element
		one.SetOne()
		return foldTerms(v.Args, moduleId, airSchema,
			func(a, b expr.Expr) expr.Expr { return a.Mul(b) },
			one)
	case *air.Constant[corsetkoalabear.Element]:
		// go-corset uses its own koalabear type; convert to gnark-crypto's.
		return expr.Const(toKoalabear(v.Value)), nil
	case *air.ColumnAccess[corsetkoalabear.Element]:
		// Resolve the column ID to a qualified name, then emit Col or Rot
		// depending on whether there is a row shift.
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

// foldTerms translates each argument in args and combines them left-to-right
// using combine. Returns expr.Const(identity) for an empty argument list.
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

// colAccessExpr converts a go-corset ColumnAccess to a loom leaf expression.
// The column name is qualified with its module ("module:col" or "col" for the
// root module). A non-zero shift produces expr.Rot; zero shift produces expr.Col.
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
