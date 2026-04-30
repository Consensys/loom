package integrationtest

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	gnark_kb "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/go-corset/pkg/asm"
	"github.com/consensys/go-corset/pkg/binfile"
	"github.com/consensys/go-corset/pkg/corset"
	"github.com/consensys/go-corset/pkg/ir/air"
	"github.com/consensys/go-corset/pkg/ir/mir"
	"github.com/consensys/go-corset/pkg/schema"
	"github.com/consensys/go-corset/pkg/schema/module"
	"github.com/consensys/go-corset/pkg/schema/register"
	"github.com/consensys/go-corset/pkg/util/field"
	gocorset_kb "github.com/consensys/go-corset/pkg/util/field/koalabear"
	"github.com/consensys/go-corset/pkg/util/source"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/trace"
)

// ====================== Reading schema =========================

// CompileBin compiles a "zkevm.bin" BinaryFile into an air.Schema whilst
// applying whatever optimisations are requested.
func CompileBin(
	binf *binfile.BinaryFile,
	optConfig *mir.OptimisationConfig,
) (
	*air.Schema[gocorset_kb.Element],
	module.LimbsMap,
) {
	asmConfig := asm.LoweringConfig{Field: field.KOALABEAR_16, Vectorize: true}
	uasmSchema := asm.LowerMixedMacroProgram(asmConfig.Vectorize, binf.Schema)
	nasmSchema, mapping := asm.Concretize[gocorset_kb.Element](asmConfig.Field, uasmSchema)
	mirSchema := asm.Compile(nasmSchema)
	airSchema := mir.LowerToAir(mirSchema, 30, *optConfig)
	return &airSchema, mapping
}

// CompileLisp compiles a .lisp source file into an air.Schema.
// The bytes argument is the file contents; filename is used only for error messages.
func CompileLisp(filename string, bytes []byte) (*air.Schema[gocorset_kb.Element], module.LimbsMap, error) {
	config := corset.CompilationConfig{Stdlib: true}
	srcfile := *source.NewSourceFile(filename, bytes)
	prog, _, syntaxErrors := corset.CompileSourceFile(config, srcfile)
	if len(syntaxErrors) > 0 {
		msgs := make([]string, len(syntaxErrors))
		for i, e := range syntaxErrors {
			msgs[i] = e.Error()
		}
		return nil, nil, fmt.Errorf("compile %q: %s", filename, strings.Join(msgs, "; "))
	}
	asmConfig := asm.LoweringConfig{Field: field.KOALABEAR_16, Vectorize: true}
	uasmSchema := asm.LowerMixedMacroProgram(asmConfig.Vectorize, prog)
	nasmSchema, mapping := asm.Concretize[gocorset_kb.Element](asmConfig.Field, uasmSchema)
	mirSchema := asm.Compile(nasmSchema)
	optConfig := mir.DEFAULT_OPTIMISATION_LEVEL
	airSchema := mir.LowerToAir(mirSchema, 30, optConfig)
	return &airSchema, mapping, nil
}

// ReadBin reads and deserialises a .bin file produced by 'go-corset compile'.
func ReadBin(r io.Reader) (*binfile.BinaryFile, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll failed: %w", err)
	}

	gob.Register(binfile.Attribute(&corset.SourceMap{}))

	var binf binfile.BinaryFile
	if err := binf.UnmarshalBinary(buf); err != nil {
		return nil, fmt.Errorf("could not parse bin file: %w", err)
	}

	return &binf, nil
}

// ====================== Loom bridge =========================

// CorsetBridge translates a go-corset air.Schema into a loom board.Builder.
type CorsetBridge struct {
	Builder *board.Builder
	Schema  *air.Schema[gocorset_kb.Element]
}

// NewCorsetBridge initialises a bridge. Every module name present in s must
// appear in moduleN, or SetupModules will panic.
func NewCorsetBridge(
	builder *board.Builder,
	s *air.Schema[gocorset_kb.Element],
) *CorsetBridge {
	return &CorsetBridge{Builder: builder, Schema: s}
}

// SetupModules creates one loom Module per go-corset schema module and
// registers it in the builder. Must be called before ScanConstraints.
// Modules with 0 registers are skipped: they are go-corset's root/global
// placeholder (always module ID 0, empty name) and can never hold column-
// access constraints, so they produce no relations in loom.
func (b *CorsetBridge) SetupModules() {
	for _, m := range b.Schema.Modules().Collect() {
		if m.Width() == 0 {
			continue
		}
		name := m.Name().String()
		loomMod := board.NewModule(name)
		b.Builder.AddModule(name, loomMod)
	}
}

// loomModuleName returns the loom module name for a schema module ID.
func (b *CorsetBridge) loomModuleName(moduleID uint) string {
	return b.Schema.Module(moduleID).Name().String()
}

// colName returns the loom column name for a (moduleID, registerID) pair.
// For a named module it returns "moduleName.registerName"; for the root module
// (empty name) it returns just "registerName" to match the trace key format.
func (b *CorsetBridge) colName(moduleID uint, regID register.Id) string {
	mod := b.Schema.Module(moduleID)
	modName := mod.Name().String()
	regName := mod.Register(regID).Name()
	if modName == "" {
		return regName
	}
	return modName + "." + regName
}

// toGnarkElement converts a go-corset koalabear field element to the
// gnark-crypto representation used by loom.
func toGnarkElement(e gocorset_kb.Element) gnark_kb.Element {
	var result gnark_kb.Element
	result.SetUint64(uint64(e.ToUint32()))
	return result
}

// termToExpr recursively converts a go-corset AIR term to a loom expr.Expr.
//
// moduleID is the enclosing schema module, used to look up register names for
// column-access terms.
func (b *CorsetBridge) termToExpr(t air.Term[gocorset_kb.Element], moduleID uint) expr.Expr {
	switch v := t.(type) {

	case *air.ColumnAccess[gocorset_kb.Element]:
		reg := b.Schema.Module(moduleID).Register(v.Register())
		// Constant registers ("0" and "1") are inlined as literals.
		if reg.IsConst() {
			var val gnark_kb.Element
			val.SetUint64(uint64(reg.ConstValue()))
			return expr.Const(val)
		}
		name := b.colName(moduleID, v.Register())
		if shift := v.RelativeShift(); shift != 0 {
			return expr.Rot(name, shift)
		}
		return expr.Col(name)

	case *air.Constant[gocorset_kb.Element]:
		return expr.Const(toGnarkElement(v.Value))

	case *air.Add[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			return expr.Const(gnark_kb.Element{})
		}
		result := b.termToExpr(v.Args[0], moduleID)
		for _, arg := range v.Args[1:] {
			result = result.Add(b.termToExpr(arg, moduleID))
		}
		return result

	case *air.Sub[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			return expr.Const(gnark_kb.Element{})
		}
		result := b.termToExpr(v.Args[0], moduleID)
		for _, arg := range v.Args[1:] {
			result = result.Sub(b.termToExpr(arg, moduleID))
		}
		return result

	case *air.Mul[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			one := gnark_kb.One()
			return expr.Const(one)
		}
		result := b.termToExpr(v.Args[0], moduleID)
		for _, arg := range v.Args[1:] {
			result = result.Mul(b.termToExpr(arg, moduleID))
		}
		return result

	default:
		panic(fmt.Sprintf("termToExpr: unsupported AIR term type %T", t))
	}
}

// AddConstraintInLoom translates a single go-corset constraint into the loom
// builder. Returns an error for unsupported constraint forms; panics only for
// truly unexpected term types.
func (b *CorsetBridge) AddConstraintInLoom(name string, corsetCS schema.Constraint[gocorset_kb.Element]) error {

	switch cs := corsetCS.(type) {

	// ── Vanishing (polynomial identity) ───────────────────────────────────
	case air.VanishingConstraint[gocorset_kb.Element]:
		vc := cs.Unwrap()
		modName := b.loomModuleName(vc.Context)
		loomExpr := b.termToExpr(vc.Constraint.Term, vc.Context)

		if vc.Domain.IsEmpty() {
			// Global constraint: holds on every row.
			return b.Builder.AssertZero(modName, loomExpr)
		}

		// Local constraint: holds on a specific row.
		position := vc.Domain.Unwrap()
		m, ok := b.Builder.Modules[modName]
		if position < 0 {
			m.AssertZeroRelativeAt(loomExpr, -position)
		}
		if !ok {
			return fmt.Errorf("constraint %q: module %q not found in builder", name, modName)
		}
		m.AssertZeroAt(loomExpr, position)
		return nil

	// ── Lookup (subset argument) ──────────────────────────────────────────
	case air.LookupConstraint[gocorset_kb.Element]:
		lc := cs.Unwrap()

		if len(lc.Sources) == 0 || len(lc.Targets) == 0 {
			return fmt.Errorf("constraint %q: empty lookup", name)
		}

		width := lc.Sources[0].Len()
		if width == 0 {
			return fmt.Errorf("constraint %q: empty lookup vector", name)
		}

		one := gnark_kb.One()

		hasAnySelector := false
		for _, v := range lc.Sources {
			if v.HasSelector() {
				hasAnySelector = true
				break
			}
		}
		if !hasAnySelector {
			for _, v := range lc.Targets {
				if v.HasSelector() {
					hasAnySelector = true
					break
				}
			}
		}

		selS := make([]expr.Expr, len(lc.Sources))
		for i, v := range lc.Sources {
			if v.HasSelector() {
				selS[i] = b.termToExpr(v.Selector.Unwrap(), v.Module)
			} else {
				selS[i] = expr.Const(one)
			}
		}
		selT := make([]expr.Expr, len(lc.Targets))
		for i, v := range lc.Targets {
			if v.HasSelector() {
				selT[i] = b.termToExpr(v.Selector.Unwrap(), v.Module)
			} else {
				selT[i] = expr.Const(one)
			}
		}

		if width == 1 {
			S := make([]board.Column, len(lc.Sources))
			for i, v := range lc.Sources {
				S[i] = board.Column{Module: b.loomModuleName(v.Module), In: b.termToExpr(v.Ith(0), v.Module)}
			}
			T := make([]board.Column, len(lc.Targets))
			for i, v := range lc.Targets {
				T[i] = board.Column{Module: b.loomModuleName(v.Module), In: b.termToExpr(v.Ith(0), v.Module)}
			}
			if !hasAnySelector {
				return arguments.LookupUnion(b.Builder, S, T)
			}
			return arguments.CLookupUnion(b.Builder, selS, selT, S, T)
		}

		// Tuple lookup: fold all columns per group with a random challenge.
		S := make([]board.Table, len(lc.Sources))
		for i, v := range lc.Sources {
			S[i] = board.NewTable(b.loomModuleName(v.Module), int(width))
			for j := range width {
				S[i].In[j] = b.termToExpr(v.Ith(j), v.Module)
			}
		}
		T := make([]board.Table, len(lc.Targets))
		for i, v := range lc.Targets {
			T[i] = board.NewTable(b.loomModuleName(v.Module), int(width))
			for j := range width {
				T[i].In[j] = b.termToExpr(v.Ith(j), v.Module)
			}
		}
		if !hasAnySelector {
			return arguments.LookupUnionTuple(b.Builder, S, T)
		}
		return arguments.CLookupUnionTuple(b.Builder, selS, selT, S, T)

	// ── Permutation (grand-product argument) ──────────────────────────────
	case air.PermutationConstraint[gocorset_kb.Element]:
		pc := cs.Unwrap()
		modName := b.loomModuleName(pc.Context)
		numCol := len(pc.Sources)
		if numCol != len(pc.Targets) {
			return fmt.Errorf("constraint %q: permutation sources and targets have different lengths", name)
		}
		if numCol == 0 {
			return nil
		}

		srcs := make([]expr.Expr, numCol)
		tgts := make([]expr.Expr, numCol)
		for i := range numCol {
			srcs[i] = expr.Col(b.colName(pc.Context, pc.Sources[i]))
			tgts[i] = expr.Col(b.colName(pc.Context, pc.Targets[i]))
		}

		if numCol == 1 {
			// Single-column grand product is simpler (no folding challenge).
			return arguments.PermutationWithinModule(b.Builder, modName, srcs, tgts)
		}

		// Multi-column: prove the joint row-tuple (srcs[0][i], ..., srcs[k][i])
		// is a permutation of (tgts[0][i], ..., tgts[k][i]).
		return arguments.PermutationTupleWithinModule(b.Builder, modName,
			[][]expr.Expr{srcs},
			[][]expr.Expr{tgts},
		)

	// ── Range constraint ──────────────────────────────────────────────────
	case air.RangeConstraint[gocorset_kb.Element]:
		rc := cs.Unwrap()
		modName := b.loomModuleName(rc.Context)
		for i, src := range rc.Sources {
			bound := uint64(1) << rc.Bitwidths[i]
			S := board.Column{Module: modName, In: b.termToExpr(src, rc.Context)}
			if err := arguments.Range(b.Builder, S, bound); err != nil {
				return err
			}
		}
		return nil

	// ── Assertion (debugging property) ───────────────────────────────────
	case air.Assertion[gocorset_kb.Element]:
		// Property assertions are never compiled into the proof; skip.
		return nil

	// ── Interleaving ──────────────────────────────────────────────────────
	case air.InterleavingConstraint[gocorset_kb.Element]:
		return fmt.Errorf("constraint %q: InterleavingConstraint is not supported", name)

	default:
		return fmt.Errorf("constraint %q: unknown constraint type %T", name, corsetCS)
	}
}

// ====================== Scanning =========================

// ScanConstraints translates all constraints in the air schema into the loom
// builder attached to bridge. Constraints are processed in deterministic
// (lexicographic Lisp-name) order. Panics on the first error.
func ScanConstraints(bridge *CorsetBridge) {
	s := bridge.Schema
	corsetCSS := s.Constraints().Collect()

	indices := make([]int, len(corsetCSS))
	for i := range indices {
		indices[i] = i
	}

	names := make([]string, len(corsetCSS))
	for i, cs := range corsetCSS {
		names[i] = cs.Lisp(s).String(false)
	}

	sort.Slice(indices, func(i, j int) bool {
		return names[indices[i]] < names[indices[j]]
	})

	for _, idx := range indices {
		if err := bridge.AddConstraintInLoom(names[idx], corsetCSS[idx]); err != nil {
			panic(fmt.Sprintf("ScanConstraints: %v", err))
		}
	}
}

// ====================== Trace loading =========================

// TracesFromLT parses a .lt file (JSONL format) and returns one trace.Trace per
// non-empty line. Each line must be a JSON object mapping "module.column" keys
// to arrays of integers. Column arrays are zero-padded to the next power of two
// (minimum 1) as required by loom's FFT-based evaluation.
func TracesFromLT(r io.Reader) ([]trace.Trace, error) {
	var traces []trace.Trace
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";;") {
			continue
		}
		var raw map[string][]json.Number
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("TracesFromLT: failed to parse line: %w", err)
		}
		t := make(trace.Trace)
		for col, nums := range raw {
			n := uint64(len(nums))
			if n == 0 {
				n = 1
			}
			n = ecc.NextPowerOfTwo(n)
			col := col
			poly := make([]gnark_kb.Element, n)
			for i, num := range nums {
				v, err := num.Int64()
				if err != nil {
					return nil, fmt.Errorf("TracesFromLT: column %q index %d: %w", col, i, err)
				}
				poly[i].SetUint64(uint64(v))
			}
			t[col] = poly
		}
		traces = append(traces, t)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("TracesFromLT: scanner error: %w", err)
	}
	return traces, nil
}

// ====================== Size setting =========================

func setSizes(program *board.Program, tr trace.Trace) {
	moduleSizes := map[string]int{}
	for colName, col := range tr {
		idx := strings.IndexByte(colName, '.')
		if idx < 0 {
			// root module column (no dot) — maps to module with empty name
			moduleSizes[""] = len(col)
		} else {
			modName := colName[:idx]
			moduleSizes[modName] = len(col)
		}
	}
	for name, cm := range program.Modules {
		n, ok := moduleSizes[name]
		if !ok {
			continue
		}
		cm.N = n
		cm.D = fft.NewDomain(uint64(n))
		program.Modules[name] = cm
	}
}
