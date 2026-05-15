// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gocorset

import (
	"bufio"
	"encoding/gob"
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
	"github.com/consensys/go-corset/pkg/ir"
	"github.com/consensys/go-corset/pkg/ir/air"
	"github.com/consensys/go-corset/pkg/ir/mir"
	"github.com/consensys/go-corset/pkg/schema"
	"github.com/consensys/go-corset/pkg/schema/module"
	"github.com/consensys/go-corset/pkg/schema/register"
	gc_trace "github.com/consensys/go-corset/pkg/trace"
	trace_json "github.com/consensys/go-corset/pkg/trace/json"
	"github.com/consensys/go-corset/pkg/trace/lt"
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
		b.Builder.AddModule(loomMod)
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

// isRealColName returns the name of the IS_REAL column for a given module.
// IS_REAL is 1 for real (original) rows and 0 for padded rows.
func isRealColName(modName string) string {
	if modName == "" {
		return "__is_real__"
	}
	return modName + ".__is_real__"
}

// termToExpr recursively converts a go-corset AIR term to a loom expr.Expr.
//
// moduleID is the enclosing schema module, used to look up register names for
// column-access terms.
//
// boundsStart is the constraint's bounds.Start value. Backward-shift accesses
// of depth j ≤ boundsStart are wrapped with (1-L_0)·…·(1-L_{j-1}) so that
// the shift returns 0 at boundary rows 0..j-1, matching go-corset's spillage
// semantics (spillage rows are zero-padded). Pass 0 for non-vanishing contexts.
func (b *CorsetBridge) termToExpr(t air.Term[gocorset_kb.Element], moduleID uint, boundsStart int) expr.Expr {
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
		shift := v.RelativeShift()
		if shift < 0 && -int(shift) <= boundsStart && boundsStart > 0 {
			// Bounded backward shift: at rows 0..|shift|-1 the cyclic wrap would
			// read the wrong end of the trace. Replace with 0 (matching spillage).
			// (1-L_0)·…·(1-L_{|shift|-1}) · Rot(name, shift)
			modName := b.loomModuleName(moduleID)
			m, ok := b.Builder.Modules[modName]
			if ok {
				one := gnark_kb.One()
				base := expr.Rot(name, shift)
				sel := expr.Expr(expr.Const(one))
				for i := 0; i < -int(shift); i++ {
					sel = sel.Mul(expr.Const(one).Sub(m.LagrangeCol(i)))
				}
				return sel.Mul(base)
			}
		}
		if shift != 0 {
			return expr.Rot(name, shift)
		}
		return expr.Col(name)

	case *air.Constant[gocorset_kb.Element]:
		return expr.Const(toGnarkElement(v.Value))

	case *air.Add[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			return expr.Const(gnark_kb.Element{})
		}
		result := b.termToExpr(v.Args[0], moduleID, boundsStart)
		for _, arg := range v.Args[1:] {
			result = result.Add(b.termToExpr(arg, moduleID, boundsStart))
		}
		return result

	case *air.Sub[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			return expr.Const(gnark_kb.Element{})
		}
		result := b.termToExpr(v.Args[0], moduleID, boundsStart)
		for _, arg := range v.Args[1:] {
			result = result.Sub(b.termToExpr(arg, moduleID, boundsStart))
		}
		return result

	case *air.Mul[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			one := gnark_kb.One()
			return expr.Const(one)
		}
		result := b.termToExpr(v.Args[0], moduleID, boundsStart)
		for _, arg := range v.Args[1:] {
			result = result.Mul(b.termToExpr(arg, moduleID, boundsStart))
		}
		return result

	default:
		panic(fmt.Sprintf("termToExpr: unsupported AIR term type %T", t))
	}
}

// termToSpillageBoundaryExpr computes the "spillage boundary" version of an AIR
// term. go-corset always prepends ≥1 spillage rows (all zeros) before real data.
// For global constraints with forward shifts, those shifts are also checked at the
// spillage row, where "current" values are 0 and "next" values are the first real
// row. This function substitutes accordingly:
//   - column access with shift ≤ 0 → Const(0) (spillage value)
//   - column access with shift k > 0 → Col(name) at real offset k-1
//     (shift=1 → Col(name) at row 0; shift=2 → Rot(name, 1); etc.)
func (b *CorsetBridge) termToSpillageBoundaryExpr(t air.Term[gocorset_kb.Element], moduleID uint) expr.Expr {
	switch v := t.(type) {
	case *air.ColumnAccess[gocorset_kb.Element]:
		reg := b.Schema.Module(moduleID).Register(v.Register())
		if reg.IsConst() {
			var val gnark_kb.Element
			val.SetUint64(uint64(reg.ConstValue()))
			return expr.Const(val)
		}
		name := b.colName(moduleID, v.Register())
		shift := v.RelativeShift()
		if shift <= 0 {
			return expr.Const(gnark_kb.Element{}) // spillage value = 0
		}
		// shift > 0: use actual column at real-data offset (shift-1)
		if shift == 1 {
			return expr.Col(name)
		}
		return expr.Rot(name, shift-1)

	case *air.Constant[gocorset_kb.Element]:
		return expr.Const(toGnarkElement(v.Value))

	case *air.Add[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			return expr.Const(gnark_kb.Element{})
		}
		result := b.termToSpillageBoundaryExpr(v.Args[0], moduleID)
		for _, arg := range v.Args[1:] {
			result = result.Add(b.termToSpillageBoundaryExpr(arg, moduleID))
		}
		return result

	case *air.Sub[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			return expr.Const(gnark_kb.Element{})
		}
		result := b.termToSpillageBoundaryExpr(v.Args[0], moduleID)
		for _, arg := range v.Args[1:] {
			result = result.Sub(b.termToSpillageBoundaryExpr(arg, moduleID))
		}
		return result

	case *air.Mul[gocorset_kb.Element]:
		if len(v.Args) == 0 {
			one := gnark_kb.One()
			return expr.Const(one)
		}
		result := b.termToSpillageBoundaryExpr(v.Args[0], moduleID)
		for _, arg := range v.Args[1:] {
			result = result.Mul(b.termToSpillageBoundaryExpr(arg, moduleID))
		}
		return result

	default:
		panic(fmt.Sprintf("termToSpillageBoundaryExpr: unsupported AIR term type %T", t))
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

		if vc.Domain.IsEmpty() {
			// Global vanishing constraint. go-corset evaluates on rows
			// [bounds.Start .. H-1-bounds.End] using zero-padded spillage for
			// out-of-bounds backward accesses. Loom evaluates cyclically on all N
			// rows, so we must:
			//
			//   1. Replace backward-shift terms (shift X -j) at boundary rows
			//      0..j-1 with 0 (bounded shifts), matching spillage semantics.
			//   2. Multiply by IS_REAL to exclude padded rows H..N-1.
			//   3. For bounds.End=k, also multiply by Π_{j=1}^k (shift IS_REAL j) ·
			//      (1-L_{N-j}) so that the last k real rows (where forward shifts read
			//      into padding) are excluded — matching go-corset's end-boundary.
			bounds := cs.Bounds(vc.Context)
			m, ok := b.Builder.Modules[modName]
			if !ok {
				return fmt.Errorf("constraint %q: module %q not found in builder", name, modName)
			}

			// Convert constraint with bounded backward shifts.
			loomExpr := b.termToExpr(vc.Constraint.Term, vc.Context, int(bounds.Start))

			// Build selector: always include IS_REAL to exclude padded rows.
			one := gnark_kb.One()
			isRealName := isRealColName(modName)
			sel := expr.Expr(expr.Col(isRealName))
			// For bounds.End=k: additionally exclude the last k real rows by
			// combining (shift IS_REAL j) · (1-L_{N-j}) for j=1..k. The Lagrange
			// factor handles H=N traces (where IS_REAL is constant 1 and the shift
			// selector wraps around cyclically).
			for j := uint(1); j <= bounds.End; j++ {
				sel = sel.Mul(expr.Rot(isRealName, int(j)))
				sel = sel.Mul(expr.Const(one).Sub(m.LagrangeColRelative(int(j) - 1)))
			}

			m.AssertZero(loomExpr.Mul(sel))

			// Spillage boundary: go-corset also evaluates the constraint at spillage
			// rows (all zero), checking the transition into the first real row.
			// For bounds.End > 0, the spillage row reads zero for the "current" value
			// and the first real row for the forward-shifted value. Add a boundary
			// constraint at row 0 of our (spillage-free) trace to enforce this.
			if bounds.End > 0 {
				boundaryExpr := b.termToSpillageBoundaryExpr(vc.Constraint.Term, vc.Context)
				m.AssertZeroAt(boundaryExpr, 0)
			}
			return nil
		}

		// Local constraint: holds on a specific row.
		position := vc.Domain.Unwrap()
		if position >= 0 {
			// go-corset always prepends ≥1 spillage rows (all zero) before real data.
			// (:domain {0}) therefore checks the spillage row, which is trivially zero.
			// In loom we strip spillage and work on real rows only, so non-negative
			// domain constraints are vacuously satisfied — skip them entirely.
			return nil
		}
		// position < 0: (:domain {-K}) checks the K-th row from the end of the
		// real trace: row H-K where H is the real (unpadded) height.
		//
		// In loom there are no spillage rows; the module has N=nextPow2(H)≥H rows
		// with IS_REAL=1 for 0..H-1 and 0 for H..N-1. We need a selector that
		// fires at exactly row H-K.
		//
		// selector = prefix * ((1 - Rot(IS_REAL, K)) + LagrangeColRelative(K-1))
		// prefix   = IS_REAL * Rot(IS_REAL, 1) * … * Rot(IS_REAL, K-1)
		//
		// The (1-Rot(IS_REAL,K)) term fires at row H-K when H<N (IS_REAL drops to
		// 0 at row H). The LagrangeColRelative(K-1) term (fires at row N-K) handles
		// the H=N case where IS_REAL wraps cyclically and never drops to 0.
		K := -position
		isRealName := isRealColName(modName)
		one := gnark_kb.One()
		loomExpr := b.termToExpr(vc.Constraint.Term, vc.Context, 0)
		m, ok := b.Builder.Modules[modName]
		if !ok {
			return fmt.Errorf("constraint %q: module %q not found in builder", name, modName)
		}
		// Build prefix = IS_REAL * Rot(IS_REAL, 1) * ... * Rot(IS_REAL, K-1)
		prefix := expr.Expr(expr.Col(isRealName))
		for i := 1; i < K; i++ {
			prefix = prefix.Mul(expr.Rot(isRealName, i))
		}
		// correction = (1 - Rot(IS_REAL, K)) + LagrangeColRelative(K-1)
		correction := expr.Const(one).Sub(expr.Rot(isRealName, K)).Add(m.LagrangeColRelative(K - 1))
		sel := prefix.Mul(correction)
		m.AssertZero(loomExpr.Mul(sel))
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
				selS[i] = b.termToExpr(v.Selector.Unwrap(), v.Module, 0)
			} else {
				selS[i] = expr.Const(one)
			}
		}
		selT := make([]expr.Expr, len(lc.Targets))
		for i, v := range lc.Targets {
			if v.HasSelector() {
				selT[i] = b.termToExpr(v.Selector.Unwrap(), v.Module, 0)
			} else {
				selT[i] = expr.Const(one)
			}
		}

		if width == 1 {
			S := make([]board.Column, len(lc.Sources))
			for i, v := range lc.Sources {
				S[i] = board.Column{Module: b.loomModuleName(v.Module), In: b.termToExpr(v.Ith(0), v.Module, 0)}
			}
			T := make([]board.Column, len(lc.Targets))
			for i, v := range lc.Targets {
				T[i] = board.Column{Module: b.loomModuleName(v.Module), In: b.termToExpr(v.Ith(0), v.Module, 0)}
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
				S[i].In[j] = b.termToExpr(v.Ith(j), v.Module, 0)
			}
		}
		T := make([]board.Table, len(lc.Targets))
		for i, v := range lc.Targets {
			T[i] = board.NewTable(b.loomModuleName(v.Module), int(width))
			for j := range width {
				T[i].In[j] = b.termToExpr(v.Ith(j), v.Module, 0)
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
			S := board.Column{Module: modName, In: b.termToExpr(src, rc.Context, 0)}
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
// non-empty line. It uses go-corset's TraceBuilder to handle limb splitting and
// computed-witness expansion automatically. Column arrays are zero-padded to the
// next power of two (minimum 1) as required by loom's FFT-based evaluation.
func TracesFromLT(r io.Reader, airSchema *air.Schema[gocorset_kb.Element], mapping module.LimbsMap) ([]trace.Trace, error) {
	builder := ir.NewTraceBuilder[gocorset_kb.Element]().
		WithRegisterMapping(mapping).
		WithExpansion(true).
		WithDefensivePadding(false).
		WithValidation(false).
		WithParallelism(false)
	anySchema := schema.Any(*airSchema)

	// Build the padding map once per schema (not per trace).
	padLastValue := buildLastValuePaddingSet(airSchema)

	var traces []trace.Trace
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";;") {
			continue
		}
		heap, modules, err := trace_json.FromBytesLegacy([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("TracesFromLT: %w", err)
		}
		// Record original heights before ir.TraceBuilder adds spillage rows.
		// Loom evaluates constraints cyclically over X^N-1 so it doesn't need
		// spillage; using the expanded height would change the domain size and
		// break the cyclic semantics for shift constraints.
		origHeights := make(map[string]uint, len(modules))
		for i := range modules {
			origHeights[modules[i].Name().String()] = modules[i].Height()
		}
		tf := lt.NewTraceFile(nil, heap, modules)
		expanded, errs := builder.Build(anySchema, tf)
		if len(errs) > 0 || expanded == nil {
			continue
		}
		traces = append(traces, corsetTraceToLoom(expanded, origHeights, padLastValue))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("TracesFromLT: %w", err)
	}
	return traces, nil
}

func buildLastValuePaddingSet(_ *air.Schema[gocorset_kb.Element]) map[string]bool {
	return make(map[string]bool)
}

// corsetTraceToLoom converts a go-corset expanded trace into a loom trace.Trace.
// origHeights maps each module name to its row count before spillage padding.
// padLastValue maps full column keys to true for columns that should be padded
// with their last real value (see buildLastValuePaddingSet).
func corsetTraceToLoom(ct gc_trace.Trace[gocorset_kb.Element], origHeights map[string]uint,
	padLastValue map[string]bool) trace.Trace {
	t := trace.New()
	for i := uint(0); i < ct.Width(); i++ {
		mod := ct.Module(i)
		modName := mod.Name().String()
		origHeight := origHeights[modName]
		// Spillage rows are prepended; skip them to reach the actual data.
		spillage := mod.Height() - origHeight
		n := uint64(origHeight)
		if n == 0 {
			n = 1
		}
		n = ecc.NextPowerOfTwo(n)
		for j := uint(0); j < mod.Width(); j++ {
			col := mod.Column(j)
			key := col.Name()
			if modName != "" {
				key = modName + "." + col.Name()
			}
			poly := make([]gnark_kb.Element, n)
			for r := uint(0); r < origHeight; r++ {
				poly[r] = toGnarkElement(col.Get(int(spillage + r)))
			}
			// Apply last-value or zero padding for rows H..N-1.
			if padLastValue[key] && origHeight > 0 && uint(n) > origHeight {
				last := poly[origHeight-1]
				for r := origHeight; r < uint(n); r++ {
					poly[r] = last
				}
			}
			t.SetBase(key, poly)
		}
		// IS_REAL column: 1 for real rows 0..H-1, 0 for padded rows H..N-1.
		// Vanishing constraints are multiplied by IS_REAL to restrict evaluation
		// to real rows, matching go-corset's finite-range semantics.
		isReal := make([]gnark_kb.Element, n)
		for r := uint(0); r < origHeight; r++ {
			isReal[r].SetOne()
		}
		t.SetBase(isRealColName(modName), isReal)
	}
	return t
}

// ====================== Size setting =========================

func setSizes(program *board.Program, tr trace.Trace) {
	moduleSizes := map[string]int{}
	for colName, col := range tr.Base {
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
