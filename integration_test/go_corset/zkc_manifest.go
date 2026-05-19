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
	"fmt"
	"math/big"
	"sort"

	gnark_kb "github.com/consensys/gnark-crypto/field/koalabear"
	corsetmodule "github.com/consensys/go-corset/pkg/schema/module"
	"github.com/consensys/go-corset/pkg/schema/register"
	corsettrace "github.com/consensys/go-corset/pkg/trace"
	gocorset_kb "github.com/consensys/go-corset/pkg/util/field/koalabear"
	zkc_constraints "github.com/consensys/go-corset/pkg/zkc/constraints"
	"github.com/consensys/go-corset/pkg/zkc/vm"
	"github.com/consensys/loom/expr"
	loomfield "github.com/consensys/loom/field"
	"github.com/consensys/loom/public"
)

const zkcPublicInputPrefix = "__public__."

// FrontendManifest carries frontend-level information that is not explicit in
// air.Schema, such as public input memories and static setup tables.
type FrontendManifest struct {
	StaticModules map[string]StaticModule
	PublicInputs  map[string]PublicValueSpec
	PublicOutputs map[string]PublicValueSpec
	ExposedValues map[string]ExposedValueSpec
	TraceModules  map[string]TraceModuleSpec

	publicInputMemories map[string]publicInputMemorySpec
}

// StaticModule describes a fixed table that can be moved to Loom setup.
type StaticModule struct {
	Columns []string
	Values  [][]gnark_kb.Element
}

// PublicValueSpec describes one concrete AIR limb column backing a frontend
// public value. Column is the Loom virtual public-input column name;
// TraceColumn is the committed zkc trace column it must equal on real rows.
type PublicValueSpec struct {
	Module        string
	Column        string
	TraceColumn   string
	Memory        string
	Register      string
	RegisterIndex int
	AddressLine   int
	DataLine      int
	LimbIndex     int
	LimbShift     uint
	LimbWidth     uint
	Field         loomfield.Kind
}

// ExposedValueSpec reserves manifest space for prover-exposed local values.
type ExposedValueSpec struct {
	Module string
	Column string
	Index  int
	Field  loomfield.Kind
}

// TraceModuleSpec records frontend trace-shape metadata.
type TraceModuleSpec struct {
	HasFrontPadding  bool
	DefensivePadding bool
	OriginalName     string
}

type publicInputMemorySpec struct {
	Name             string
	Module           string
	AddressRegisters []register.Register
	DataRegisters    []register.Register
	Specs            []PublicValueSpec
}

// NewZkcManifest builds a manifest from a zkc binary. Public input memories are
// represented as Loom public-input columns with bridge constraints tying them
// to the committed zkc memory trace columns.
func NewZkcManifest(binf *zkc_constraints.BinaryFile[gocorset_kb.Element]) (*FrontendManifest, error) {
	if binf == nil {
		return nil, fmt.Errorf("NewZkcManifest: nil binary file")
	}

	airSchema := binf.AirConstraints()
	limbsMap := binf.LimbsMap()
	manifest := &FrontendManifest{
		StaticModules:       make(map[string]StaticModule),
		PublicInputs:        make(map[string]PublicValueSpec),
		PublicOutputs:       make(map[string]PublicValueSpec),
		ExposedValues:       make(map[string]ExposedValueSpec),
		TraceModules:        make(map[string]TraceModuleSpec),
		publicInputMemories: make(map[string]publicInputMemorySpec),
	}

	for _, mod := range airSchema.Modules().Collect() {
		if mod.Width() == 0 {
			continue
		}
		modName := mod.Name().String()
		manifest.TraceModules[modName] = TraceModuleSpec{
			HasFrontPadding: mod.AllowPadding(),
			OriginalName:    modName,
		}
		if mod.IsStatic() {
			staticModule, err := buildStaticModule(modName, mod.Registers(), mod.StaticContents())
			if err != nil {
				return nil, err
			}
			manifest.StaticModules[modName] = staticModule
		}
	}

	machine := binf.WordMachine()
	for _, mod := range machine.Modules() {
		mem, ok := mod.(vm.InputOutputMemory[vm.Uint])
		if !ok || !mem.IsPublic() {
			continue
		}

		specs, err := zkcMemoryValueSpecs(mem, limbsMap)
		if err != nil {
			return nil, err
		}

		switch {
		case mem.IsReadOnly() && !mem.IsStatic():
			for _, spec := range specs {
				manifest.PublicInputs[spec.Column] = spec
			}
			manifest.publicInputMemories[mem.Name()] = newPublicInputMemorySpec(mem, specs)

		case mem.IsWriteOnly():
			for _, spec := range specs {
				manifest.PublicOutputs[spec.Column] = spec
			}
		}
	}

	return manifest, nil
}

// PublicInputColumnName returns the Loom virtual public-input column for a
// committed zkc trace column.
func PublicInputColumnName(traceColumn string) string {
	return zkcPublicInputPrefix + traceColumn
}

// ApplyToBridge augments a CorsetBridge with manifest-driven bridge metadata
// and constraints.
func (m *FrontendManifest) ApplyToBridge(bridge *CorsetBridge) error {
	if m == nil {
		return nil
	}
	if bridge == nil || bridge.Builder == nil {
		return fmt.Errorf("FrontendManifest.ApplyToBridge: nil bridge")
	}

	staticModules := sortedKeys(m.StaticModules)
	for _, moduleName := range staticModules {
		if _, ok := bridge.Builder.Modules[moduleName]; !ok {
			return fmt.Errorf("FrontendManifest.ApplyToBridge: static module %q not found in builder", moduleName)
		}
		for _, col := range m.StaticModules[moduleName].Columns {
			if !builderHasPublicColumn(bridge, moduleName, col) {
				bridge.Builder.MakeColumnPublic(moduleName, col)
			}
		}
	}

	publicInputs := sortedKeys(m.PublicInputs)
	for _, name := range publicInputs {
		spec := m.PublicInputs[name]
		if spec.Field == loomfield.Ext {
			return fmt.Errorf("FrontendManifest.ApplyToBridge: extension public input %q is not supported", spec.Column)
		}
		if _, ok := bridge.Builder.Modules[spec.Module]; !ok {
			return fmt.Errorf("FrontendManifest.ApplyToBridge: public input module %q not found in builder", spec.Module)
		}
		relation := expr.Col(spec.TraceColumn).Sub(expr.PublicInput(spec.Column))
		relation = relation.Mul(expr.Col(isRealColName(spec.Module)))
		if err := bridge.Builder.AssertZero(spec.Module, relation); err != nil {
			return err
		}
	}

	return nil
}

// PublicInputsFromZkcInput extracts Loom public inputs from the JSON-decoded
// zkc input map. Public zkc input memories are packed byte arrays; their
// addresses are implicit row indices.
func (m *FrontendManifest) PublicInputsFromZkcInput(input map[string][]byte) (public.Inputs, error) {
	res := make(public.Inputs)
	if m == nil {
		return res, nil
	}

	memoryNames := sortedKeys(m.publicInputMemories)
	for _, memoryName := range memoryNames {
		mem := m.publicInputMemories[memoryName]
		raw, ok := input[memoryName]
		if !ok {
			return nil, fmt.Errorf("PublicInputsFromZkcInput: missing public input memory %q", memoryName)
		}
		if len(mem.DataRegisters) == 0 {
			return nil, fmt.Errorf("PublicInputsFromZkcInput: public input memory %q has no data registers", memoryName)
		}

		decoded := vm.DecodeBytes[vm.Uint](raw, mem.DataRegisters)
		if len(decoded)%len(mem.DataRegisters) != 0 {
			return nil, fmt.Errorf(
				"PublicInputsFromZkcInput: public input memory %q decodes to %d values, not a multiple of %d data registers",
				memoryName,
				len(decoded),
				len(mem.DataRegisters),
			)
		}

		rows := len(decoded) / len(mem.DataRegisters)
		for _, spec := range mem.Specs {
			entries := make([]public.Entry, rows)
			for row := range rows {
				value, err := publicInputMemoryValue(mem, decoded, row, spec)
				if err != nil {
					return nil, err
				}
				limb := limbValue(value, spec.LimbShift, spec.LimbWidth)
				var elem gnark_kb.Element
				elem.SetBigInt(limb)
				entries[row].Idx = row
				entries[row].SetBase(elem)
			}
			res[spec.Column] = public.Input{Module: spec.Module, Entries: entries}
		}
	}

	return res, nil
}

func buildStaticModule(
	moduleName string,
	registers []register.Register,
	contents []gocorset_kb.Element,
) (StaticModule, error) {
	width := len(registers)
	if width == 0 {
		return StaticModule{}, nil
	}
	if len(contents)%width != 0 {
		return StaticModule{}, fmt.Errorf(
			"buildStaticModule: static module %q has %d values, not a multiple of width %d",
			moduleName,
			len(contents),
			width,
		)
	}

	columns := make([]string, width)
	for i, reg := range registers {
		columns[i] = qualifyColumnName(moduleName, reg.Name())
	}

	rows := len(contents) / width
	values := make([][]gnark_kb.Element, rows)
	for row := range rows {
		values[row] = make([]gnark_kb.Element, width)
		for col := range width {
			values[row][col] = toGnarkElement(contents[row*width+col])
		}
	}

	return StaticModule{Columns: columns, Values: values}, nil
}

func zkcMemoryValueSpecs(
	mem vm.InputOutputMemory[vm.Uint],
	limbsMap corsetmodule.LimbsMap,
) ([]PublicValueSpec, error) {
	registers := mem.Registers()
	addressLines := int(mem.Geometry().AddressLines())
	dataLines := int(mem.Geometry().DataLines())
	if len(registers) < addressLines+dataLines {
		return nil, fmt.Errorf(
			"zkcMemoryValueSpecs: memory %q has %d registers, expected at least %d address/data registers",
			mem.Name(),
			len(registers),
			addressLines+dataLines,
		)
	}

	moduleMapping, ok := limbModule(limbsMap, mem.Name())
	if !ok {
		return nil, fmt.Errorf("zkcMemoryValueSpecs: memory module %q not found in limb map", mem.Name())
	}

	specs := make([]PublicValueSpec, 0, addressLines+dataLines)
	for i := 0; i < addressLines+dataLines; i++ {
		reg := registers[i]
		if reg.IsNative() {
			return nil, fmt.Errorf("zkcMemoryValueSpecs: memory %q register %q is native", mem.Name(), reg.Name())
		}

		limbIDs := moduleMapping.LimbIds(register.NewId(uint(i)))
		shift := uint(0)
		for limbIndex, limbID := range limbIDs {
			limb := moduleMapping.Limb(limbID)
			traceColumn := qualifyColumnName(mem.Name(), limb.Name())
			spec := PublicValueSpec{
				Module:        mem.Name(),
				Column:        PublicInputColumnName(traceColumn),
				TraceColumn:   traceColumn,
				Memory:        mem.Name(),
				Register:      reg.Name(),
				RegisterIndex: i,
				AddressLine:   -1,
				DataLine:      -1,
				LimbIndex:     limbIndex,
				LimbShift:     shift,
				LimbWidth:     limb.Width(),
				Field:         loomfield.Base,
			}
			if i < addressLines {
				spec.AddressLine = i
			} else {
				spec.DataLine = i - addressLines
			}
			specs = append(specs, spec)
			shift += limb.Width()
		}
	}

	return specs, nil
}

func newPublicInputMemorySpec(
	mem vm.InputOutputMemory[vm.Uint],
	specs []PublicValueSpec,
) publicInputMemorySpec {
	registers := mem.Registers()
	addressLines := int(mem.Geometry().AddressLines())
	dataLines := int(mem.Geometry().DataLines())

	addressRegisters := append([]register.Register(nil), registers[:addressLines]...)
	dataRegisters := append([]register.Register(nil), registers[addressLines:addressLines+dataLines]...)
	specs = append([]PublicValueSpec(nil), specs...)

	return publicInputMemorySpec{
		Name:             mem.Name(),
		Module:           mem.Name(),
		AddressRegisters: addressRegisters,
		DataRegisters:    dataRegisters,
		Specs:            specs,
	}
}

func publicInputMemoryValue(
	mem publicInputMemorySpec,
	decoded []vm.Uint,
	row int,
	spec PublicValueSpec,
) (*big.Int, error) {
	switch {
	case spec.AddressLine >= 0:
		return addressLineValue(row, mem.AddressRegisters, spec.AddressLine)
	case spec.DataLine >= 0:
		idx := row*len(mem.DataRegisters) + spec.DataLine
		if idx < 0 || idx >= len(decoded) {
			return nil, fmt.Errorf("publicInputMemoryValue: data index %d out of bounds for memory %q", idx, mem.Name)
		}
		return decoded[idx].BigInt(), nil
	default:
		return nil, fmt.Errorf("publicInputMemoryValue: spec %q is neither address nor data", spec.Column)
	}
}

func addressLineValue(row int, addressRegisters []register.Register, line int) (*big.Int, error) {
	if row < 0 {
		return nil, fmt.Errorf("addressLineValue: negative row %d", row)
	}
	if line < 0 || line >= len(addressRegisters) {
		return nil, fmt.Errorf("addressLineValue: address line %d out of bounds", line)
	}

	totalWidth := uint(0)
	for _, reg := range addressRegisters {
		if reg.IsNative() {
			return nil, fmt.Errorf("addressLineValue: native address register %q", reg.Name())
		}
		totalWidth += reg.Width()
	}

	index := new(big.Int).SetUint64(uint64(row))
	capacity := new(big.Int).Lsh(big.NewInt(1), totalWidth)
	if index.Cmp(capacity) >= 0 {
		return nil, fmt.Errorf("addressLineValue: row %d does not fit in %d address bits", row, totalWidth)
	}

	shift := uint(0)
	for i := line + 1; i < len(addressRegisters); i++ {
		shift += addressRegisters[i].Width()
	}

	width := addressRegisters[line].Width()
	value := new(big.Int).Rsh(index, shift)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	value.And(value, mask)
	return value, nil
}

func limbValue(value *big.Int, shift, width uint) *big.Int {
	limb := new(big.Int).Rsh(new(big.Int).Set(value), shift)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	limb.And(limb, mask)
	return limb
}

func limbModule(mapping corsetmodule.LimbsMap, moduleName string) (register.LimbsMap, bool) {
	target := corsettrace.ModuleName{Name: moduleName, Multiplier: 1}
	for i := uint(0); i < mapping.Width(); i++ {
		ith := mapping.Module(i)
		if ith.Name() == target {
			return ith, true
		}
	}
	return nil, false
}

func qualifyColumnName(moduleName, registerName string) string {
	if moduleName == "" {
		return registerName
	}
	return moduleName + "." + registerName
}

func builderHasPublicColumn(bridge *CorsetBridge, module, name string) bool {
	for _, ref := range bridge.Builder.PublicColumns {
		if ref.Module == module && ref.Name == name {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
