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

package zkc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	gnark_kb "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/go-corset/pkg/util/field"
	gocorset_kb "github.com/consensys/go-corset/pkg/util/field/koalabear"
	"github.com/consensys/go-corset/pkg/util/source"
	zkc_compiler "github.com/consensys/go-corset/pkg/zkc/compiler"
	"github.com/consensys/go-corset/pkg/zkc/compiler/codegen"
	zkc_constraints "github.com/consensys/go-corset/pkg/zkc/constraints"
	zkc_util "github.com/consensys/go-corset/pkg/zkc/util"
	zkc_vm "github.com/consensys/go-corset/pkg/zkc/vm"
	"github.com/consensys/loom"
	"github.com/consensys/loom/board"
	gocorset "github.com/consensys/loom/integration_test/go_corset"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/public"
	"github.com/consensys/loom/verifier"
)

var zkcIntegrationCases = []struct {
	name     string
	inputs   []string
	expected zkcExpectedBehavior
}{
	{
		name: "zkc_01",
		inputs: []string{
			`{"data": "0x0000_0001"}`,
			`{"data": "0x0041_0042"}`,
		},
		expected: zkcAllPass,
	},
	{
		name: "zkc_02",
		inputs: []string{
			`{"data": "0x0003_0008"}`,
			`{"data": "0x000f_8000"}`,
		},
		expected: zkcAllPass,
	},
}

type zkcExpectedOutcome uint8

const (
	zkcExpectPass zkcExpectedOutcome = iota
	zkcExpectFail
)

type zkcExpectedBehavior struct {
	Setup    zkcExpectedOutcome
	Prover   zkcExpectedOutcome
	Verifier zkcExpectedOutcome
}

var zkcAllPass = zkcExpectedBehavior{
	Setup:    zkcExpectPass,
	Prover:   zkcExpectPass,
	Verifier: zkcExpectPass,
}

func TestZkcIntegrationFromBinary(t *testing.T) {
	for _, tc := range zkcIntegrationCases {
		t.Run(tc.name, func(t *testing.T) {
			binf := readZkcBinary(t, filepath.Join("testdata", tc.name+".bin"))
			runZkcIntegration(t, binf, tc.inputs, tc.expected)
		})
	}
}

func TestZkcIntegrationFromSource(t *testing.T) {
	for _, tc := range zkcIntegrationCases {
		t.Run(tc.name, func(t *testing.T) {
			binf := compileZkcSource(t, filepath.Join("testdata", tc.name+".zkc"))
			runZkcIntegration(t, binf, tc.inputs, tc.expected)
		})
	}
}

func readZkcBinary(t *testing.T, filename string) *zkc_constraints.BinaryFile[gocorset_kb.Element] {
	t.Helper()

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}

	var binf zkc_constraints.BinaryFile[gocorset_kb.Element]
	if err := binf.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal %s: %v", filename, err)
	}

	return &binf
}

func compileZkcSource(t *testing.T, filename string) *zkc_constraints.BinaryFile[gocorset_kb.Element] {
	return compileZkcSourceWithConfig(t, filename, codegen.DEFAULT_CONFIG.Field(field.KOALABEAR_16))
}

func compileZkcSourceWithConfig(
	t *testing.T,
	filename string,
	config codegen.Config,
) *zkc_constraints.BinaryFile[gocorset_kb.Element] {
	t.Helper()

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}

	srcfile := *source.NewSourceFile(filename, data)
	program, _, syntaxErrors := zkc_compiler.Compile(field.KOALABEAR_16, srcfile)
	if len(syntaxErrors) > 0 {
		t.Fatalf("compile %s: %s", filename, formatSyntaxErrors(syntaxErrors))
	}

	machine, syntaxErrors := program.Compile(config)
	if len(syntaxErrors) > 0 {
		t.Fatalf("codegen %s: %s", filename, formatSyntaxErrors(syntaxErrors))
	}

	return zkc_constraints.NewBinaryFile[gocorset_kb.Element](nil, nil, field.KOALABEAR_16, *machine)
}

func runZkcIntegration(
	t *testing.T,
	binf *zkc_constraints.BinaryFile[gocorset_kb.Element],
	inputs []string,
	expected zkcExpectedBehavior,
) {
	t.Helper()
	validateZkcExpectedBehavior(t, expected)

	airSchema := binf.AirConstraints()
	manifest, err := gocorset.NewZkcManifest(binf)
	if err != nil {
		t.Fatalf("NewZkcManifest: %v", err)
	}

	builder := board.NewBuilder()
	bridge := gocorset.NewCorsetBridge(&builder, &airSchema)
	bridge.SetupModules()
	if err := manifest.ApplyToBridge(bridge); err != nil {
		t.Fatalf("manifest.ApplyToBridge: %v", err)
	}
	gocorset.ScanConstraints(bridge)
	pg, err := board.Compile(bridge.Builder)
	if err != nil {
		t.Fatalf("board.Compile: %v", err)
	}

	const defensivePadding = false
	traceConfig := zkc_constraints.DEFAULT_TRACE_CONFIG.
		WithDefensivePadding(defensivePadding).
		WithParallelism(false)

	for i, rawInput := range inputs {
		input, err := zkc_util.ParseJsonInputFile([]byte(rawInput))
		if err != nil {
			t.Fatalf("input[%d]: %v", i, err)
		}
		traceInput := filterZkcTraceInput(binf, input)
		publicInputs, err := manifest.PublicInputsFromZkcInput(traceInput)
		if err != nil {
			t.Fatalf("public inputs[%d]: %v", i, err)
		}

		expandedTrace, errs := binf.Trace(traceInput, traceConfig)
		if len(errs) > 0 {
			t.Fatalf("trace[%d]: %v", i, errors.Join(errs...))
		}

		loomTrace, err := gocorset.ExpandedTraceToLoom(expandedTrace, &airSchema, defensivePadding)
		if err != nil {
			t.Fatalf("convert trace[%d]: %v", i, err)
		}

		gocorset.SetSize(&pg, loomTrace)
		provingKey, verificationKey, err := loom.Setup(loomTrace, pg)
		if !checkZkcExpectedOutcome(t, "setup", i, err, expected.Setup) {
			continue
		}

		statement := loom.Statement{
			Program:         pg,
			VerificationKey: verificationKey,
			PublicInputs:    publicInputs,
		}
		witness := loom.Witness{Trace: loomTrace, ProvingKey: provingKey}

		prf, err := loom.Prove(statement, witness, prover.SkipFRI())
		if !checkZkcExpectedOutcome(t, "prove", i, err, expected.Prover) {
			continue
		}

		if err := loom.Verify(statement, prf, verifier.SkipFRI()); !checkZkcExpectedOutcome(t, "verify", i, err, expected.Verifier) {
			continue
		}

		if i == 0 {
			badPublicInputs := clonePublicInputs(publicInputs)
			if tamperFirstPublicInput(badPublicInputs) {
				badStatement := statement
				badStatement.PublicInputs = badPublicInputs
				if err := loom.Verify(badStatement, prf, verifier.SkipFRI()); err == nil {
					t.Fatalf("verify[%d]: accepted tampered public input", i)
				}
			}
		}
	}
}

func filterZkcTraceInput(
	binf *zkc_constraints.BinaryFile[gocorset_kb.Element],
	input map[string][]byte,
) map[string][]byte {
	machine := binf.WordMachine()
	filtered := make(map[string][]byte)

	for _, module := range machine.Modules() {
		mem, ok := module.(zkc_vm.InputOutputMemory[zkc_vm.Uint])
		if !ok || !mem.IsReadOnly() || mem.IsStatic() {
			continue
		}
		if value, ok := input[module.Name()]; ok {
			filtered[module.Name()] = value
		}
	}

	return filtered
}

func zkcAirConstraintsIssue(binf *zkc_constraints.BinaryFile[gocorset_kb.Element]) (issue string) {
	defer func() {
		if r := recover(); r != nil {
			issue = fmt.Sprint(r)
		}
	}()

	_ = binf.AirConstraints()
	return ""
}

func validateZkcExpectedBehavior(t *testing.T, expected zkcExpectedBehavior) {
	t.Helper()

	validate := func(name string, outcome zkcExpectedOutcome) {
		t.Helper()
		switch outcome {
		case zkcExpectPass, zkcExpectFail:
		default:
			t.Fatalf("invalid zkc expected outcome for %s: %d", name, outcome)
		}
	}
	validate("setup", expected.Setup)
	validate("prover", expected.Prover)
	validate("verifier", expected.Verifier)

	if expected.Setup == zkcExpectFail && expected.Prover == zkcExpectPass {
		t.Fatalf("invalid zkc expected behavior: prover cannot pass when setup is expected to fail")
	}
	if (expected.Setup == zkcExpectFail || expected.Prover == zkcExpectFail) && expected.Verifier == zkcExpectPass {
		t.Fatalf("invalid zkc expected behavior: verifier cannot pass when an earlier phase is expected to fail")
	}
}

func checkZkcExpectedOutcome(
	t *testing.T,
	phase string,
	inputIdx int,
	err error,
	expected zkcExpectedOutcome,
) bool {
	t.Helper()

	switch expected {
	case zkcExpectPass:
		if err != nil {
			t.Fatalf("%s[%d]: %v", phase, inputIdx, err)
		}
		return true
	case zkcExpectFail:
		if err == nil {
			t.Fatalf("%s[%d]: expected failure", phase, inputIdx)
		}
		return false
	default:
		t.Fatalf("%s[%d]: invalid expected outcome %d", phase, inputIdx, expected)
		return false
	}
}

func formatSyntaxErrors(errs []source.SyntaxError) string {
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, "; ")
}

func clonePublicInputs(inputs public.Inputs) public.Inputs {
	res := make(public.Inputs, len(inputs))
	for name, input := range inputs {
		entries := append([]public.Entry(nil), input.Entries...)
		res[name] = public.Input{Module: input.Module, Entries: entries}
	}
	return res
}

func tamperFirstPublicInput(inputs public.Inputs) bool {
	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)

	one := gnark_kb.One()
	for _, name := range names {
		input := inputs[name]
		if len(input.Entries) == 0 {
			continue
		}
		input.Entries[0].Value.Add(&input.Entries[0].Value, &one)
		input.Entries[0].SetBase(input.Entries[0].Value)
		inputs[name] = input
		return true
	}
	return false
}
