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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/go-corset/pkg/util/field"
	gocorset_kb "github.com/consensys/go-corset/pkg/util/field/koalabear"
	"github.com/consensys/go-corset/pkg/util/source"
	zkc_compiler "github.com/consensys/go-corset/pkg/zkc/compiler"
	"github.com/consensys/go-corset/pkg/zkc/compiler/codegen"
	zkc_constraints "github.com/consensys/go-corset/pkg/zkc/constraints"
	zkc_util "github.com/consensys/go-corset/pkg/zkc/util"
	"github.com/consensys/loom"
	"github.com/consensys/loom/board"
	gocorset "github.com/consensys/loom/integration_test/go_corset"
)

var zkcIntegrationCases = []struct {
	name   string
	inputs []string
}{
	{
		name: "zkc_01",
		inputs: []string{
			`{"data": "0x0000_0001"}`,
			`{"data": "0x0041_0042"}`,
		},
	},
	{
		name: "zkc_02",
		inputs: []string{
			`{"data": "0x0003_0008"}`,
			`{"data": "0x000f_8000"}`,
		},
	},
}

func TestZkcIntegrationFromBinary(t *testing.T) {
	for _, tc := range zkcIntegrationCases {
		t.Run(tc.name, func(t *testing.T) {
			binf := readZkcBinary(t, filepath.Join("testdata", tc.name+".bin"))
			runZkcIntegration(t, binf, tc.inputs)
		})
	}
}

func TestZkcIntegrationFromSource(t *testing.T) {
	for _, tc := range zkcIntegrationCases {
		t.Run(tc.name, func(t *testing.T) {
			binf := compileZkcSource(t, filepath.Join("testdata", tc.name+".zkc"))
			runZkcIntegration(t, binf, tc.inputs)
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

	machine, syntaxErrors := program.Compile(codegen.DEFAULT_CONFIG.Field(field.KOALABEAR_16))
	if len(syntaxErrors) > 0 {
		t.Fatalf("codegen %s: %s", filename, formatSyntaxErrors(syntaxErrors))
	}

	return zkc_constraints.NewBinaryFile[gocorset_kb.Element](nil, nil, field.KOALABEAR_16, *machine)
}

func runZkcIntegration(
	t *testing.T,
	binf *zkc_constraints.BinaryFile[gocorset_kb.Element],
	inputs []string,
) {
	t.Helper()

	airSchema := binf.AirConstraints()

	builder := board.NewBuilder()
	bridge := gocorset.NewCorsetBridge(&builder, &airSchema)
	bridge.SetupModules()
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

		expandedTrace, errs := binf.Trace(input, traceConfig)
		if len(errs) > 0 {
			t.Fatalf("trace[%d]: %v", i, errors.Join(errs...))
		}

		loomTrace, err := gocorset.ExpandedTraceToLoom(expandedTrace, &airSchema, defensivePadding)
		if err != nil {
			t.Fatalf("convert trace[%d]: %v", i, err)
		}

		gocorset.SetSize(&pg, loomTrace)

		statement := loom.Statement{Program: pg}
		witness := loom.Witness{Trace: loomTrace}

		prf, err := loom.Prove(statement, witness)
		if err != nil {
			t.Fatalf("prove[%d]: %v", i, err)
		}

		if err := loom.Verify(statement, prf); err != nil {
			t.Fatalf("verify[%d]: %v", i, err)
		}
	}
}

func formatSyntaxErrors(errs []source.SyntaxError) string {
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, "; ")
}
