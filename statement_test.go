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

package loom_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

func TestStatementWitnessProveVerify(t *testing.T) {
	statement, witness := equalityStatementWitness(t)

	prf, err := loom.Prove(statement, witness, prover.SkipFRI())
	if err != nil {
		t.Fatal(err)
	}
	if err := loom.Verify(statement, prf, verifier.SkipFRI()); err != nil {
		t.Fatal(err)
	}
}

func TestStatementWitnessProveVerifySHA256HashBackend(t *testing.T) {
	statement, witness := equalityStatementWitness(t)
	backend := loom.SHA256HashBackend()

	prf, err := loom.Prove(statement, witness, loom.WithProverHashBackend(backend), prover.SkipFRI())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := prf.HashBackendID, backend.ID; got != want {
		t.Fatalf("proof hash backend = %q, want %q", got, want)
	}
	if err := loom.Verify(statement, prf, loom.WithVerifierHashBackend(backend), verifier.SkipFRI()); err != nil {
		t.Fatal(err)
	}
	if err := loom.Verify(statement, prf, verifier.SkipFRI()); err == nil {
		t.Fatal("expected verifier hash backend mismatch")
	}
}

func TestSetupHashBackendIsUsedByProveAndVerify(t *testing.T) {
	statement, witness := equalityStatementWitness(t)
	builder := board.NewBuilder()
	module := board.NewModule("main")
	module.N = 4
	module.AssertZero(expr.Col("A").Sub(expr.Col("B")))
	builder.AddModule(module)
	builder.MakeColumnPublic("main", "A")
	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}
	statement.Program = program

	backend := loom.SHA256HashBackend()
	pk, vk, err := loom.Setup(witness.Trace, program, loom.WithSetupHashBackend(backend))
	if err != nil {
		t.Fatal(err)
	}
	statement.VerificationKey = vk
	witness.ProvingKey = pk

	prf, err := loom.Prove(statement, witness, prover.SkipFRI())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := prf.HashBackendID, backend.ID; got != want {
		t.Fatalf("proof hash backend = %q, want %q", got, want)
	}
	if err := loom.Verify(statement, prf, verifier.SkipFRI()); err != nil {
		t.Fatal(err)
	}
}

func equalityStatementWitness(t *testing.T) (loom.Statement, loom.Witness) {
	t.Helper()

	builder := board.NewBuilder()
	module := board.NewModule("main")
	module.N = 4
	module.AssertZero(expr.Col("A").Sub(expr.Col("B")))
	builder.AddModule(module)

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	values := make([]koalabear.Element, module.N)
	for i := range values {
		values[i].SetUint64(uint64(i + 1))
	}
	valuesCopy := make([]koalabear.Element, len(values))
	copy(valuesCopy, values)

	tr := trace.New()
	tr.SetBase("A", values)
	tr.SetBase("B", valuesCopy)

	statement := loom.Statement{Program: program}
	witness := loom.Witness{Trace: tr}

	return statement, witness
}
