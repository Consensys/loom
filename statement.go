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

package loom

import (
	"bytes"
	"fmt"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/public"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

// Statement contains the verifier-owned public data for one proof instance.
// Proof data produced by the prover, including proof.ExposedValues, does not
// belong here.
type Statement struct {
	Program      board.Program
	SetupRoots   PublicKeyRoots
	PublicInputs PublicInputs
}

// Witness contains prover-owned data used to produce a proof for a Statement.
type Witness struct {
	Trace trace.Trace
	Setup setup.PublicKey
}

type PublicInputs = public.Inputs

// ProverOption configures Prove.
type ProverOption = prover.Option

// VerifierOption configures Verify.
type VerifierOption = verifier.Option

type PublicKey = setup.PublicKey

type PublicKeyRoots = setup.PublicKeyRoots

// Setup produces the Merkle trees of the precommitted columns + their roots.
func Setup(t trace.Trace, program board.Program) (PublicKey, PublicKeyRoots, error) {
	pk, err := setup.Setup(t, program)
	if err != nil {
		return pk, nil, err
	}
	pkRoots := setup.Roots(pk)
	return pk, pkRoots, nil
}

// Prove produces a proof for statement using witness.
func Prove(statement Statement, witness Witness, opts ...ProverOption) (proof.Proof, error) {
	if err := checkSetupRoots(statement.SetupRoots, witness.Setup); err != nil {
		return proof.Proof{}, err
	}
	return prover.Prove(witness.Trace, witness.Setup, statement.PublicInputs, statement.Program, opts...)
}

// Verify checks prf against statement.
func Verify(statement Statement, prf proof.Proof, opts ...VerifierOption) error {
	return verifier.Verify(statement.PublicInputs, statement.SetupRoots, statement.Program, prf, opts...)
}

func checkSetupRoots(statementRoots setup.PublicKeyRoots, witnessSetup setup.PublicKey) error {
	witnessRoots := setup.Roots(witnessSetup)
	if len(statementRoots) != len(witnessRoots) {
		return fmt.Errorf("loom: statement has %d setup roots, witness has %d setup trees", len(statementRoots), len(witnessRoots))
	}
	for i := range statementRoots {
		if !bytes.Equal(statementRoots[i], witnessRoots[i]) {
			return fmt.Errorf("loom: statement setup root %d does not match witness setup root", i)
		}
	}
	return nil
}
