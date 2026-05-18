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

package recursion

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/verifier"
)

func fibonacciProgram(t *testing.T, n int) (board.Program, koalabear.Element, koalabear.Element) {
	t.Helper()

	builder := board.NewBuilder()
	module := board.NewModule("fibonacci")
	module.N = n
	module.AssertZeroExceptAt(expr.Rot("A", 1).Sub(expr.Col("B")), n-1)
	module.AssertZeroExceptAt(expr.Rot("B", 1).Sub(expr.Col("C")), n-1)
	module.AssertZero(expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B")))
	builder.AddModule(module)

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	var a, b koalabear.Element
	b.SetOne()
	return program, a, b
}

func proveFibonacci(t *testing.T, n int) RecursionInput {
	t.Helper()

	program, a, b := fibonacciProgram(t, n)
	tr := prover.TraceFibonacci(n, a, b)
	prf, err := prover.Prove(tr, nil, nil, program, prover.UsePoseidon2())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(nil, nil, program, prf, verifier.UsePoseidon2()); err != nil {
		t.Fatal(err)
	}

	return RecursionInput{Program: program, Proof: prf}
}

func TestProveNextLayerPoseidon2(t *testing.T) {
	input := proveFibonacci(t, 4)

	output, err := ProveNextLayer(input, UsePoseidon2(), SkipOuterFRI())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOutput(output, verifier.UsePoseidon2(), verifier.SkipFRI()); err != nil {
		t.Fatal(err)
	}
}

func TestProveAggregationLayerPoseidon2(t *testing.T) {
	left := proveFibonacci(t, 4)
	right := proveFibonacci(t, 8)

	output, err := ProveAggregationLayer(AggregationInput{Left: left, Right: right}, UsePoseidon2(), SkipOuterFRI())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOutput(output, verifier.UsePoseidon2(), verifier.SkipFRI()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierCoreRejectsBadAIRClaim(t *testing.T) {
	input := proveFibonacci(t, 4)

	one := koalabear.One()
	value, ok := input.Proof.ValuesAtZeta["A"]
	if !ok {
		t.Fatal("expected proof to contain A opening")
	}
	value.B0.A0.Add(&value.B0.A0, &one)
	input.Proof.ValuesAtZeta["A"] = value

	if _, err := ProveNextLayer(input, UsePoseidon2(), WithoutInnerVerification(), SkipOuterFRI()); err == nil {
		t.Fatal("expected recursive verifier core to reject tampered ValuesAtZeta")
	}
}

func TestVerifierCoreRejectsBadFRIBridgeClaim(t *testing.T) {
	input := proveFibonacci(t, 4)

	if len(input.Proof.DeepQuotientFriProof.FRIQueries) == 0 || len(input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers) == 0 {
		t.Fatal("expected proof to contain FRI query layers")
	}

	one := koalabear.One()
	layer := input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[0]
	layer.LeafPExt.B0.A0.Add(&layer.LeafPExt.B0.A0, &one)
	input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[0] = layer

	if _, err := ProveNextLayer(input, UsePoseidon2(), WithoutInnerVerification(), SkipOuterFRI()); err == nil {
		t.Fatal("expected recursive verifier core to reject tampered FRI bridge claim")
	}
}

func TestVerifierCoreRejectsBadFRIFoldClaim(t *testing.T) {
	input := proveFibonacci(t, 4)

	if len(input.Proof.DeepQuotientFriProof.FRIQueries) == 0 || len(input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers) < 2 {
		t.Fatal("expected proof to contain at least two FRI folding layers")
	}

	one := koalabear.One()
	layer := input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[1]
	layer.LeafPExt.B0.A0.Add(&layer.LeafPExt.B0.A0, &one)
	layer.LeafQExt.B0.A0.Add(&layer.LeafQExt.B0.A0, &one)
	input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[1] = layer

	if _, err := ProveNextLayer(input, UsePoseidon2(), WithoutInnerVerification(), SkipOuterFRI()); err == nil {
		t.Fatal("expected recursive verifier core to reject tampered FRI fold claim")
	}
}

func TestPoseidon2MerkleModuleRejectsBadPointSamplingPath(t *testing.T) {
	input := proveFibonacci(t, 4)

	if len(input.Proof.PointSamplings) == 0 ||
		len(input.Proof.PointSamplings[0]) == 0 ||
		len(input.Proof.PointSamplings[0][0].Proof.Siblings) == 0 {
		t.Fatal("expected proof to contain point-sampling Merkle siblings")
	}
	sibling := input.Proof.PointSamplings[0][0].Proof.Siblings[0]
	sibling[len(sibling)-1] ^= 1
	input.Proof.PointSamplings[0][0].Proof.Siblings[0] = sibling

	module, tr, err := buildPoseidon2VerifierModule(
		verifierCoreModule+"_poseidon2_test",
		[]poseidon2MerkleTarget{{Namespace: "bad", Input: input}},
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := board.NewBuilder()
	builder.AddModule(module)
	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}
	prf, err := prover.Prove(tr, nil, nil, program, prover.UsePoseidon2(), prover.SkipFRI())
	if err != nil {
		return
	}
	if err := verifier.Verify(nil, nil, program, prf, verifier.UsePoseidon2(), verifier.SkipFRI()); err == nil {
		t.Fatal("expected Poseidon2 Merkle module to reject tampered sibling")
	}
}

func TestPoseidon2MerkleModuleRejectsBadFRIPath(t *testing.T) {
	input := proveFibonacci(t, 4)

	if len(input.Proof.DeepQuotientFriProof.FRIQueries) == 0 ||
		len(input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers) == 0 ||
		len(input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[0].Path.Siblings) == 0 {
		t.Fatal("expected proof to contain FRI Merkle siblings")
	}
	sibling := input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[0].Path.Siblings[0]
	sibling[len(sibling)-1] ^= 1
	input.Proof.DeepQuotientFriProof.FRIQueries[0].Layers[0].Path.Siblings[0] = sibling

	module, tr, err := buildPoseidon2VerifierModule(
		verifierCoreModule+"_poseidon2_fri_test",
		[]poseidon2MerkleTarget{{Namespace: "bad", Input: input}},
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := board.NewBuilder()
	builder.AddModule(module)
	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}
	prf, err := prover.Prove(tr, nil, nil, program, prover.UsePoseidon2(), prover.SkipFRI())
	if err != nil {
		return
	}
	if err := verifier.Verify(nil, nil, program, prf, verifier.UsePoseidon2(), verifier.SkipFRI()); err == nil {
		t.Fatal("expected Poseidon2 Merkle module to reject tampered FRI sibling")
	}
}
