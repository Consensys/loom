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

package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/recursion"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

func main() {
	left := proveFibonacci(4)
	right := proveFibonacci(8)

	aggregated, err := recursion.ProveAggregationLayer(
		recursion.AggregationInput{Left: left, Right: right},
		recursion.UsePoseidon2(),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := recursion.VerifyOutput(aggregated, verifier.UsePoseidon2()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("aggregated commitments=%d\n", len(aggregated.Proof.Commitments))
}

func proveFibonacci(n int) recursion.RecursionInput {
	program, tr := fibonacciInstance(n)
	prf, err := prover.Prove(tr, nil, nil, program, prover.UsePoseidon2())
	if err != nil {
		log.Fatal(err)
	}
	if err := verifier.Verify(nil, nil, program, prf, verifier.UsePoseidon2()); err != nil {
		log.Fatal(err)
	}
	return recursion.RecursionInput{Program: program, Proof: prf}
}

func fibonacciInstance(n int) (board.Program, trace.Trace) {
	builder := board.NewBuilder()
	module := board.NewModule("fibonacci")
	module.N = n
	module.AssertZeroExceptAt(expr.Rot("A", 1).Sub(expr.Col("B")), n-1)
	module.AssertZeroExceptAt(expr.Rot("B", 1).Sub(expr.Col("C")), n-1)
	module.AssertZero(expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B")))
	builder.AddModule(module)

	program, err := board.Compile(&builder)
	if err != nil {
		log.Fatal(err)
	}

	var a, b koalabear.Element
	b.SetOne()
	return program, prover.TraceFibonacci(n, a, b)
}
