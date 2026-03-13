package fibonacci

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/viz"
)

func TestFibonacci(t *testing.T) {

	N := 16

	// characterizing the fact that the columns A, B, C are the steps of a Fibo sequence
	// is captured by the following constraints (this is completely arbitrary, there are other ways to shape the trace):
	// 1. A + B - C = 0 (it means that row wise: a + b = c)
	// 2. 	* Filter1(A)=Filter2(B),
	// 		* Filter1(B)=Filter2(C)
	// where Filter1 = [0,1,1,1...], Filter2 = [1,1,1,...,1,0]
	// -> it means [* fn+1 fn+2] at row i is correctly reported to [fn+1 fn+2 *] at row i+1
	// 3. A[0]=0, B[0]=1

	var a, b koalabear.Element
	a.SetRandom()
	b.SetRandom()
	publicInputs := make(proof.PublicInputs)
	publicInputs["A"] = proof.PublicColumnInfo{Idx: []int{0}, Vals: []koalabear.Element{koalabear.Element{}}}
	publicInputs["B"] = proof.PublicColumnInfo{Idx: []int{0}, Vals: []koalabear.Element{koalabear.One()}}

	// vanishing constraint A + B - C = 0
	system := constraint.NewBuilder(N, publicInputs)
	colA := expr.Col("A")
	colB := expr.Col("B")
	colC := expr.Col("C")
	C1 := colA.Add(colB).Sub(colC)
	system.AssertZero(C1)

	// Filter1(A)=Filter2(B), Filter1(B)=Filter2(C) where Filter1 = [0,1,1,1...], Filter2 = [1,1,1,...,1,0]
	filter := make([]koalabear.Element, N)
	for i := 1; i < N; i++ {
		filter[i].SetOne()
	}
	system.AddColumn("F1", filter)
	F1 := expr.Col("F1")
	F2 := expr.Rot("F1", 1)
	arguments.Projection(&system, colA, F1, colB, F2)
	arguments.Projection(&system, colB, F1, colC, F2)

	// A[0]=0, B[0]=1
	// system.AddLagrangeColumn(0)
	// var zero, one koalabear.Element
	// one.SetOne()
	// system.AssertZero(constraint.BuildLocalRelation(colA, expr.Const(zero), 0, N))
	// system.AssertZero(constraint.BuildLocalRelation(colB, expr.Const(one), 0, N))

	cp := system.Compile()

	// Now that the system is compiled, fetch the trace and generate the proof

	trace := GetFibonacciTrace(N, "A", "B", "C")
	// viewer.WriteTraceToCSV("fibonacci.csv", trace, N)

	proof, err := loom.Prove(cp, trace, publicInputs, 1)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	viz.WriteTraceToCSV("fibonacci.csv", trace, proof.N)
	viz.WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, "transcript_rounds.html")
	viz.WriteDerivationPlanDagToHTML(cp, "derivation_plan.html")

	// verifierRunTime := verifier.NewRunTime(cp)
	err = loom.Verify(cp, &proof, publicInputs, 1)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
