package fibonacci

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/giop/arguments"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/prover"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
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

	// vanishing constraint A + B - C = 0
	system := cs.NewSystem(N)
	colA := sym.NewCommittedColumn("A")
	colB := sym.NewCommittedColumn("B")
	colC := sym.NewCommittedColumn("C")
	C1 := colA.Add(colB).Sub(colC)
	system.AssertZero(C1)

	// Filter1(A)=Filter2(B), Filter1(B)=Filter2(C) where Filter1 = [0,1,1,1...], Filter2 = [1,1,1,...,1,0]
	filter := make([]koalabear.Element, N)
	for i := 1; i < N; i++ {
		filter[i].SetOne()
	}
	system.RegisterProverAction(nil, []string{"F1"}, proveractions.NewBuilderContext(filter))
	F1 := sym.NewCommittedColumn("F1")
	F2 := sym.NewShiftedColumn("F1", 1)
	arguments.ProjectionExpr(&system, colA, colB, F1, F2)
	arguments.ProjectionExpr(&system, colB, colC, F1, F2)

	// A[0]=0, B[0]=1
	system.RegisterithLagrangeColumn(0)
	var zero, one koalabear.Element
	one.SetOne()
	system.AssertZero(cs.BuildLocalRelation(colA, sym.NewConst(zero), 0, N))
	system.AssertZero(cs.BuildLocalRelation(colB, sym.NewConst(one), 0, N))

	cciop := cs.Compile(&system)

	// Now that the system is compiled, fetch the trace and generate the proof

	trace := GetFibonacciTrace(N, "A", "B", "C")
	// viewer.WriteTraceToCSV("fibonacci.csv", trace, N)

	proverRuntime := prover.NewRuntime(cciop, trace)

	knownColumns := make(map[string]bool)
	knownColumns["A"] = true
	knownColumns["B"] = true
	knownColumns["C"] = true

	proof, err := proverRuntime.Prove(knownColumns, 1)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
