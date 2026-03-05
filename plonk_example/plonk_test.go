package plonk_example

import (
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/std"
	"github.com/consensys/giop/trace"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/giop/viewer"
)

func getKnownColumns(n int) map[string]bool {

	knowncolumns := make(map[string]bool)
	for i := 0; i < n; i++ {
		knowncolumns[ithInstance(ID_L, i)] = true
		knowncolumns[ithInstance(ID_R, i)] = true
		knowncolumns[ithInstance(ID_O, i)] = true
		knowncolumns[ithInstance(ID_Ql, i)] = true
		knowncolumns[ithInstance(ID_Qr, i)] = true
		knowncolumns[ithInstance(ID_Qm, i)] = true
		knowncolumns[ithInstance(ID_Qo, i)] = true
		knowncolumns[ithInstance(ID_Qk, i)] = true
		knowncolumns[ithInstance(ID_ID1, i)] = true
		knowncolumns[ithInstance(ID_ID2, i)] = true
		knowncolumns[ithInstance(ID_ID3, i)] = true
		knowncolumns[ithInstance(ID_S1, i)] = true
		knowncolumns[ithInstance(ID_S2, i)] = true
		knowncolumns[ithInstance(ID_S3, i)] = true
	}
	return knowncolumns
}

func getIthPlonkRelation(n int) cs.Constraint {

	C := sym.NewCommittedColumn(ithInstance(ID_Ql, n)).Mul(sym.NewCommittedColumn(ithInstance(ID_L, n))).
		Add(sym.NewCommittedColumn(ithInstance(ID_Qr, n)).Mul(sym.NewCommittedColumn(ithInstance(ID_R, n)))).
		Add(sym.NewCommittedColumn(ithInstance(ID_Qm, n)).Mul(sym.NewCommittedColumn(ithInstance(ID_L, n))).Mul(sym.NewCommittedColumn(ithInstance(ID_R, n)))).
		Add(sym.NewCommittedColumn(ithInstance(ID_Qo, n)).Mul(sym.NewCommittedColumn(ithInstance(ID_O, n)))).
		Add(sym.NewCommittedColumn(ithInstance(ID_Qk, n)))

	return C
}

func getIthMultiSets(n int) (multiSetIds1 [][]string, multiSetIds2 [][]string) {
	multiSetIds1 = [][]string{
		[]string{ithInstance(ID_L, n), ithInstance(ID_ID1, n)},
		[]string{ithInstance(ID_R, n), ithInstance(ID_ID2, n)},
		[]string{ithInstance(ID_O, n), ithInstance(ID_ID3, n)},
	}

	multiSetIds2 = [][]string{
		[]string{ithInstance(ID_L, n), ithInstance(ID_S1, n)},
		[]string{ithInstance(ID_R, n), ithInstance(ID_S2, n)},
		[]string{ithInstance(ID_O, n), ithInstance(ID_S3, n)},
	}
	return
}

func mergeTrace(t1, t2 trace.Trace) trace.Trace {
	res := make(trace.Trace, len(t1)+len(t2))
	for k, v := range t1 {
		res[k] = v
	}
	for k, v := range t2 {
		res[k] = v
	}
	return res
}

func TestPlonk(t *testing.T) {

	// This would be the result of a tracer in a real life example (here we use gnark as a tracer)
	trace1, N, err := GetIthPlonkTrace(0)
	if err != nil {
		t.Fatal(nil)
	}
	trace2, N, err := GetIthPlonkTrace(1)
	if err != nil {
		t.Fatal(nil)
	}
	trace := mergeTrace(trace1, trace2)

	system := cs.NewSystem(N)

	// This is the result of the constraint (lisp ?) file in a real life example. Here we know in advance the shape of the constraints
	// QL*L + QR*R + QM*L*R + QO*O + QK = 0
	// ( (L, ID1), (R, ID2), (O, ID3)) and ( (L, S1), (R, S2), (O, S3)) must be equal as multisets

	{
		C := getIthPlonkRelation(0)
		system.RegisterConstraint(C)
		multiSetIds1, multiSetIds2 := getIthMultiSets(0)
		err = std.MultiSetEqualityUpToPermutationIOP(&system, multiSetIds1, multiSetIds2)
		if err != nil {
			t.Fatal(err)
		}
	}
	{
		C := getIthPlonkRelation(1)
		system.RegisterConstraint(C)
		multiSetIds1, multiSetIds2 := getIthMultiSets(1)
		err = std.MultiSetEqualityUpToPermutationIOP(&system, multiSetIds1, multiSetIds2)
		if err != nil {
			t.Fatal(err)
		}
	}

	cciop := cs.Compile(&system)

	proverRunTime := prover.NewRuntime(cciop, trace)
	proof := cs.NewProof(N)

	// Step 1: Solve — compute all intermediate columns (beta, gamma, Z, Z_shifted, LAGRANGE_0)
	knowncolumns := getKnownColumns(2)
	err = proverRunTime.Solve(knowncolumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: DeriveFinalFoldingChallenge — derive alpha, fold constraints
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: ComputeQuotient — compute H = C(trace) / (X^N - 1)
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}

	// Step 4: DeriveOpeningChallenge — derive zeta
	zeta, err := proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}

	// Step 5: OpenCommitments — evaluate all polynomials at zeta
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	viewer.WriteProofRoundsDagToHTML(proof.Rounds, "dag.html")

	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}

}
