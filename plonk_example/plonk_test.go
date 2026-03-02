package plonk_example

import (
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/std"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/giop/viewer"
)

func TestPlonk(t *testing.T) {

	// This would be the result of a tracer in a real life example (here we use gnark as a tracer)
	trace, N, err := GetPlonkTrace()
	if err != nil {
		t.Fatal(nil)
	}

	knowncolumns := make(map[string]bool)
	knowncolumns[ID_L] = true
	knowncolumns[ID_R] = true
	knowncolumns[ID_O] = true
	knowncolumns[ID_Ql] = true
	knowncolumns[ID_Qr] = true
	knowncolumns[ID_Qm] = true
	knowncolumns[ID_Qo] = true
	knowncolumns[ID_Qk] = true
	knowncolumns[ID_ID1] = true
	knowncolumns[ID_ID2] = true
	knowncolumns[ID_ID3] = true
	knowncolumns[ID_S1] = true
	knowncolumns[ID_S2] = true
	knowncolumns[ID_S3] = true

	system := cs.NewSystem(N)

	// This is the result of the constraint (lisp ?) file in a real life example. Here we know in advance the shape of the constraints
	// QL*L + QR*R + QM*L*R + QO*O + QK = 0
	// ( (L, ID1), (R, ID2), (O, ID3)) and ( (L, S1), (R, S2), (O, S3)) must be equal as multisets

	C := sym.NewCommittedColumn(ID_Ql).Mul(sym.NewCommittedColumn(ID_L)).
		Add(sym.NewCommittedColumn(ID_Qr).Mul(sym.NewCommittedColumn(ID_R))).
		Add(sym.NewCommittedColumn(ID_Qm).Mul(sym.NewCommittedColumn(ID_L)).Mul(sym.NewCommittedColumn(ID_R))).
		Add(sym.NewCommittedColumn(ID_Qo).Mul(sym.NewCommittedColumn(ID_O))).
		Add(sym.NewCommittedColumn(ID_Qk))

	system.RegisterConstraint(C)

	multiSetIds1 := [][]string{
		[]string{ID_L, ID_ID1},
		[]string{ID_R, ID_ID2},
		[]string{ID_O, ID_ID3},
	}

	multiSetIds2 := [][]string{
		[]string{ID_L, ID_S1},
		[]string{ID_R, ID_S2},
		[]string{ID_O, ID_S3},
	}

	err = std.MultiSetEqualityUpToPermutationIOP(&system, multiSetIds1, multiSetIds2, "PlonkGrandProduct", "beta", "gamma")
	if err != nil {
		t.Fatal(err)
	}

	cciop := cs.Compile(&system)
	viewer.WriteProverActionsDagToHTML(cciop, "plonk_dag.html")

	proverRunTime := prover.NewRuntime(cciop, trace)
	proof := cs.NewProof(N)

	// Step 1: Solve — compute all intermediate columns (beta, gamma, Z, Z_shifted, LAGRANGE_0)
	viewer.WriteTraceToCSV("trace_0_known.csv", proverRunTime.Trace, N)
	err = proverRunTime.Solve(knowncolumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	viewer.WriteTraceToCSV("trace_1_after_solve.csv", proverRunTime.Trace, N)

	// Step 2: DeriveFinalFoldingChallenge — derive alpha, fold constraints
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	viewer.WriteTraceToCSV("trace_2_after_folding.csv", proverRunTime.Trace, N)

	// Step 3: ComputeQuotient — compute H = C(trace) / (X^N - 1)
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	viewer.WriteTraceToCSV("trace_3_after_quotient.csv", proverRunTime.Trace, N)

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

	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.Verify(&proof)
	if err != nil {
		t.Fatal(err)
	}

}
