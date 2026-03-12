package viz

import (
	"os"
	"testing"

	"github.com/consensys/giop/arguments"
	"github.com/consensys/giop/constraint"
	"github.com/consensys/giop/prover"
)

func TestWriteDerivationPlanDagToHTML(t *testing.T) {
	size := 16
	system := constraint.NewBuilder(size)
	if err := arguments.PermutationMultiset(
		&system,
		[][]string{{"P0", "P1"}},
		[][]string{{"Q0", "Q1"}},
	); err != nil {
		t.Fatal(err)
	}
	cciop := system.Compile()

	out := t.TempDir() + "/prover_dag.html"
	if err := WriteDerivationPlanDagToHTML(cciop, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 100 {
		t.Fatalf("output file is suspiciously small (%d bytes)", len(data))
	}
	t.Logf("Prover actions DAG HTML written to %s (%d bytes)", out, len(data))
}

func TestWriteProofTranscriptRoundsDagToHTML_Permutation(t *testing.T) {
	size := 16
	trace := constraint.BuildPermutationCircuit(t, size)
	system := constraint.NewBuilder(size)
	arguments.Permutation(&system, []string{"P0"}, []string{"P1"})

	cciop := system.Compile()
	rt := prover.NewProver(cciop, trace)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_permutation.html"
	if err := WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 100 {
		t.Fatalf("output file is suspiciously small (%d bytes)", len(data))
	}
	t.Logf("DAG HTML written to %s (%d bytes)", out, len(data))
}

func TestWriteProofTranscriptRoundsDagToHTML_Tuple(t *testing.T) {
	size := 16
	trace := constraint.BuildPermutationTuple(t, size)
	system := constraint.NewBuilder(size)
	if err := arguments.PermutationMultiset(
		&system,
		[][]string{{"P0", "P1"}},
		[][]string{{"Q0", "Q1"}},
	); err != nil {
		t.Fatal(err)
	}

	cciop := system.Compile()
	rt := prover.NewProver(cciop, trace)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true, "Q0": true, "Q1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_multiset.html"
	if err := WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DAG HTML written to %s (%d bytes)", out, len(data))
}
