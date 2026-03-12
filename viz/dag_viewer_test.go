package viz

import (
	"os"
	"testing"

	"github.com/consensys/giop/arguments"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/prover"
)

func TestWriteProverActionsDagToHTML(t *testing.T) {
	size := 16
	system := cs.NewBuilder(size)
	if err := arguments.PermutationMultiset(
		&system,
		[][]string{{"P0", "P1"}},
		[][]string{{"Q0", "Q1"}},
	); err != nil {
		t.Fatal(err)
	}
	cciop := cs.Compile(&system)

	out := t.TempDir() + "/prover_dag.html"
	if err := WriteProverActionsDagToHTML(cciop, out); err != nil {
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

func TestWriteProofRoundsDagToHTML_Permutation(t *testing.T) {
	size := 16
	trace := cs.BuildPermutationCircuit(t, size)
	system := cs.NewBuilder(size)
	arguments.Permutation(&system, []string{"P0"}, []string{"P1"})

	cciop := cs.Compile(&system)
	rt := prover.NewRuntime(cciop, trace)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_permutation.html"
	if err := WriteProofRoundsDagToHTML(proof.Rounds, out); err != nil {
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

func TestWriteProofRoundsDagToHTML_Tuple(t *testing.T) {
	size := 16
	trace := cs.BuildPermutationTuple(t, size)
	system := cs.NewBuilder(size)
	if err := arguments.PermutationMultiset(
		&system,
		[][]string{{"P0", "P1"}},
		[][]string{{"Q0", "Q1"}},
	); err != nil {
		t.Fatal(err)
	}

	cciop := cs.Compile(&system)
	rt := prover.NewRuntime(cciop, trace)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true, "Q0": true, "Q1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_multiset.html"
	if err := WriteProofRoundsDagToHTML(proof.Rounds, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DAG HTML written to %s (%d bytes)", out, len(data))
}
