package viz

import (
	"os"
	"testing"

	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/prover"
)

func TestWriteDerivationPlanDagToHTML(t *testing.T) {
	size := 16
	system := constraint.NewBuilder(size, nil)
	if err := arguments.PermutationTuple(
		&system,
		[][]expr.Expr{{expr.Col("P0"), expr.Col("P1")}},
		[][]expr.Expr{{expr.Col("Q0"), expr.Col("Q1")}},
	); err != nil {
		t.Fatal(err)
	}
	cp := system.Compile()

	out := t.TempDir() + "/prover_dag.html"
	if err := WriteDerivationPlanDagToHTML(cp, out); err != nil {
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
	system := constraint.NewBuilder(size, nil)
	arguments.Permutation(&system, []expr.Expr{expr.Col("P0")}, []expr.Expr{expr.Col("P1")})

	cp := system.Compile()
	rt := prover.NewProver(cp, trace, nil)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_permutation.html"
	if err := WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, proof.BatchColumns, out); err != nil {
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
	system := constraint.NewBuilder(size, nil)
	P0 := expr.Col("P0")
	P1 := expr.Col("P1")
	Q0 := expr.Col("Q0")
	Q1 := expr.Col("Q1")
	if err := arguments.PermutationTuple(
		&system,
		[][]expr.Expr{{P0, P1}},
		[][]expr.Expr{{Q0, Q1}},
	); err != nil {
		t.Fatal(err)
	}

	cp := system.Compile()
	rt := prover.NewProver(cp, trace, nil)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true, "Q0": true, "Q1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_multiset.html"
	if err := WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, proof.BatchColumns, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DAG HTML written to %s (%d bytes)", out, len(data))
}
