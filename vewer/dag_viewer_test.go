package viewer

import (
	"os"
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/std"
)

func TestWriteDagToHTML_Permutation(t *testing.T) {
	size := 16
	trace := cs.BuildPermutationCircuit(t, size)
	system := cs.NewSystem(size)
	std.EqualityUpToPermutationIOP(&system, []string{"P0"}, []string{"P1"}, "GrandProduct", "gamma")

	cciop := cs.Compile(&system)
	rt := prover.NewRuntime(cciop, trace)
	proof, err := rt.Prove(map[string]bool{"P0": true, "P1": true}, 1)
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir() + "/dag_permutation.html"
	if err := WriteDagToHTML(proof.Rounds, out); err != nil {
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

func TestWriteDagToHTML_MultiSet(t *testing.T) {
	size := 16
	trace := cs.BuildPermutationMultiSet(t, size)
	system := cs.NewSystem(size)
	if err := std.MultiSetEqualityUpToPermutationIOP(
		&system,
		[][]string{{"P0", "P1"}},
		[][]string{{"Q0", "Q1"}},
		"GrandProduct", "alpha", "gamma",
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
	if err := WriteDagToHTML(proof.Rounds, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DAG HTML written to %s (%d bytes)", out, len(data))
}
