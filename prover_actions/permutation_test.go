package proveractions

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/consensys/giop/trace"
)

func TestPermutationGeneration(t *testing.T) {
	const N = 16

	// create a random permutation S of 32 elements (0..31 in random order)
	S := make([]int64, 2*N)
	for i := range S {
		S[i] = int64(i)
	}
	rand.Shuffle(len(S), func(i, j int) { S[i], S[j] = S[j], S[i] })

	permStepContext := PermutationContext{S: S}

	// build a trace and call ComputePermutationColumns with proof.N=16, outputs "P1" and "P2"
	tr := make(trace.Trace)
	proof := NewProof(N)
	mu := &sync.Mutex{}

	idChunks := []string{
		GetPermutationSupportID(0),
		GetPermutationSupportID(1),
	}
	outputs := append(idChunks, "P1", "P2")
	err := ComputePermutationColumns(tr, &proof, mu, nil, outputs, permStepContext)
	if err != nil {
		t.Fatalf("ComputePermutationColumns failed: %v", err)
	}

	// check that the trace contains 4 columns: ID_0, ID_1, P1, P2
	if len(tr) != 4 {
		t.Fatalf("expected 4 columns in trace, got %d", len(tr))
	}
	for _, name := range []string{"ID_0", "ID_1", "P1", "P2"} {
		if _, ok := tr[name]; !ok {
			t.Fatalf("column %q missing from trace", name)
		}
	}

	// check that (P1 || P2) = S(ID_0 || ID_1):
	// for each index i in 0..31, the i-th element of (P1||P2) must equal
	// the S[i]-th element of (ID_0||ID_1)
	chunks := []string{"P1", "P2"}
	for i := 0; i < 2*N; i++ {
		gotChunk, gotIdx := i/N, i%N
		got := tr[chunks[gotChunk]][gotIdx]

		si := S[i]
		wantChunk, wantIdx := si/N, si%N
		want := tr[idChunks[wantChunk]][wantIdx]

		if got != want {
			t.Errorf("index %d (S[%d]=%d): got %v, want %v", i, i, si, got, want)
		}
	}
}
