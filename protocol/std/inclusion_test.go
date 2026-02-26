package std

import (
	"testing"

	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

func TestInclusion(t *testing.T) {

	// without caching
	{
		const size = 16
		S := system.BuildLookupCircuit(t, size)

		prot := protocol.NewProtocol(S)

		if err := InclusionCheckIOP(&prot, "S", "T", "M", "SigmaS", "SigmaT", "gamma"); err != nil {
			t.Fatal(err)
		}

		// BuildGrandSum adds 4 constraints (C1, C2, C3, C4)
		if len(prot.S.Constraints) != 4 {
			t.Errorf("expected 4 active constraints, got %d", len(prot.S.Constraints))
		}
		if len(prot.S.CachedConstraints) != 0 {
			t.Errorf("expected 0 cached constraints, got %d", len(prot.S.CachedConstraints))
		}

		// fold the 4 constraints into 1
		if err := prot.FoldConstraints(protocol.FINAL_FOLDING_CHALLENGE); err != nil {
			t.Fatal(err)
		}

		// sanity check
		if err := system.BruteForceChecker(prot.S); err != nil {
			t.Fatal(err)
		}

		proof, err := prot.Finalize()
		if err != nil {
			t.Fatal(err)
		}

		if err := protocol.Verify(&proof); err != nil {
			t.Fatal(err)
		}
	}

	// with caching
	{
		const size = 16
		S := system.BuildLookupCircuit(t, size)

		prot := protocol.NewProtocol(S)

		if err := InclusionCheckIOP(&prot, "S", "T", "M", "SigmaS", "SigmaT", "gamma", system.CacheMe()); err != nil {
			t.Fatal(err)
		}

		// BuildGrandSum with CacheMe adds 4 cached constraints
		if len(prot.S.Constraints) != 0 {
			t.Errorf("expected 0 active constraints, got %d", len(prot.S.Constraints))
		}
		if len(prot.S.CachedConstraints) != 4 {
			t.Errorf("expected 4 cached constraints, got %d", len(prot.S.CachedConstraints))
		}

		// fold the 4 cached constraints into 1
		if err := prot.FoldCachedConstraints(protocol.FINAL_FOLDING_CHALLENGE); err != nil {
			t.Fatal(err)
		}

		// sanity check
		if err := system.BruteForceChecker(prot.S); err != nil {
			t.Fatal(err)
		}

		proof, err := prot.Finalize()
		if err != nil {
			t.Fatal(err)
		}

		if err := protocol.Verify(&proof); err != nil {
			t.Fatal(err)
		}
	}
}
