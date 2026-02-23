package std

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

// TestGrandProductIOP embedds BuildGrandProductConstraint in a full protocol (so there are FS interactions + proof build)
// and check that the generated proof passes
func TestPermutation(t *testing.T) {

	// without caching
	{
		size := 16
		S := system.BuildPermutationCircuit(t, size)

		// build a protocol
		prot := protocol.NewProtocol(S)

		// call NewPermutationIOP on "P0" and "P1"
		if err := EqualityUpToPermutation(&prot, []string{"P0"}, []string{"P1"}, "Z", "gamma"); err != nil {
			t.Fatal(err)
		}

		// there should be two constraints in the Constraint registery, and none in the cache
		if len(prot.S.Constraints) != 2 {
			t.Errorf("expected two active constraints, got %d\n", len(prot.S.Constraints))
		}
		if len(prot.S.CachedConstraints) != 0 {
			t.Errorf("expected 0 cached constraints, got %d\n", len(prot.S.Constraints))
		}

		// There are two constraints: grand product constraint, and a lagrange constraint, we need to fold them
		err := prot.FoldConstraints(protocol.FINAL_FOLDING_CHALLENGE)
		if err != nil {
			t.Fatal(err)
		}

		// sanity check
		err = system.BruteForceChecker(prot.S)
		if err != nil {
			t.Fatal(err)
		}

		// finalise the protocol and get the proof
		proof, err := prot.Finalize()
		if err != nil {
			t.Fatal(err)
		}

		// verify the proof
		if err := protocol.Verify(&proof); err != nil {
			t.Fatal(err)
		}
	}

	// with caching
	{
		size := 16
		S := system.BuildPermutationCircuit(t, size)

		// build a protocol
		prot := protocol.NewProtocol(S)

		// call NewPermutationIOP on "P0" and "P1"
		if err := EqualityUpToPermutation(&prot, []string{"P0"}, []string{"P1"}, "Z", "gamma", system.CacheMe()); err != nil {
			t.Fatal(err)
		}

		// there should be 0 constraints in the Constraint registery, and two in the cache
		if len(prot.S.Constraints) != 0 {
			t.Errorf("expected 0 active constraints, got %d\n", len(prot.S.Constraints))
		}
		if len(prot.S.CachedConstraints) != 2 {
			t.Errorf("expected 2 cached constraints, got %d\n", len(prot.S.Constraints))
		}

		// There are two constraints: grand product constraint, and a lagrange constraint, we need to fold them
		err := prot.FoldCachedConstraints(protocol.FINAL_FOLDING_CHALLENGE)
		if err != nil {
			t.Fatal(err)
		}

		// sanity check
		err = system.BruteForceChecker(prot.S)
		if err != nil {
			t.Fatal(err)
		}

		// finalise the protocol and get the proof
		proof, err := prot.Finalize()
		if err != nil {
			t.Fatal(err)
		}

		// verify the proof
		if err := protocol.Verify(&proof); err != nil {
			t.Fatal(err)
		}
	}
}

func getPermutationMultiSet(t *testing.T) system.System {
	const size = 16

	// Build 2 subsets on each side, each with 2 columns.
	// ID1: subsets {A0,A1} and {B0,B1}
	// ID2: subsets {C0,C1} and {D0,D1}
	// (Cx[j], Cy[j]) = (Ax[(j+1)%N], Ay[(j+1)%N]) — cyclic row-shift preserves the tuple multiset.
	makeRandom := func(name string) (univariate.Polynomial, []koalabear.Element) {
		coeffs := make([]koalabear.Element, size)
		for i := range coeffs {
			coeffs[i].SetRandom()
		}
		p, err := univariate.NewInterpolatedPolynomial(coeffs, name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return p, coeffs
	}
	makeShifted := func(name string, src []koalabear.Element) univariate.Polynomial {
		coeffs := make([]koalabear.Element, size)
		for i := range coeffs {
			coeffs[i] = src[(i+1)%size]
		}
		p, err := univariate.NewInterpolatedPolynomial(coeffs, name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return p
	}

	A0, rawA0 := makeRandom("A0")
	A1, rawA1 := makeRandom("A1")
	B0, rawB0 := makeRandom("B0")
	B1, rawB1 := makeRandom("B1")
	C0 := makeShifted("C0", rawA0)
	C1 := makeShifted("C1", rawA1)
	D0 := makeShifted("D0", rawB0)
	D1 := makeShifted("D1", rawB1)

	S := system.NewSystem(
		system.Trace{
			"A0": &A0, "A1": &A1,
			"B0": &B0, "B1": &B1,
			"C0": &C0, "C1": &C1,
			"D0": &D0, "D1": &D1,
		},
		[]system.Constraint{},
		[]system.Constraint{},
		size,
	)
	return S
}

func TestPermutationMultiSet(t *testing.T) {

	// without caching
	{
		S := getPermutationMultiSet(t)

		prot := protocol.NewProtocol(S)

		if err := MultiSetEqualityUpToPermutation(
			&prot,
			[][]string{{"A0", "A1"}, {"B0", "B1"}},
			[][]string{{"C0", "C1"}, {"D0", "D1"}},
			"Z", "alpha", "gamma",
		); err != nil {
			t.Fatal(err)
		}

		// there should be two constraints in the Constraint registery, and none in the cache
		if len(prot.S.Constraints) != 2 {
			t.Errorf("expected two active constraints, got %d\n", len(prot.S.Constraints))
		}
		if len(prot.S.CachedConstraints) != 0 {
			t.Errorf("expected 0 cached constraints, got %d\n", len(prot.S.Constraints))
		}

		// There are two constraints: grand product constraint, and a lagrange constraint, we need to fold them
		err := prot.FoldConstraints(protocol.FINAL_FOLDING_CHALLENGE)
		if err != nil {
			t.Fatal(err)
		}

		// sanity check
		err = system.BruteForceChecker(prot.S)
		if err != nil {
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
		S := getPermutationMultiSet(t)

		prot := protocol.NewProtocol(S)

		if err := MultiSetEqualityUpToPermutation(
			&prot,
			[][]string{{"A0", "A1"}, {"B0", "B1"}},
			[][]string{{"C0", "C1"}, {"D0", "D1"}},
			"Z", "alpha", "gamma",
			system.CacheMe(),
		); err != nil {
			t.Fatal(err)
		}

		// there should be 0 constraints in the Constraint registery, and two in the cache
		if len(prot.S.Constraints) != 0 {
			t.Errorf("expected 0 active constraints, got %d\n", len(prot.S.Constraints))
		}
		if len(prot.S.CachedConstraints) != 2 {
			t.Errorf("expected 2 cached constraints, got %d\n", len(prot.S.Constraints))
		}

		// There are two constraints: grand product constraint, and a lagrange constraint, we need to fold them
		err := prot.FoldCachedConstraints(protocol.FINAL_FOLDING_CHALLENGE)
		if err != nil {
			t.Fatal(err)
		}

		// sanity check
		err = system.BruteForceChecker(prot.S)
		if err != nil {
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
