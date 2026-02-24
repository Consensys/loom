package std

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

func TestDegreeReduction(t *testing.T) {

	const size = 16

	// generate a high degree constraint like at line 108 of system/columns_test.go:
	// P0 is random, P1[i] = P0[i]^2, so C = P0^4 - P1^2 vanishes on every row.
	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}
	P0, err := univariate.NewInterpolatedPolynomial(coeffs0, "P0")
	if err != nil {
		t.Fatal(err)
	}

	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs1 {
		coeffs1[i].Mul(&coeffs0[i], &coeffs0[i])
	}
	P1, err := univariate.NewInterpolatedPolynomial(coeffs1, "P1")
	if err != nil {
		t.Fatal(err)
	}

	// build a protocol containing the trace (no constraints in it)
	S := system.NewSystem(
		system.Trace{"P0": &P0, "P1": &P1},
		[]system.Constraint{},
		[]system.Constraint{},
		size,
	)
	prot := protocol.NewProtocol(S)

	// call DegreeReductionIOP to register the flattened constraint
	C := sym.NewVar("P0").Pow(4).Sub(sym.NewVar("P1").Pow(2))
	if err := DegreeReductionIOP(&prot, C, 2, "alpha"); err != nil {
		t.Fatal(err)
	}

	// after DegreeReductionIOP there should be exactly one active constraint (the folded one)
	if len(prot.S.Constraints) != 1 {
		t.Fatalf("expected 1 active constraint, got %d", len(prot.S.Constraints))
	}
	if len(prot.S.CachedConstraints) != 0 {
		t.Fatalf("expected 0 cached constraints, got %d", len(prot.S.CachedConstraints))
	}

	// sanity check: the folded constraint vanishes row-by-row
	if err := system.BruteForceChecker(prot.S); err != nil {
		t.Fatal(err)
	}

	// finalise the protocol
	proof, err := prot.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	// verify the proof
	if err := protocol.Verify(&proof); err != nil {
		t.Fatal(err)
	}
}
