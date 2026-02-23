package protocol

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/system"
)

func TestRunLastRound(t *testing.T) {

	const size = 16

	// Build a polynomial P with known values at entries 0, 1, 2.
	var v0, v1, v2 koalabear.Element
	v0.SetUint64(7)
	v1.SetUint64(13)
	v2.SetUint64(42)

	coeffs := make([]koalabear.Element, size)
	for i := range coeffs {
		coeffs[i].SetRandom()
	}
	coeffs[0] = v0
	coeffs[1] = v1
	coeffs[2] = v2

	P, err := univariate.NewInterpolatedPolynomial(coeffs, "P")
	if err != nil {
		t.Fatal(err)
	}

	S := system.System{
		Trace:             map[string]*univariate.Polynomial{"P": &P},
		Constraints:       []system.Constraint{},
		CachedConstraints: []system.Constraint{},
		N:                 size,
	}

	// Build a Protocol around the system.
	prot := NewProtocol(S)

	// Cache three Lagrange constraints via the protocol (ReceiveChallenge commits P
	// and binds it to the folding challenge in the same round).
	if err := system.NewLagrangeConstraint(&prot.S, "P", 0, v0, system.CacheMe()); err != nil {
		t.Fatal(err)
	}
	if err := system.NewLagrangeConstraint(&prot.S, "P", 1, v1, system.CacheMe()); err != nil {
		t.Fatal(err)
	}
	if err := system.NewLagrangeConstraint(&prot.S, "P", 2, v2, system.CacheMe()); err != nil {
		t.Fatal(err)
	}

	// Fold the cached constraints via the protocol so that ReceiveChallenge
	// commits all relevant polynomials and records the round in prot.P.Rounds.
	if err := prot.FoldCachedConstraints("alpha"); err != nil {
		t.Fatal(err)
	}

	if len(prot.S.Constraints) != 1 {
		t.Fatalf("expected 1 constraint after fold, got %d", len(prot.S.Constraints))
	}

	// Run the last round: compute quotient, commit, derive zeta, open everything.
	proof, err := prot.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the proof.
	if err := Verify(&proof); err != nil {
		t.Fatal(err)
	}
}
