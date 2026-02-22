package cs

import (
	"crypto/sha256"
	"testing"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
)

// TestChallengeGeneration checks that the challenge generated on prover and verifier side are the same
func TestChallengeGeneration(t *testing.T) {

	// build a random trace with three polynomials
	size := 16
	T := make(Trace)
	for _, name := range []string{"P1", "P2", "P3"} {
		coeffs := make([]koalabear.Element, size)
		for i := range coeffs {
			coeffs[i].SetRandom()
		}
		p, err := univariate.NewInterpolatedPolynomial(coeffs, name)
		if err != nil {
			t.Fatal(err)
		}
		pp := p
		T[name] = &pp
	}
	S := System{Trace: T, N: size}

	// create a new protocol
	prot := NewProtocol(S)

	// derive challenges using SendMeAChallenge, binding polynomials arbitrarily across rounds
	var q []koalabear.Element

	c, err := prot.SendMeAChallenge([]string{"P1"}, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	q = append(q, c)

	c, err = prot.SendMeAChallenge([]string{"P2", "P3"}, "beta")
	if err != nil {
		t.Fatal(err)
	}
	q = append(q, c)

	c, err = prot.SendMeAChallenge([]string{"P1", "P2"}, "gamma")
	if err != nil {
		t.Fatal(err)
	}
	q = append(q, c)

	// create a fresh Fiat-Shamir transcript and replay the rounds via GenerateChallenges
	fs := fiatshamir.NewTranscript(sha256.New())
	r, err := GenerateChallenges(prot.P, fs)
	if err != nil {
		t.Fatal(err)
	}

	// check that q[i] == r[i] for all i
	if len(q) != len(r) {
		t.Fatalf("expected %d challenges, got %d", len(q), len(r))
	}
	for i := range q {
		if !q[i].Equal(&r[i]) {
			t.Errorf("challenge[%d] mismatch: prover=%s, verifier=%s", i, q[i].String(), r[i].String())
		}
	}
}
