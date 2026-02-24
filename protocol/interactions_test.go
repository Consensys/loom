package protocol

import (
	"crypto/sha256"
	"fmt"
	"testing"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/system"
)

// GenerateChallenges generate the challenges in the same order of generation than the prover
func generateChallenges(P Proof, fs *fiatshamir.Transcript) ([]koalabear.Element, error) {

	r := make([]koalabear.Element, len(P.Rounds))
	for i := 0; i < len(P.Rounds); i++ {
		err := fs.NewChallenge(P.Rounds[i].ChallengeName)
		if err != nil {
			return nil, err
		}
		for _, d := range P.Rounds[i].Dependencies {
			com, ok := P.OpeningProofs[d]
			if !ok {
				return nil, fmt.Errorf("%s not found in the list of commitments", d)
			}
			err = fs.Bind(P.Rounds[i].ChallengeName, com.Digest.Marshal())
			if err != nil {
				return nil, err
			}
		}
		br, err := fs.ComputeChallenge(P.Rounds[i].ChallengeName)
		if err != nil {
			return nil, err
		}
		r[i].SetBytes(br)
	}
	return r, nil
}

// TestChallengeGeneration checks that the challenge generated on prover and verifier side are the same
func TestChallengeGeneration(t *testing.T) {

	// build a random trace with three polynomials
	size := 16
	T := make(system.Trace)
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
	S := system.System{Trace: T, N: size}

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
	r, err := generateChallenges(prot.P, fs)
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
