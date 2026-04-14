package verifier

import (
	"crypto/sha256"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/proof"
)

type verifierRunTime struct {
	proof        proof.Proof
	publicInputs map[string]proof.PublicInput
	program      board.Program
	zeta         koalabear.Element
	fs           *fiatshamir.Transcript
}

func newVerifierRuntime(program board.Program, publicInputs map[string]proof.PublicInput, proof proof.Proof) verifierRunTime {

	res := verifierRunTime{
		proof:        proof,
		publicInputs: publicInputs,
		program:      program,
	}

	res.fs = fiatshamir.NewTranscript(sha256.New())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	return res
}

func (vr *verifierRunTime) deriveChallenges() error {

	// populate proof.ValuesAtZeta with the challenges
	for i, fsi := range vr.proof.FSInputs {
		challengeName := constants.CanonicalChallengeName(i)
		vr.fs.Bind(challengeName, fsi)
		bChallenge, err := vr.fs.ComputeChallenge((challengeName))
		if err != nil {
			return err
		}
		var c koalabear.Element
		c.SetBytes(bChallenge)
		vr.proof.ValuesAtZeta[challengeName] = c
	}
	vr.fs.Bind(constants.FINAL_EVALUATION_POINT, vr.proof.AIRQuotientsCommitment)
	bzeta, err := vr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	vr.zeta.SetBytes(bzeta)

	return nil
}

// checkAIRRelations checks the air
// func (vr *verifierRunTime) checkAIRRelations() error {

// }

func Verify(publicInputs map[string]proof.PublicInput, program board.Program, proof proof.Proof) error {

	vr := newVerifierRuntime(program, publicInputs, proof)

	// 1 - derive the challenges, and populate proof.ValuesAtZeta with those challenges
	for i, r := range proof.FSInputs {
		vr.fs.Bind(constants.CanonicalChallengeName(i), r)
	}

	// 2 - populate the Lagrange columns at zeta

	return nil
}
