package verifier

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment/fri"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
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
	for i := range numRounds {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	return res
}

func (vr *verifierRunTime) deriveChallenges() error {
	friVerifier := fri.NewVerifier(vr.fs)
	numRounds := len(vr.program.FScolumnsDependencies)

	// populate proof.ValuesAtZeta with the challenges
	for i := range numRounds {
		challengeName := constants.CanonicalChallengeName(i)
		if i >= len(vr.proof.CommitmentOpenings.Commitments) {
			return fmt.Errorf("missing commitment transcript entry for %s", challengeName)
		}
		if err := friVerifier.Bind(challengeName, vr.proof.CommitmentOpenings.Commitments[i]); err != nil {
			return err
		}
		bChallenge, err := vr.fs.ComputeChallenge((challengeName))
		if err != nil {
			return err
		}
		var c koalabear.Element
		c.SetBytes(bChallenge)
		vr.proof.ValuesAtZeta[challengeName] = c
	}
	finalCommitmentIndex := numRounds
	if finalCommitmentIndex >= len(vr.proof.CommitmentOpenings.Commitments) {
		return fmt.Errorf("missing commitment for final evaluation point binding")
	}
	if err := friVerifier.Bind(constants.FINAL_EVALUATION_POINT, vr.proof.CommitmentOpenings.Commitments[finalCommitmentIndex]); err != nil {
		return err
	}
	bzeta, err := vr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	vr.zeta.SetBytes(bzeta)

	return nil
}

func (vr *verifierRunTime) computePublicColumns() error {
	for k, pi := range vr.proof.PublicColumns {
		var lag koalabear.Element
		for _, pe := range pi.Entries {
			tmp := poly.LagrangeAtZeta(vr.zeta, pi.N, pe.Idx)
			tmp.Mul(&tmp, &pe.Value)
			lag.Add(&lag, &tmp)
		}
		vr.proof.ValuesAtZeta[k] = lag
	}
	return nil
}

func (vr *verifierRunTime) computeLagrange() error {
	config := expr.OnlyLagranges
	for _, m := range vr.program.Modules {
		lags := m.VanishingRelation.Leaves(expr.NewConfig(config...))
		for _, lag := range lags {
			_, ok := vr.proof.ValuesAtZeta[lag]
			if ok {
				continue
			}
			i, N := constants.ParseLagrangeName(lag)
			v := poly.LagrangeAtZeta(vr.zeta, N, i)
			vr.proof.ValuesAtZeta[lag] = v
		}
	}
	return nil
}

func (vr *verifierRunTime) checkLogupBus() error {
	for _, bus := range vr.program.LogupBus {
		var cumNegative, cumPositive koalabear.Element
		for _, pos := range bus.Positive {
			if len(vr.proof.PublicColumns[pos].Entries) > 1 {
				return fmt.Errorf("an extracted value from a logup column should have exactly one entry")
			}
			pe := vr.proof.PublicColumns[pos].Entries[0]
			cumPositive.Add(&cumPositive, &pe.Value)
		}
		for _, neg := range bus.Negative {
			if len(vr.proof.PublicColumns[neg].Entries) > 1 {
				return fmt.Errorf("an extracted value from a logup column should have exactly one entry")
			}
			pe := vr.proof.PublicColumns[neg].Entries[0]
			cumNegative.Add(&cumNegative, &pe.Value)
		}
		cumPositive.Sub(&cumPositive, &cumNegative)
		if !cumPositive.IsZero() {
			return fmt.Errorf("the cumulative sums of the bus are not equal")
		}
	}
	return nil
}

// checkAIRRelations checks the air relations per module
func (vr *verifierRunTime) checkAIRRelations() error {

	for moduleName, m := range vr.program.Modules {

		// Compute Q(zeta) = chunk_0(zeta) + zeta^N * chunk_1(zeta) + zeta^(2N) * chunk_2(zeta) + ...
		// The i-th chunk is stored in proof.ValuesAtZeta under the key "moduleName_i".
		var qZeta koalabear.Element
		var zetaPowIN koalabear.Element
		zetaPowIN.SetOne()
		var zetaN koalabear.Element
		zetaN.Exp(vr.zeta, big.NewInt(int64(m.N)))
		for i := 0; ; i++ {
			chunkName := fmt.Sprintf("%s_%d", moduleName, i)
			chunkVal, ok := vr.proof.ValuesAtZeta[chunkName]
			if !ok {
				break
			}
			var term koalabear.Element
			term.Mul(&zetaPowIN, &chunkVal)
			qZeta.Add(&qZeta, &term)
			zetaPowIN.Mul(&zetaPowIN, &zetaN)
		}

		// Compute V(zeta): evaluate the vanishing relation DAG at zeta using ValuesAtZeta.
		vZeta := m.VanishingRelation.Eval(vr.proof.ValuesAtZeta)

		// Check V(zeta) == (zeta^N - 1) * Q(zeta)
		one := koalabear.One()
		var zetaNMinusOne koalabear.Element
		zetaNMinusOne.Sub(&zetaN, &one)
		var rhs koalabear.Element
		rhs.Mul(&zetaNMinusOne, &qZeta)

		if !vZeta.Equal(&rhs) {
			return fmt.Errorf("AIR relation check failed for module %q: V(zeta)=%s != (zeta^N-1)*Q(zeta)=%s", moduleName, vZeta.String(), rhs.String())
		}
	}

	return nil
}

func Verify(publicInputs map[string]proof.PublicInput, program board.Program, proof proof.Proof) error {

	vr := newVerifierRuntime(program, publicInputs, proof)

	// 1 - derive the challenges, and populate proof.ValuesAtZeta with those challenges
	err := vr.deriveChallenges()
	if err != nil {
		return err
	}

	// 2 - populate proof.ValuesAtZeta with the public columns and lagrange columns
	err = vr.computePublicColumns()
	if err != nil {
		return err
	}
	err = vr.computeLagrange()
	if err != nil {
		return err
	}

	// 3 - check bus values
	err = vr.checkLogupBus()
	if err != nil {
		return err
	}

	// 4 - check the AIR relations
	err = vr.checkAIRRelations()
	if err != nil {
		return err
	}

	return nil
}
