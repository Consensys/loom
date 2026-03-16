package verifier

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	derive "github.com/consensys/loom/internal/derive"
)

// Verifier stores the variables to plug in the final relation to check.
type Verifier struct {
	Vars              map[string]koalabear.Element // values keyed by leaf name
	VanishingRelation dag.DAG
	PublicInputs      derive.PublicInputs
}

// NewRunTime creates the Verifier for the given compiled IOP.
func NewRunTime(cp constraint.Program, publicInputs derive.PublicInputs) Verifier {
	res := Verifier{
		Vars:              make(map[string]koalabear.Element),
		VanishingRelation: cp.VanishingRelation,
		PublicInputs:      publicInputs,
	}
	if res.PublicInputs == nil {
		res.PublicInputs = make(derive.PublicInputs)
	}
	return res
}

// DeriveChallenge derives the challenge for proof.TranscriptRounds[i] by binding the
// batch digest (if the batch is non-empty) and the immediately preceding challenge.
func (runtime *Verifier) DeriveChallenge(proof *derive.Proof, i int) error {

	round := proof.TranscriptRounds[i]

	fs := fiatshamir.NewTranscript(sha256.New())
	if err := fs.NewChallenge(round.ChallengeName); err != nil {
		return err
	}
	if len(proof.BatchColumns[round.DependencyBatch]) > 0 {
		if err := fs.Bind(round.ChallengeName, proof.Batch[round.DependencyBatch].Marshal()); err != nil {
			return err
		}
	}
	if i > 0 {
		prevChallenge, ok := runtime.Vars[proof.TranscriptRounds[i-1].ChallengeName]
		if !ok {
			return fmt.Errorf("challenge %s not yet derived", proof.TranscriptRounds[i-1].ChallengeName)
		}
		if err := fs.Bind(round.ChallengeName, prevChallenge.Marshal()); err != nil {
			return err
		}
	}

	bc, err := fs.ComputeChallenge(round.ChallengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)
	runtime.Vars[round.ChallengeName] = c
	return nil
}

// ComputeChallenges replays the Fiat-Shamir transcript sequentially.
// nbWorkers is accepted for API compatibility but the replay is always sequential.
func (runtime *Verifier) ComputeChallenges(proof *derive.Proof, nbWorkers int) error {
	for i := range proof.TranscriptRounds {
		if err := runtime.DeriveChallenge(proof, i); err != nil {
			return err
		}
	}
	return nil
}

// EvaluateVirtualColumns evaluates the computable columns at zeta and stores the results in runtime.Vars.
func (runtime *Verifier) EvaluateVirtualColumns() error {

	ccLeaves := runtime.VanishingRelation.Leaves(expr.NewConfig(expr.WithoutChallenges(), expr.WithoutCommittedColumns(), expr.WithoutRotatedColumns()))
	ccLeaves = expr.RemoveDuplicates(ccLeaves)

	for _, l := range ccLeaves {
		cc, err := derive.GetComputationableColumn(l)
		if err != nil {
			return err
		}
		runtime.Vars[l] = cc.F(runtime.Vars[constants.FINAL_EVALUATION_POINT])
	}

	return nil
}

// compute \Sigma_i Lagrange_{info.Idx[i]}(zeta*\omega^shift)*info.Vals[i]
func (runtime *Verifier) computeMissingPart(info derive.PublicColumnInfo, shift, N int) (koalabear.Element, error) {

	zeta := runtime.Vars[constants.FINAL_EVALUATION_POINT]

	w, err := koalabear.Generator(uint64(N))
	if err != nil {
		return koalabear.Element{}, err
	}
	if shift != 0 {
		wi := w.Exp(w, big.NewInt(int64(shift)))
		zeta.Mul(&zeta, wi)
	}

	var invN koalabear.Element
	invN.SetUint64(uint64(N)).Inverse(&invN)

	var one, res koalabear.Element
	var zetaN, num koalabear.Element
	one.SetOne()
	zetaN.Exp(zeta, big.NewInt(int64(N)))
	num.Sub(&zetaN, &one).Mul(&num, &invN) // (zeta^N-1)/N
	invZetaMinusOmegai := make([]koalabear.Element, len(info.Idx))
	omegai := make([]koalabear.Element, len(info.Idx))
	for k, idx := range info.Idx {
		omegai[k] = *w.Exp(w, big.NewInt(int64(idx)))
		invZetaMinusOmegai[k].Sub(&zeta, &omegai[k])
	}
	invZetaMinusOmegai = koalabear.BatchInvert(invZetaMinusOmegai)
	var tmp koalabear.Element
	for k := range info.Idx {
		tmp.Mul(&num, &invZetaMinusOmegai[k]).Mul(&tmp, &omegai[k])
		tmp.Mul(&tmp, &info.Vals[k])
		res.Add(&res, &tmp)
	}
	return res, nil
}

// FillClaimedValues fills runtime.Vars with the opening evaluations from the proof.
func (runtime *Verifier) FillClaimedValues(proof *derive.Proof) error {

	for batchIdx, colNames := range proof.BatchColumns {
		if batchIdx >= len(proof.OpeningProofs) {
			break
		}
		op := proof.OpeningProofs[batchIdx]
		for polyIdx, colName := range colNames {
			if polyIdx >= len(op.Shift) {
				continue
			}
			for shiftIdx, shift := range op.Shift[polyIdx] {
				name := constants.GetShiftedName(colName, shift)
				val := op.ClaimedValues[polyIdx][shiftIdx]
				if publicInfo, ok := runtime.PublicInputs[colName]; ok {
					missingPart, err := runtime.computeMissingPart(publicInfo, shift, proof.N)
					if err != nil {
						return err
					}
					val.Add(&val, &missingPart)
				}
				runtime.Vars[name] = val
			}
		}
	}
	return nil
}

// CheckRelation checks the final relation: VanishingRelation(zeta) = H(zeta) · (zeta^N - 1)
func (runtime *Verifier) CheckRelation(proof *derive.Proof) error {

	zeta := runtime.Vars[constants.FINAL_EVALUATION_POINT]

	hzeta, ok := runtime.Vars[constants.FINAL_QUOTIENT]
	if !ok {
		return fmt.Errorf("%s not found in vars", constants.FINAL_QUOTIENT)
	}

	var zetaNMinusOne koalabear.Element
	one := koalabear.One()
	zetaNMinusOne.Set(&zeta).Exp(zetaNMinusOne, big.NewInt(int64(proof.N))).Sub(&zetaNMinusOne, &one)

	vanishingRelationAtZeta := runtime.VanishingRelation.Eval(runtime.Vars)

	hzeta.Mul(&zetaNMinusOne, &hzeta)
	if !vanishingRelationAtZeta.Equal(&hzeta) {
		return fmt.Errorf("algebraic relation does not hold")
	}

	return nil
}

// VerifyOpeningProofs verifies each batch opening proof.
func (runtime *Verifier) VerifyOpeningProofs(proof *derive.Proof) error {
	zeta := runtime.Vars[constants.FINAL_EVALUATION_POINT]
	for batchIdx, batch := range proof.Batch {
		if batchIdx >= len(proof.OpeningProofs) {
			break
		}
		if err := commitment.VerifyBatch(batch, proof.OpeningProofs[batchIdx], zeta); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Verifier) Verify(proof *derive.Proof, nbWorkers int) error {

	if err := runtime.ComputeChallenges(proof, nbWorkers); err != nil {
		return err
	}

	if err := runtime.EvaluateVirtualColumns(); err != nil {
		return err
	}

	if err := runtime.FillClaimedValues(proof); err != nil {
		return err
	}

	if err := runtime.CheckRelation(proof); err != nil {
		return err
	}

	return runtime.VerifyOpeningProofs(proof)
}
