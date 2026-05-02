package verifier

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"slices"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
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
	friVerifier  fri.Verifier
	vars         map[string]koalabear.Element
}

// Config collects verifier-side protocol parameters that must agree with the
// prover's. Mismatches surface as proof rejections.
type Config struct {
	// FRIGrindingBits must equal the prover's WithFRIGrindingBits value
	// (default 0 = no grinding).
	FRIGrindingBits int
}

type Option func(c *Config) error

// WithFRIGrindingBits configures the verifier to require this many leading
// zero bits in the proof's grinding nonce. Must match the prover-side value.
func WithFRIGrindingBits(n int) Option {
	return func(c *Config) error {
		c.FRIGrindingBits = n
		return nil
	}
}

func newVerifierRuntime(program board.Program, publicInputs map[string]proof.PublicInput, proof proof.Proof, config Config) verifierRunTime {

	res := verifierRunTime{
		proof:        proof,
		publicInputs: publicInputs,
		program:      program,
		vars:         make(map[string]koalabear.Element),
	}

	res.fs = fiatshamir.NewTranscript(sha256.New())
	res.friVerifier = fri.NewVerifier(res.fs)
	res.friVerifier.GrindingBits = config.FRIGrindingBits

	return res
}

// deriveChallenges re-derives all Fiat-Shamir challenges, advances the FRI
// verifier transcript to match the prover's, derives ζ, and registers all
// AIR-relevant FRI open requests so that VerifyOpening can reconstruct the
// DEEP-quotient structure.
func (vr *verifierRunTime) deriveChallenges() error {
	numRounds := len(vr.program.FScolumnsDependencies)

	for i := range numRounds {
		challengeName := constants.CanonicalChallengeName(i)
		if i >= len(vr.proof.CommitmentOpenings.Commitments) {
			return fmt.Errorf("missing commitment transcript entry for %s", challengeName)
		}
		if err := vr.friVerifier.Bind(challengeName, vr.proof.CommitmentOpenings.Commitments[i]); err != nil {
			return err
		}
		bChallenge, err := vr.fs.ComputeChallenge((challengeName))
		if err != nil {
			return err
		}
		var c koalabear.Element
		c.SetBytes(bChallenge)
		vr.vars[challengeName] = c
	}

	finalCommitmentIndex := numRounds
	if finalCommitmentIndex >= len(vr.proof.CommitmentOpenings.Commitments) {
		return fmt.Errorf("missing commitment for final evaluation point binding")
	}
	if err := vr.friVerifier.Bind(constants.FINAL_EVALUATION_POINT, vr.proof.CommitmentOpenings.Commitments[finalCommitmentIndex]); err != nil {
		return err
	}
	bzeta, err := vr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	vr.zeta.SetBytes(bzeta)

	// Register all AIR-relevant FRI opens in the same deterministic order the
	// prover used, so that deepPoints indices line up with ClaimedValues.
	if err := vr.registerAIROpens(finalCommitmentIndex); err != nil {
		return err
	}

	return nil
}

// registerAIROpens calls friVerifier.RegisterOpenAt for every open request the
// prover made in ComputeAIRQuotients and ComputeEvaluationsAtZeta, in the same
// deterministic order (sorted module names, chunk index, then leaf DAG order).
func (vr *verifierRunTime) registerAIROpens(finalCommitmentIndex int) error {
	// Build a lookup set of the AIR-quotient oracle's polynomial names.
	finalPolyNames := make(map[string]bool)
	for _, name := range vr.proof.CommitmentOpenings.Commitments[finalCommitmentIndex].PolynomialNames {
		finalPolyNames[name] = true
	}

	sortedModuleNames := make([]string, 0, len(vr.program.Modules))
	for name := range vr.program.Modules {
		sortedModuleNames = append(sortedModuleNames, name)
	}
	slices.Sort(sortedModuleNames)

	// 1. AIR quotient chunks: (moduleName, i) in sorted module × ascending i order.
	for _, moduleName := range sortedModuleNames {
		for i := 0; ; i++ {
			chunkName := fmt.Sprintf("%s_%d", moduleName, i)
			if !finalPolyNames[chunkName] {
				break
			}
			if err := vr.friVerifier.RegisterOpenAt(chunkName, vr.zeta); err != nil {
				return err
			}
		}
	}

	// 2. Committed and rotated column leaves: sorted module names, LeavesFull DAG
	//    order, duplicate (name, evalPoint) pairs skipped.
	leafConfig := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
	type evalKey struct {
		name  string
		point koalabear.Element
	}
	seen := make(map[evalKey]bool)

	for _, moduleName := range sortedModuleNames {
		module := vr.program.Modules[moduleName]
		leaves := module.VanishingRelation.LeavesFull(leafConfig)
		for _, leaf := range leaves {
			evalPoint := vr.zeta
			if leaf.Type == expr.RotatedColumn {
				shift := ((leaf.Shift % module.N) + module.N) % module.N
				var omegaPow koalabear.Element
				omegaPow.SetOne()
				for range shift {
					omegaPow.Mul(&omegaPow, &module.D.Generator)
				}
				evalPoint.Mul(&evalPoint, &omegaPow)
			}
			key := evalKey{leaf.Name, evalPoint}
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := vr.friVerifier.RegisterOpenAt(leaf.Name, evalPoint); err != nil {
				return err
			}
		}
	}

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
		vr.vars[k] = lag
	}
	return nil
}

func (vr *verifierRunTime) computeLagrange() error {
	config := expr.OnlyLagranges
	for _, m := range vr.program.Modules {
		lags := m.VanishingRelation.Leaves(expr.NewConfig(config...))
		for _, lag := range lags {
			if _, ok := vr.vars[lag]; ok {
				continue
			}
			i, N := constants.ParseLagrangeName(lag)
			v := poly.LagrangeAtZeta(vr.zeta, N, i)
			vr.vars[lag] = v
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

// populateAIREvaluations reads the FRI-verified claimed values for all
// AIR-relevant polynomials (quotient chunks and committed/rotated leaves) from
// the opening proof into vr.vars. Must be called after VerifyOpening succeeds.
func (vr *verifierRunTime) populateAIREvaluations() error {
	finalCommitmentIndex := len(vr.program.FScolumnsDependencies)
	finalPolyNames := make(map[string]bool)
	for _, name := range vr.proof.CommitmentOpenings.Commitments[finalCommitmentIndex].PolynomialNames {
		finalPolyNames[name] = true
	}

	sortedModuleNames := make([]string, 0, len(vr.program.Modules))
	for name := range vr.program.Modules {
		sortedModuleNames = append(sortedModuleNames, name)
	}
	slices.Sort(sortedModuleNames)

	// Populate AIR quotient chunk values.
	for _, moduleName := range sortedModuleNames {
		for i := 0; ; i++ {
			chunkName := fmt.Sprintf("%s_%d", moduleName, i)
			if !finalPolyNames[chunkName] {
				break
			}
			val, err := vr.friVerifier.ClaimedValueAt(vr.proof.CommitmentOpenings, chunkName, vr.zeta)
			if err != nil {
				return err
			}
			vr.vars[chunkName] = val
		}
	}

	// Populate committed and rotated column values.
	leafConfig := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
	type evalKey struct {
		name  string
		point koalabear.Element
	}
	seen := make(map[evalKey]bool)

	for _, moduleName := range sortedModuleNames {
		module := vr.program.Modules[moduleName]
		leaves := module.VanishingRelation.LeavesFull(leafConfig)
		for _, leaf := range leaves {
			evalPoint := vr.zeta
			if leaf.Type == expr.RotatedColumn {
				shift := ((leaf.Shift % module.N) + module.N) % module.N
				var omegaPow koalabear.Element
				omegaPow.SetOne()
				for range shift {
					omegaPow.Mul(&omegaPow, &module.D.Generator)
				}
				evalPoint.Mul(&evalPoint, &omegaPow)
			}
			key := evalKey{leaf.Name, evalPoint}
			if seen[key] {
				continue
			}
			seen[key] = true
			val, err := vr.friVerifier.ClaimedValueAt(vr.proof.CommitmentOpenings, leaf.Name, evalPoint)
			if err != nil {
				return err
			}
			vr.vars[leaf.String()] = val
		}
	}

	return nil
}

// checkAIRRelations checks the AIR relations per module using values from vr.vars.
func (vr *verifierRunTime) checkAIRRelations() error {

	for moduleName, m := range vr.program.Modules {

		// Compute Q(zeta) = chunk_0(zeta) + zeta^N * chunk_1(zeta) + zeta^(2N) * chunk_2(zeta) + ...
		var qZeta koalabear.Element
		var zetaPowIN koalabear.Element
		zetaPowIN.SetOne()
		var zetaN koalabear.Element
		zetaN.Exp(vr.zeta, big.NewInt(int64(m.N)))
		for i := 0; ; i++ {
			chunkName := fmt.Sprintf("%s_%d", moduleName, i)
			chunkVal, ok := vr.vars[chunkName]
			if !ok {
				break
			}
			var term koalabear.Element
			term.Mul(&zetaPowIN, &chunkVal)
			qZeta.Add(&qZeta, &term)
			zetaPowIN.Mul(&zetaPowIN, &zetaN)
		}

		// Evaluate the vanishing relation DAG at zeta using vr.vars.
		vZeta := m.VanishingRelation.Eval(vr.vars)

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

func Verify(publicInputs map[string]proof.PublicInput, program board.Program, proof proof.Proof, opts ...Option) error {

	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return err
		}
	}

	vr := newVerifierRuntime(program, publicInputs, proof, config)

	// 1 - Re-derive FS challenges; register AIR FRI opens in deterministic order.
	if err := vr.deriveChallenges(); err != nil {
		return err
	}

	// 2 - Populate vr.vars with public column evaluations and Lagrange values.
	if err := vr.computePublicColumns(); err != nil {
		return err
	}
	if err := vr.computeLagrange(); err != nil {
		return err
	}

	// 3 - Check bus values.
	if err := vr.checkLogupBus(); err != nil {
		return err
	}

	// 4 - Verify FRI opening proofs. This must succeed before we trust any
	// claimed values for the AIR check.
	if err := vr.friVerifier.VerifyOpening(vr.proof.CommitmentOpenings, commitment.LeafHash, commitment.NodeHash); err != nil {
		return err
	}

	// 5 - Read FRI-verified claimed values into vr.vars for AIR checking.
	if err := vr.populateAIREvaluations(); err != nil {
		return err
	}

	// 6 - Check AIR algebraic relations using the now-populated vr.vars.
	if err := vr.checkAIRRelations(); err != nil {
		return err
	}

	return nil
}
