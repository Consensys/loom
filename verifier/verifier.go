// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
)

type PublicKey = merkle.Tree

type verifierRunTime struct {
	proof        proof.Proof
	publicInputs map[string]proof.PublicInput
	program      board.Program
	zeta         koalabear.Element
	setup        *PublicKey
	fs           *fiatshamir.Transcript
	friVerifier  fri.Verifier
	vars         map[string]koalabear.Element
}

// Config collects verifier-side protocol parameters. The FRI parameters
// surface as a config floor that the proof's self-described parameters must
// meet (a malicious prover otherwise could lower NumQueries to trivially
// pass the proximity check).
type Config struct {
	// FRIGrindingBits must equal the prover's WithFRIGrindingBits value
	// (default 0 = no grinding).
	FRIGrindingBits int
	// FRIFoldingFactor matches the prover's FoldingFactor (default 8).
	// Tiny modules can use a smaller k; the integration-test wrapper picks
	// k=2 when the largest module's base domain is below the default.
	FRIFoldingFactor int
	// FRIFinalPolynomialMaxLen is an upper bound on the prover's final
	// polynomial size (default 16). The verifier rejects proofs whose
	// FinalPolynomialMaxLen exceeds this.
	FRIFinalPolynomialMaxLen int
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

// WithFRIFoldingFactor configures the verifier's expected FRI folding factor.
// Must match the prover-side value.
func WithFRIFoldingFactor(k int) Option {
	return func(c *Config) error {
		c.FRIFoldingFactor = k
		return nil
	}
}

// WithFRIFinalPolynomialMaxLen sets the verifier's ceiling on the prover's
// final polynomial length. Must equal the prover-side value (or be larger).
func WithFRIFinalPolynomialMaxLen(n int) Option {
	return func(c *Config) error {
		c.FRIFinalPolynomialMaxLen = n
		return nil
	}
}

func newVerifierRuntime(program board.Program, setup *PublicKey, publicInputs map[string]proof.PublicInput, proof proof.Proof, config Config) verifierRunTime {

	res := verifierRunTime{
		proof:        proof,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
		vars:         make(map[string]koalabear.Element),
	}

	res.fs = fiatshamir.NewTranscript(sha256.New())
	friCfg := fri.Config{
		GrindingBits:          config.FRIGrindingBits,
		FoldingFactor:         config.FRIFoldingFactor,
		FinalPolynomialMaxLen: config.FRIFinalPolynomialMaxLen,
	}
	res.friVerifier = fri.NewVerifier(res.fs, friCfg, proof.CommitmentOpenings)

	if setup != nil {
		res.fs.Bind(constants.CanonicalChallengeName(0), res.setup.Root())
	}

	return res
}

func (vr *verifierRunTime) finalCommitmentIndex() int {
	commitmentI := 0
	for i := range vr.program.FScolumnsDependencies {
		if len(vr.program.FScolumnsDependencies[i]) > 0 {
			commitmentI++
		}
	}
	return commitmentI
}

// deriveChallenges re-derives all Fiat-Shamir challenges, advances the FRI
// verifier transcript to match the prover's, derives ζ, and reads all
// AIR-relevant FRI opens via friVerifier.Open in the same deterministic
// order the prover used. Each Open both transcript-binds the claim and
// stores the value in vr.vars for later use by checkAIRRelations.
func (vr *verifierRunTime) deriveChallenges() error {
	numRounds := len(vr.program.FScolumnsDependencies)
	commitmentI := 0

	for i := range numRounds {
		challengeName := constants.CanonicalChallengeName(i)
		if len(vr.program.FScolumnsDependencies[i]) > 0 {
			if commitmentI >= len(vr.proof.CommitmentOpenings.Commitments) {
				return fmt.Errorf("missing commitment transcript entry for %s", challengeName)
			}
			if err := vr.friVerifier.BindCommitment(challengeName); err != nil {
				return err
			}
			commitmentI++
		} else {
			if err := vr.fs.NewChallenge(challengeName); err != nil {
				return err
			}
		}
		bChallenge, err := vr.fs.ComputeChallenge((challengeName))
		if err != nil {
			return err
		}
		var c koalabear.Element
		c.SetBytes(bChallenge)
		vr.vars[challengeName] = c
	}

	finalCommitmentIndex := commitmentI
	if finalCommitmentIndex >= len(vr.proof.CommitmentOpenings.Commitments) {
		return fmt.Errorf("missing commitment for final evaluation point binding")
	}
	if err := vr.friVerifier.BindCommitment(constants.FINAL_EVALUATION_POINT); err != nil {
		return err
	}
	bzeta, err := vr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	vr.zeta.SetBytes(bzeta)

	// Open every AIR-relevant polynomial in the same deterministic order the
	// prover used, transcript-binding the claim and stashing the value for
	// checkAIRRelations.
	if err := vr.openAIRClaims(finalCommitmentIndex); err != nil {
		return err
	}

	return nil
}

// openAIRClaims walks the prover's deterministic Open sequence in lockstep:
// AIR quotient chunks first (sorted module × ascending chunk index), then
// committed/rotated column leaves (sorted module × LeavesFull DAG order,
// duplicate (name, point) pairs skipped). Each friVerifier.Open both binds
// the claim to the transcript and returns the (still-unverified) value,
// which is stored in vr.vars under the appropriate key.
func (vr *verifierRunTime) openAIRClaims(finalCommitmentIndex int) error {
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

	// 1. AIR quotient chunks at ζ.
	for _, moduleName := range sortedModuleNames {
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			if !finalPolyNames[chunkName] {
				break
			}
			y, err := vr.friVerifier.Open(chunkName, vr.zeta)
			if err != nil {
				return err
			}
			vr.vars[chunkName] = y
		}
	}

	// 2. Committed and rotated column leaves.
	leafConfig := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
	type evalKey struct {
		name  string
		point koalabear.Element
	}
	seen := make(map[evalKey]koalabear.Element) // value cached per (name, point) for duplicate leaves

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
			y, hit := seen[key]
			if !hit {
				var err error
				y, err = vr.friVerifier.Open(leaf.Name, evalPoint)
				if err != nil {
					return err
				}
				seen[key] = y
			}
			vr.vars[leaf.String()] = y
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
			var i int
			i = constants.ParseLagrangeName(lag)
			if i < 0 {
				// relative column: stored as -(k+1) where k is the offset from
				// the last row, so absolute position = N-1-k = N + i.
				i = m.N + i
			}
			v := poly.LagrangeAtZeta(vr.zeta, m.N, i)
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
			chunkName := constants.QuotientChunkName(moduleName, i)
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

func Verify(publicInputs map[string]proof.PublicInput, setup *PublicKey, program board.Program, proof proof.Proof, opts ...Option) error {

	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return err
		}
	}

	vr := newVerifierRuntime(program, setup, publicInputs, proof, config)

	// 1 - Re-derive FS challenges; Open every AIR-relevant claim, transcript-
	// binding it and reading its (still-unverified) value into vr.vars.
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

	// 3 - Check bus values (uses public columns only — no opened values).
	if err := vr.checkLogupBus(); err != nil {
		return err
	}

	// 4 - Cryptographically verify the FRI commitment. Any opened value
	// inconsistent with the committed codeword causes rejection here.
	if err := vr.friVerifier.Verify(commitment.LeafHash, commitment.NodeHash); err != nil {
		return err
	}

	// 5 - Check AIR algebraic relations using vr.vars (now FRI-certified).
	if err := vr.checkAIRRelations(); err != nil {
		return err
	}

	return nil
}
