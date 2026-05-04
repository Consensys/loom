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

package prover

import (
	"crypto/sha256"
	"slices"
	"sync"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/commitment/fri"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Config struct {
	EmulateFS bool
	// FRIGrindingBits is the number of leading zero bits the proof-of-work
	// nonce inside the FRI commitment must satisfy. 0 disables grinding.
	// The verifier must be configured with the same value to accept the proof.
	FRIGrindingBits int
	// FRIFoldingFactor overrides the FRI folding factor k. Default 0 leaves
	// the FRI library default (8) in place. Tiny modules can drop to k=2 or
	// 4 to keep the codeword domain at or above the folding factor without
	// excessive blowup.
	FRIFoldingFactor int
	// FRIFinalPolynomialMaxLen overrides the FRI fold-loop stop threshold.
	// Default 0 leaves the FRI library default (16) in place.
	FRIFinalPolynomialMaxLen int
}

type Option func(c *Config) error

func EmulateFS() Option {
	return func(c *Config) error {
		c.EmulateFS = true
		return nil
	}
}

// WithFRIFoldingFactor overrides the FRI folding factor k (default 8).
// The verifier must be invoked with the matching verifier.WithFRIFoldingFactor.
func WithFRIFoldingFactor(k int) Option {
	return func(c *Config) error {
		c.FRIFoldingFactor = k
		return nil
	}
}

// WithFRIFinalPolynomialMaxLen overrides the FRI fold-loop stop threshold
// (default 16). The verifier must be invoked with a matching ceiling.
func WithFRIFinalPolynomialMaxLen(n int) Option {
	return func(c *Config) error {
		c.FRIFinalPolynomialMaxLen = n
		return nil
	}
}

// WithFRIGrindingBits sets the proof-of-work bit count for the FRI
// commitment scheme. The verifier must be invoked with the matching
// verifier.WithFRIGrindingBits option.
func WithFRIGrindingBits(n int) Option {
	return func(c *Config) error {
		c.FRIGrindingBits = n
		return nil
	}
}

type proverRuntime struct {
	Committer    fri.Committer
	Proof        proof.Proof
	config       Config
	t            trace.Trace
	airTrace     trace.Trace
	publicInputs proof.PublicInputs
	program      board.Program
	zeta         koalabear.Element
	mu           sync.Mutex
	setup        *PublicKey
	fs           *fiatshamir.Transcript
}

func newProverRuntime(t trace.Trace, setup *PublicKey, publicInputs proof.PublicInputs, program board.Program, config Config) proverRuntime {

	res := proverRuntime{
		Proof:        proof.NewProof(),
		config:       config,
		t:            t,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
		airTrace:     make(trace.Trace),
		mu:           sync.Mutex{}, // mutex to protect the trace when reading/writing (in case of parallelisation)
	}

	// initialize FS transcript and pre-register all challenges (challenge@loom_0..n-1 and zeta)
	res.fs = fiatshamir.NewTranscript(sha256.New())

	// Compute the maximum polynomial base-domain size across all modules so that
	// every committed oracle uses the same codeword domain.
	var maxModuleN uint64
	for _, m := range program.Modules {
		if uint64(m.N) > maxModuleN {
			maxModuleN = uint64(m.N)
		}
	}
	friCfg := fri.Config{
		CodewordDomainSize:    fri.DefaultFRIMinBlowupFactor * maxModuleN,
		GrindingBits:          config.FRIGrindingBits,
		FoldingFactor:         config.FRIFoldingFactor,
		FinalPolynomialMaxLen: config.FRIFinalPolynomialMaxLen,
	}

	// Initialize the FRI committer against the same transcript used by the rest
	// of the prover. All oracles are encoded at CodewordDomainSize.
	res.Committer = fri.NewCommitter(res.fs, friCfg, commitment.LeafHash, commitment.NodeHash)

	if setup != nil {
		res.fs.Bind(constants.CanonicalChallengeName(0), res.setup.Root())
	}

	return res
}

func (pr *proverRuntime) ExecuteSteps() error {

	// 1 - for each module in program, execute the list of Gen() functions in GenCol
	for _, m := range pr.program.Modules {
		mCopy := m
		for _, gen := range mCopy.GenCol {
			gen.Gen(pr.t, &mCopy)
		}
	}

	roundIdx := 0

	// 2 - execute the program's Steps level by level
	for _, steps := range pr.program.Steps {
		for _, s := range steps {
			_, ok := s.Ctx.(board.FSCtx)
			if ok {
				challengeName := constants.CanonicalChallengeName(roundIdx)

				// fetch all trace polynomials referred in FScolumnsDependencies[roundIdx]
				deps := pr.program.FScolumnsDependencies[roundIdx]
				polys := make(map[string]poly.Polynomial, len(deps))
				pr.mu.Lock()
				for _, name := range deps {
					polys[name] = pr.t[name]
				}
				pr.mu.Unlock()

				// Commit only when this round introduces new oracle columns.
				// Some compiled FS rounds only advance the outer transcript.
				if len(polys) > 0 {
					if err := pr.Committer.Commit(challengeName, polys); err != nil {
						return err
					}
				} else if !pr.config.EmulateFS {
					if err := pr.fs.NewChallenge(challengeName); err != nil {
						return err
					}
				}

				// derive 'challengeName' using fs, or sample a random element if EmulateFS is set,
				// then store the value in the trace under challengeName as a polynomial of size 1
				var challengeVal koalabear.Element
				if pr.config.EmulateFS {
					challengeVal.MustSetRandom()
				} else {
					challengeBytes, err := pr.fs.ComputeChallenge(challengeName)
					if err != nil {
						return err
					}
					challengeVal.SetBytes(challengeBytes)
				}

				pr.mu.Lock()
				pr.t[challengeName] = []koalabear.Element{challengeVal}
				pr.mu.Unlock()

				roundIdx++

				continue
			}
			err := s.Execute(pr.t, &pr.program, &pr.Proof, &pr.mu)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (pr *proverRuntime) ComputeAIRQuotients() error {

	// 1 - Compute the AIR quotient for each module in the Program.
	// The quotient is written in canonical (coefficient) form, split into chunks
	// of size n, and stored as Lagrange-normal polynomials in a dedicated trace.

	for moduleName, module := range pr.program.Modules {
		// Skip modules with a trivially-zero VanishingRelation (no constraints).
		// The zero polynomial is vacuously divisible by (X^N-1), quotient = 0, nothing to commit.
		if module.VanishingRelation.Degree() <= 0 {
			continue
		}
		// compute quotient: VanishingRelation / (X^n - 1), returned in coset-Lagrange form
		quotient, err := poly.ComputeQuotient(pr.t, *module.VanishingRelation, module.N)
		if err != nil {
			return err
		}

		// convert from coset-Lagrange to standard Lagrange Normal form
		// TODO add a method to convert the quotient to canonical directly
		poly.CosetLagrangeToLagrangeNormal(quotient)

		// convert from Lagrange Normal to canonical (coefficient) form via IFFT
		bigSize := len(quotient)
		bigD := fft.NewDomain(uint64(bigSize))
		bigD.FFTInverse(quotient, fft.DIF)
		utils.BitReverse(quotient) // quotient[k] = k-th coefficient of H

		// split into chunks of size N; convert each chunk back to Lagrange Normal for commitment
		N := module.N
		numChunks := bigSize / N
		for i := range numChunks {
			chunk := make(poly.Polynomial, N)
			copy(chunk, quotient[i*N:(i+1)*N])
			module.D.FFT(chunk, fft.DIF)
			utils.BitReverse(chunk)
			chunkName := constants.QuotientChunkName(moduleName, i)
			pr.airTrace[chunkName] = chunk
		}
	}

	// 2 - commit to the AIR quotient trace
	polysToCommit := make(map[string]poly.Polynomial, len(pr.airTrace))
	for name, p := range pr.airTrace {
		polysToCommit[name] = p
	}
	if err := pr.Committer.Commit(constants.FINAL_EVALUATION_POINT, polysToCommit); err != nil {
		return err
	}

	// 3 - derive zeta using FS (or emulate) after the quotient commitment has
	// already been bound by the FRI committer.
	var zetaVal koalabear.Element
	if pr.config.EmulateFS {
		zetaVal.MustSetRandom()
	} else {
		zetaBytes, err := pr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
		if err != nil {
			return err
		}
		zetaVal.SetBytes(zetaBytes)
	}
	pr.zeta = zetaVal

	// Register FRI opens for each chunk at zeta. Iterate in (module name,
	// chunk index) order so the registration sequence is deterministic and
	// matches the verifier's RegisterOpenAt calls.
	sortedModuleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		sortedModuleNames = append(sortedModuleNames, name)
	}
	slices.Sort(sortedModuleNames)

	for _, moduleName := range sortedModuleNames {
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			if _, ok := pr.airTrace[chunkName]; !ok {
				break
			}
			if _, err := pr.Committer.Open(chunkName, pr.zeta); err != nil {
				return err
			}
		}
	}

	return nil
}

// ComputeEvaluationsAtZeta registers FRI open requests for every committed and
// rotated column appearing in every module's vanishing relation. Iteration is
// in sorted module-name order; duplicate (name, evalPoint) pairs are skipped.
// This makes the Open registration sequence deterministic and identical to the
// verifier's RegisterOpenAt sequence.
func (pr *proverRuntime) ComputeEvaluationsAtZeta() error {

	// only CommittedColumn and RotatedColumn leaves need to be opened
	config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())

	// sort module names for deterministic Open ordering
	moduleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		moduleNames = append(moduleNames, name)
	}
	slices.Sort(moduleNames)

	type evalKey struct {
		name  string
		point koalabear.Element
	}
	seen := make(map[evalKey]bool)

	for _, moduleName := range moduleNames {
		module := pr.program.Modules[moduleName]
		leaves := module.VanishingRelation.LeavesFull(config)
		for _, leaf := range leaves {
			// compute the evaluation point: zeta for committed columns,
			// omega^shift * zeta for rotated columns
			evalPoint := pr.zeta
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

			// Open eagerly evaluates, binds the claim to the transcript, and
			// returns the value (which we discard here — the loom verifier
			// reads the matching claim from the proof).
			if _, err := pr.Committer.Open(leaf.Name, evalPoint); err != nil {
				return err
			}
		}
	}
	return nil
}

func Prove(t trace.Trace, setup *PublicKey, publicInputs proof.PublicInputs, program board.Program, opts ...Option) (proof.Proof, error) {

	var config Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return proof.Proof{}, err
		}
	}

	pr := newProverRuntime(t, setup, publicInputs, program, config)

	// run ExecuteSteps
	if err := pr.ExecuteSteps(); err != nil {
		return proof.Proof{}, err
	}

	// run ComputeAIRQuotients
	if err := pr.ComputeAIRQuotients(); err != nil {
		return proof.Proof{}, err
	}

	// run ComputeEvaluationsAtZeta
	if err := pr.ComputeEvaluationsAtZeta(); err != nil {
		return proof.Proof{}, err
	}

	openingProof, err := pr.Committer.Prove()
	if err != nil {
		return proof.Proof{}, err
	}
	pr.Proof.CommitmentOpenings = openingProof

	return pr.Proof, nil
}
