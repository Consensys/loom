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
	"fmt"
	"sort"
	"sync"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Config struct {
	EmulateFS bool
}

type Option func(c *Config) error

func EmulateFS() Option {
	return func(c *Config) error {
		c.EmulateFS = true
		return nil
	}
}

type proverRuntime struct {
	Committer      commitment.RSCommit
	friParams      fri.Params
	Proof          proof.Proof
	config         Config
	tTrees         []commitment.WMerkleTree
	airTree        commitment.WMerkleTree
	deepTree       commitment.WMerkleTree
	t              trace.Trace
	airTrace       trace.Trace
	publicInputs   proof.PublicInputs
	program        board.Program
	zeta           koalabear.Element
	mu             sync.Mutex
	setup          PublicKey
	queryPositions []int
	fs             *fiatshamir.Transcript
}

func newProverRuntime(t trace.Trace, setup PublicKey, publicInputs proof.PublicInputs, program board.Program, config Config) (proverRuntime, error) {

	res := proverRuntime{
		Proof:        proof.NewProof(),
		config:       config,
		t:            t,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
		tTrees:       make([]commitment.WMerkleTree, 0, len(program.FScolumnsDependencies)),
		airTrace:     make(trace.Trace),
		mu:           sync.Mutex{}, // mutex to protect the trace when reading/writing (in case of parallelisation)
	}

	res.Proof.PointSamplings = make([][]commitment.WMerkleProof, constants.NUM_QUERIES)
	for i := 0; i < constants.NUM_QUERIES; i++ {
		res.Proof.PointSamplings[i] = make([]commitment.WMerkleProof, 0, len(program.FScolumnsDependencies)+2) // setup + air quotients + FScolumnsDependencies
	}

	// find the largest module size N in program and populate the Committer
	maxN := 0
	for _, m := range program.Modules {
		if m.N > maxN {
			maxN = m.N
		}
	}
	fmt.Printf("[PROVER] %d\n", maxN)

	var err error
	res.friParams, err = fri.NewParams(int(constants.RATE)*maxN, maxN, constants.NUM_QUERIES, commitment.LeafHash, commitment.NodeHash)
	if err != nil {
		return res, err
	}

	res.queryPositions = make([]int, constants.NUM_QUERIES)

	res.Committer = commitment.NewRSCommit(uint64(maxN), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)

	// initialize FS transcript and pre-register all challenges (challenge@loom_0..n-1 and zeta)
	res.fs = fiatshamir.NewTranscript(sha256.New())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	if setup.Tree != nil {
		res.fs.Bind(constants.CanonicalChallengeName(0), res.setup.Root())
	}

	return res, nil
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
				polys := make([]poly.Polynomial, len(deps))
				pr.mu.Lock()
				for i, name := range deps {
					polys[i] = pr.t[name]
				}
				pr.mu.Unlock()

				// commit to them using RSCommit
				tree, err := pr.Committer.Commit(polys)
				if err != nil {
					return err
				}
				commitRoot := tree.Root()
				pr.tTrees = append(pr.tTrees, tree)

				// store the commitment in proof.TraceCommitments[roundIdx], bind it to challengeName in fs
				pr.Proof.TraceCommitments = append(pr.Proof.TraceCommitments, commitRoot)
				if err := pr.fs.Bind(challengeName, commitRoot); err != nil {
					return err
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
	// We also keep a map from chunk name to its domain for later evaluation at zeta.
	chunkDomains := make(map[string]*fft.Domain)

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
		for i := 0; i < numChunks; i++ {
			chunk := make(poly.Polynomial, N)
			copy(chunk, quotient[i*N:(i+1)*N])
			module.D.FFT(chunk, fft.DIF)
			utils.BitReverse(chunk)
			chunkName := constants.QuotientChunkName(moduleName, i)
			pr.airTrace[chunkName] = chunk
			chunkDomains[chunkName] = module.D
		}
	}

	// 2 - commit to the AIR quotient trace
	polysToCommit := make([]poly.Polynomial, 0, len(pr.airTrace))
	for _, p := range pr.airTrace {
		polysToCommit = append(polysToCommit, p)
	}
	tree, err := pr.Committer.Commit(polysToCommit)
	if err != nil {
		return err
	}
	pr.Proof.AIRQuotientsCommitment = tree.Root()
	pr.airTree = tree

	// 3 - derive zeta using FS (or emulate), bind to the AIR quotient commitment
	if err := pr.fs.Bind(constants.FINAL_EVALUATION_POINT, pr.Proof.AIRQuotientsCommitment); err != nil {
		return err
	}

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

	// evaluate each quotient chunk at zeta and store in ValuesAtZeta
	for chunkName, chunkPoly := range pr.airTrace {
		pr.Proof.ValuesAtZeta[chunkName] = poly.Evaluate(chunkPoly, chunkDomains[chunkName], pr.zeta)
	}

	return nil
}

// ComputeEvaluationsAtZeta computes the evaluations at zeta of every polynomial
// appearing in every vanishing relation of every module.
func (pr *proverRuntime) ComputeEvaluationsAtZeta() error {

	// only CommittedColumn and RotatedColumn leaves need to be opened
	config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())

	for _, module := range pr.program.Modules {
		leaves := module.VanishingRelation.LeavesFull(config)
		for _, leaf := range leaves {
			// compute the evaluation point: zeta for committed columns,
			// omega^shift * zeta for rotated columns
			evalPoint := pr.zeta
			if leaf.Type == expr.RotatedColumn {
				shift := ((leaf.Shift % module.N) + module.N) % module.N
				var omegaPow koalabear.Element
				omegaPow.SetOne()
				for k := 0; k < shift; k++ {
					omegaPow.Mul(&omegaPow, &module.D.Generator)
				}
				evalPoint.Mul(&evalPoint, &omegaPow)
			}

			// fetch the polynomial from the trace using the leaf's bare name
			p, ok := pr.t[leaf.Name]
			if !ok {
				return fmt.Errorf("ComputeEvaluationsAtZeta: column %q not found in trace", leaf.Name)
			}

			// evaluate using poly.Evaluate (Lagrange interpolation on module.D)
			val := poly.Evaluate(p, module.D, evalPoint)

			// store result using leaf.String() as key
			pr.Proof.ValuesAtZeta[leaf.String()] = val
		}
	}
	return nil
}

func (pr *proverRuntime) ComputeDeepQuotient() error {

	// sort modules by N in decreasing order
	sortedModule := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		sortedModule = append(sortedModule, name)
	}
	sort.Slice(sortedModule, func(i, j int) bool {
		return pr.program.Modules[sortedModule[i]].N > pr.program.Modules[sortedModule[j]].N
	})

	// for now we emulate the folding challenge
	var alpha koalabear.Element
	alpha.MustSetRandom()

	// deepQuotient result -> it is equal to \sum_i \alpha^i (C(zeta*omega^shift)-C)/(zeta*omega^shift-X))
	// the columns C are fetched from the vanishing relation of the modules, shift!=0 according to the column being
	// rotated or not
	maxN := pr.program.Modules[sortedModule[0]].N
	largestD := pr.program.Modules[sortedModule[0]].D
	deepQuotient := make([]koalabear.Element, maxN) // largest N

	var alphaAcc koalabear.Element
	alphaAcc.SetOne()

	// loop through sortedModule, get the corresponding module
	for _, moduleName := range sortedModule {
		module := pr.program.Modules[moduleName]
		N := module.N

		// 1 - get the RotatedColumn and CommittedColumn from the module's vanishing relation
		config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
		leaves := module.VanishingRelation.LeavesFull(config)

		// 2 - group columns by normalized shift; deduplicate by leaf.String()
		// Each entry carries the bare column name (for trace lookup) and the original
		// leaf.String() key (for ValuesAtZeta lookup, which preserves the raw shift).
		type colEntry struct {
			name string // bare column name → key in pr.t
			key  string // leaf.String() → key in ValuesAtZeta
		}
		byShift := map[int][]colEntry{} // normalized shift → entries
		seenKey := map[string]bool{}    // deduplicate by leaf.String()
		for _, leaf := range leaves {
			k := leaf.String()
			if seenKey[k] {
				continue
			}
			seenKey[k] = true
			normalizedShift := 0
			if leaf.Type == expr.RotatedColumn {
				normalizedShift = ((leaf.Shift % N) + N) % N
			}
			byShift[normalizedShift] = append(byShift[normalizedShift], colEntry{name: leaf.Name, key: k})
		}
		// store shifts sorted in increasing order
		shifts := make([]int, 0, len(byShift))
		for s := range byShift {
			shifts = append(shifts, s)
		}
		sort.Ints(shifts)

		// 3 - for each shift in 'sorted' (looped through in increasing order), fold the corresponding columns in the trace
		// using alpha to build C_shift := \sum_i \alpha^i C
		// compute C_shift_deep := (C_shift(\omega^shift * zeta)-C_shift)/(omega^shift*zeta - X) using synthetic division
		for _, shift := range shifts {

			// evaluation point z_s = omega^shift * zeta
			var omegaShift koalabear.Element
			omegaShift.SetOne()
			for k := 0; k < shift; k++ {
				omegaShift.Mul(&omegaShift, &module.D.Generator)
			}
			var z_s koalabear.Element
			z_s.Mul(&pr.zeta, &omegaShift)

			// fold: C_s(X) = sum_i alphaAcc_i * C_i(X), v_s = C_s(z_s) = sum_i alphaAcc_i * C_i(z_s)
			C_s := make(poly.Polynomial, N)
			var v_s koalabear.Element
			for _, entry := range byShift[shift] {
				col := pr.t[entry.name]
				evalAtZ, ok := pr.Proof.ValuesAtZeta[entry.key]
				if !ok {
					return fmt.Errorf("ComputeDeepQuotient: %q not found in ValuesAtZeta", entry.key)
				}
				for j := 0; j < N; j++ {
					var term koalabear.Element
					if len(col) == 1 {
						term = col[0] // constant polynomial
					} else {
						term = col[j]
					}
					term.Mul(&term, &alphaAcc)
					C_s[j].Add(&C_s[j], &term)
				}
				var term koalabear.Element
				term.Mul(&evalAtZ, &alphaAcc)
				v_s.Add(&v_s, &term)
				alphaAcc.Mul(&alphaAcc, &alpha)
			}

			// compute DQ_s = (v_s - C_s(X)) / (z_s - X) via synthetic division
			DQ_s := poly.DeepQuotient(C_s, v_s, z_s, module.D)

			// accumulate into deepQuotient; extend to maxN domain if this module is smaller
			if N == maxN {
				for j := 0; j < N; j++ {
					deepQuotient[j].Add(&deepQuotient[j], &DQ_s[j])
				}
			} else {
				// IFFT DQ_s to canonical (natural order), zero-pad to maxN, FFT to largest domain
				module.D.FFTInverse(DQ_s, fft.DIF)
				utils.BitReverse(DQ_s)
				extended := make(poly.Polynomial, maxN)
				copy(extended, DQ_s)
				// largestD := fft.NewDomain(uint64(maxN))
				largestD.FFT(extended, fft.DIF)
				utils.BitReverse(extended)
				for j := 0; j < maxN; j++ {
					deepQuotient[j].Add(&deepQuotient[j], &extended[j])
				}
			}
		}
	}

	// Compute the AIR quotient shares of the DEEP ComputeDeepQuotient
	// 1- loop through the modules in the program (in the order given by sortedModule)
	// 2- add the contribution of each quotient shares for the given module (ordered by share 0, then share 1, etc...) to the deep quotient
	for _, moduleName := range sortedModule {
		module := pr.program.Modules[moduleName]
		N := module.N

		C_s := make(poly.Polynomial, N)
		var v_s koalabear.Element
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			chunk, ok := pr.airTrace[chunkName]
			if !ok {
				break
			}
			evalAtZ := pr.Proof.ValuesAtZeta[chunkName]
			for j := 0; j < N; j++ {
				var term koalabear.Element
				term.Mul(&chunk[j], &alphaAcc)
				C_s[j].Add(&C_s[j], &term)
			}
			var term koalabear.Element
			term.Mul(&evalAtZ, &alphaAcc)
			v_s.Add(&v_s, &term)
			alphaAcc.Mul(&alphaAcc, &alpha)
		}

		DQ_air := poly.DeepQuotient(C_s, v_s, pr.zeta, module.D)

		if N == maxN {
			for j := 0; j < N; j++ {
				deepQuotient[j].Add(&deepQuotient[j], &DQ_air[j])
			}
		} else {
			module.D.FFTInverse(DQ_air, fft.DIF)
			utils.BitReverse(DQ_air)
			extended := make(poly.Polynomial, maxN)
			copy(extended, DQ_air)
			largestD.FFT(extended, fft.DIF)
			utils.BitReverse(extended)
			for j := 0; j < maxN; j++ {
				deepQuotient[j].Add(&deepQuotient[j], &extended[j])
			}
		}
	}

	deepQuotientTree, err := pr.Committer.Commit([]poly.Polynomial{deepQuotient})
	if err != nil {
		return fmt.Errorf("pr.Committer.Commit: %v", err)
	}
	pr.Proof.DeepQuotientCommitment = deepQuotientTree.Root()
	deepQuotient, err = pr.friParams.Encode(deepQuotient)
	if err != nil {
		return fmt.Errorf("pr.friParams.Encode: %v", err)
	}
	pr.Proof.DeepQuotientFriProof, pr.queryPositions, err = fri.Prove(pr.friParams, deepQuotient, pr.fs)
	if err != nil {
		return fmt.Errorf("fri.Prove: %v", err)
	}

	return nil
}

// SampleEvaluations builds
func (pr *proverRuntime) SampleEvaluations() error {

	// for each query position, open the list of polynomial evaluations at {f(w^i),f(-w^i)}
	// the relevant polynomials, that the verifier need to connec to the DEEP quotient,
	// are already stored in the setup tree, the trace trees, and the air trees
	for k, pos := range pr.queryPositions {

		var err error

		// setup
		if pr.setup.Tree != nil {
			var wproof commitment.WMerkleProof
			wproof.Leafs = make([]commitment.Pair, len(pr.setup.RawLeafs[pos]))
			wproof.Proof, err = pr.setup.Tree.OpenProof(pos)
			if err != nil {
				return err
			}
			pr.Proof.PointSamplings[k] = append(pr.Proof.PointSamplings[k], wproof)
		}

		// trace polynomials
		for _, tree := range pr.tTrees {
			var wproof commitment.WMerkleProof
			wproof.Leafs = make([]commitment.Pair, len(tree.RawLeafs[pos]))
			wproof.Proof, err = tree.Tree.OpenProof(pos)
			if err != nil {
				return err
			}
			pr.Proof.PointSamplings[k] = append(pr.Proof.PointSamplings[k], wproof)
		}

		// air quotients
		var wproof commitment.WMerkleProof
		wproof.Leafs = make([]commitment.Pair, len(pr.airTree.RawLeafs[pos]))
		wproof.Proof, err = pr.airTree.Tree.OpenProof(pos)
		if err != nil {
			return err
		}
		pr.Proof.PointSamplings[k] = append(pr.Proof.PointSamplings[k], wproof)

	}

	return nil
}

// TODO publicInputs are not used
func Prove(t trace.Trace, setup PublicKey, publicInputs proof.PublicInputs, program board.Program, opts ...Option) (proof.Proof, error) {

	var config Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return proof.Proof{}, err
		}
	}

	pr, err := newProverRuntime(t, setup, publicInputs, program, config)
	if err != nil {
		return proof.Proof{}, err
	}

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

	// Compute DEEP quotient and FRI-prove that it is the evaluation of a polynomial of degree N
	if err := pr.ComputeDeepQuotient(); err != nil {
		return proof.Proof{}, err
	}

	// Brige FRI <-> polynomial commitments, using sample at queryPositions
	if err := pr.SampleEvaluations(); err != nil {
		return proof.Proof{}, err
	}

	return pr.Proof, nil
}
