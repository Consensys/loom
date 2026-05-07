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
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
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
	friParams fri.Params
	Proof     proof.Proof
	config    Config

	// layout is the canonical commitment layout (built from program + setup
	// at the start of every Prove call so program.SetSize changes are
	// reflected). It defines the order of trees in `allTrees` and the
	// column-name → Slot mapping consumed by SampleEvaluations.
	layout Layout
	// allTrees[i] is the i-th committed WMerkleTree in the canonical order
	// (setup → trace per round → AIR). Setup trees are copied from `setup`
	// at construction; trace and AIR trees are filled in as commitments
	// happen.
	allTrees []commitment.WMerkleTree

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
		airTrace:     make(trace.Trace),
		mu:           sync.Mutex{}, // mutex to protect the trace when reading/writing (in case of parallelisation)
	}

	// Build the canonical commitment layout for this run.
	res.layout = BuildLayout(program, len(setup))

	// allTrees holds setup trees up front; trace and AIR slots get filled as
	// commitments happen. proof.Commitments stores ONLY the trace+AIR roots
	// (setup roots come from the verifier's PublicKey input, not the proof).
	res.allTrees = make([]commitment.WMerkleTree, res.layout.NumTrees)
	for i, tree := range setup {
		res.allTrees[res.layout.SetupBegin+i] = tree
	}
	res.Proof.Commitments = make([][]byte, res.layout.NumTrees-res.layout.SetupEnd)

	// find the largest module size N in program (used to size FRI's outer domain)
	maxN := 0
	for _, m := range program.Modules {
		if m.N > maxN {
			maxN = m.N
		}
	}

	var err error
	res.friParams, err = fri.NewParams(int(constants.RATE)*maxN, maxN, constants.NUM_QUERIES, commitment.LeafHash, commitment.NodeHash)
	if err != nil {
		return res, err
	}

	res.queryPositions = make([]int, constants.NUM_QUERIES)

	// initialize FS transcript and pre-register all challenges (challenge@loom_0..n-1 and zeta)
	res.fs = fiatshamir.NewTranscript(sha256.New())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	// Bind every setup tree's root to challenge_0 (decreasing-N order, set by Setup).
	for _, tree := range setup {
		res.fs.Bind(constants.CanonicalChallengeName(0), tree.Root())
	}

	return res, nil
}

// commitIdxOf converts a canonical tree index into the offset in
// pr.Proof.Commitments (which excludes the setup section).
func (pr *proverRuntime) commitIdxOf(treeIdx int) int {
	return treeIdx - pr.layout.SetupEnd
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

				// Fetch trace polynomials for this round, grouping by their
				// owning module's domain size so we can build one commitment
				// per size (multi-degree commitment scheme). Group order
				// matches Layout (decreasing N, stable within a size).
				deps := pr.program.FScolumnsDependencies[roundIdx]
				polysByN := map[int][]poly.Polynomial{}
				pr.mu.Lock()
				for _, dep := range deps {
					m, ok := pr.program.Modules[dep.Module]
					if !ok {
						pr.mu.Unlock()
						return fmt.Errorf("ExecuteSteps: column %q references unknown module %q", dep.Name, dep.Module)
					}
					polysByN[m.N] = append(polysByN[m.N], pr.t[dep.Name])
				}
				pr.mu.Unlock()

				// Sizes in decreasing N order (consistent with Layout).
				sizes := make([]int, 0, len(polysByN))
				for n := range polysByN {
					sizes = append(sizes, n)
				}
				sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

				// Commit per size; place trees and roots at the canonical
				// layout offsets for this FS round.
				base := pr.layout.TraceBegin[roundIdx]
				for i, N := range sizes {
					committer := commitment.NewRSCommit(uint64(N), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)
					tree, err := committer.Commit(polysByN[N])
					if err != nil {
						return err
					}
					treeIdx := base + i
					pr.allTrees[treeIdx] = tree
					root := tree.Root()
					pr.Proof.Commitments[pr.commitIdxOf(treeIdx)] = root
					if err := pr.fs.Bind(challengeName, root); err != nil {
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

	// 2 - Group AIR-quotient chunks by their owning module's domain size, in
	// deterministic order. Within a size group: modules sorted by name
	// (ascending), then their chunks in index order. Sizes are processed in
	// decreasing-N order so that airTrees and AIRQuotientsCommitment line up
	// with the rest of the multi-degree commitment scheme.
	chunksByN := map[int][]poly.Polynomial{}
	moduleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)
	for _, moduleName := range moduleNames {
		N := pr.program.Modules[moduleName].N
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			chunk, ok := pr.airTrace[chunkName]
			if !ok {
				break
			}
			chunksByN[N] = append(chunksByN[N], chunk)
		}
	}
	sizes := make([]int, 0, len(chunksByN))
	for n := range chunksByN {
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	// Place AIR trees at canonical layout offsets and write their roots
	// into proof.Commitments. Bind every root to __zeta in the same order.
	if len(sizes) != pr.layout.AIREnd-pr.layout.AIRBegin {
		return fmt.Errorf("ComputeAIRQuotients: %d AIR size groups, layout expects %d", len(sizes), pr.layout.AIREnd-pr.layout.AIRBegin)
	}
	for i, N := range sizes {
		committer := commitment.NewRSCommit(uint64(N), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)
		tree, err := committer.Commit(chunksByN[N])
		if err != nil {
			return err
		}
		treeIdx := pr.layout.AIRBegin + i
		pr.allTrees[treeIdx] = tree
		root := tree.Root()
		pr.Proof.Commitments[pr.commitIdxOf(treeIdx)] = root
		if err := pr.fs.Bind(constants.FINAL_EVALUATION_POINT, root); err != nil {
			return err
		}
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

	// Group module names by domain size N. Within a size, names are sorted
	// alphabetically so the alpha accumulation is deterministic.
	modulesByN := map[int][]string{}
	for name := range pr.program.Modules {
		N := pr.program.Modules[name].N
		modulesByN[N] = append(modulesByN[N], name)
	}
	for _, names := range modulesByN {
		sort.Strings(names)
	}
	// Sizes in decreasing order: levels[0] is the largest (= friParams.D).
	sizes := make([]int, 0, len(modulesByN))
	for n := range modulesByN {
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	// for now we emulate the folding challenge
	var alpha koalabear.Element
	// TODO make it random via FS
	alpha.SetUint64(10)

	// One DEEP quotient per size, combining vanishing-relation columns and AIR
	// quotient chunks of all modules of that size. alphaAcc is reset to 1 for
	// each size — different sizes are mixed by FRI's level-batching γ_l later.
	deepQuotients := make(map[int]poly.Polynomial, len(sizes))

	for _, N := range sizes {
		deepQuotient := make(poly.Polynomial, N)

		var alphaAcc koalabear.Element
		alphaAcc.SetOne()

		// All modules of size N share the same canonical domain (size-N roots
		// of unity); pick the first one as reference for shift evaluation.
		domainN := pr.program.Modules[modulesByN[N][0]].D

		// ── Phase 1: vanishing-relation columns ────────────────────────────────
		// Pool leaves across ALL modules of this size, deduplicated by
		// leaf.String() so a column referenced by several same-size modules
		// only contributes once to the size-N deep quotient.
		type colEntry struct {
			name string // bare column name → key in pr.t
			key  string // leaf.String() → key in ValuesAtZeta
		}
		byShift := map[int][]colEntry{}
		seenKey := map[string]bool{}
		for _, moduleName := range modulesByN[N] {
			module := pr.program.Modules[moduleName]

			config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
			leaves := module.VanishingRelation.LeavesFull(config)
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
		}
		shifts := make([]int, 0, len(byShift))
		for s := range byShift {
			shifts = append(shifts, s)
		}
		sort.Ints(shifts)
		for _, sh := range shifts {
			sort.Slice(byShift[sh], func(i, j int) bool { return byShift[sh][i].key < byShift[sh][j].key })
		}

		for _, shift := range shifts {
			// evaluation point z_s = omega^shift * zeta
			var omegaShift koalabear.Element
			omegaShift.SetOne()
			for k := 0; k < shift; k++ {
				omegaShift.Mul(&omegaShift, &domainN.Generator)
			}
			var z_s koalabear.Element
			z_s.Mul(&pr.zeta, &omegaShift)

			// fold: C_s(X) = Σ_i alphaAcc_i * C_i(X); v_s = C_s(z_s)
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

			DQ_s := poly.DeepQuotient(C_s, v_s, z_s, domainN)
			for j := 0; j < N; j++ {
				deepQuotient[j].Add(&deepQuotient[j], &DQ_s[j])
			}
		}

		// ── Phase 2: AIR quotient chunks (per module — each module has its
		// own vanishing relation, hence its own quotient chunks) ───────────────
		for _, moduleName := range modulesByN[N] {
			module := pr.program.Modules[moduleName]

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
			for j := 0; j < N; j++ {
				deepQuotient[j].Add(&deepQuotient[j], &DQ_air[j])
			}
		}

		deepQuotients[N] = deepQuotient
	}

	// ── Build FRI levels: encode each per-size deep quotient and its tree ────
	levels := make([]fri.Level, len(sizes))
	for li, N := range sizes {
		// RS-encode at size N → length RATE*N. Reuse any module-of-size-N's domain.
		firstModule := pr.program.Modules[modulesByN[N][0]]
		encoder := reedsolomon.NewEncoder(uint64(constants.RATE) * uint64(N))
		encoded := encoder.Encode(deepQuotients[N], firstModule.D)

		tree, err := pr.friParams.BuildLevelTree(encoded)
		if err != nil {
			return fmt.Errorf("ComputeDeepQuotient: BuildLevelTree N=%d: %w", N, err)
		}

		levels[li] = fri.Level{
			D:     N,
			Evals: [][]koalabear.Element{encoded},
			Trees: []*merkle.Tree{tree},
		}
	}

	// Expose every level's tree root as DeepQuotientCommitment[l] (same order
	// as `levels`, i.e. decreasing N). The verifier passes these to fri.Verify
	// as levelRoots; the polynomial-commitment bridge that ties them back to
	// the trace and AIR commitments is left for later.
	pr.Proof.DeepQuotientCommitment = make([][]byte, len(levels))
	for li := range levels {
		pr.Proof.DeepQuotientCommitment[li] = levels[li].Trees[0].Root()
	}

	var err error
	pr.Proof.DeepQuotientFriProof, pr.queryPositions, err = fri.Prove(pr.friParams, levels, pr.fs)
	if err != nil {
		return fmt.Errorf("fri.Prove: %v", err)
	}

	return nil
}

// openWMerkleAt opens a WMerkleTree at the leaf index corresponding to FRI
// query position `s`, reduced mod the tree's paired-leaf count (=
// encoded_size/2 = RATE·N/2).
func openWMerkleAt(tree commitment.WMerkleTree, s int) (commitment.WMerkleProof, error) {
	pos := s % len(tree.RawLeafs)
	pth, err := tree.Tree.OpenProof(pos)
	if err != nil {
		return commitment.WMerkleProof{}, err
	}
	rawLeaf := make([]commitment.Pair, len(tree.RawLeafs[pos]))
	copy(rawLeaf, tree.RawLeafs[pos])
	return commitment.WMerkleProof{RawLeaf: rawLeaf, Proof: pth}, nil
}

// SampleEvaluations opens every committed polynomial at every FRI query
// position so the verifier can bridge the FRI proof back to the column
// commitments. Trees are walked in the canonical layout order
// (setup → trace per round → AIR), and each tree is opened at
// `s mod len(tree.RawLeafs)` (= s reduced mod RATE·N/2 for the tree's size N).
func (pr *proverRuntime) SampleEvaluations() error {
	NQ := len(pr.queryPositions)
	pr.Proof.PointSamplings = make([][]commitment.WMerkleProof, NQ)
	for q, s := range pr.queryPositions {
		samplings := make([]commitment.WMerkleProof, pr.layout.NumTrees)
		for i, tree := range pr.allTrees {
			wp, err := openWMerkleAt(tree, s)
			if err != nil {
				return fmt.Errorf("SampleEvaluations: tree %d query %d: %w", i, q, err)
			}
			samplings[i] = wp
		}
		pr.Proof.PointSamplings[q] = samplings
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
