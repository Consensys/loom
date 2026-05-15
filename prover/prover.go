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
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
)

type Config struct {
	EmulateFS bool
	SkipFRI   bool
}

type Option func(c *Config) error

func EmulateFS() Option {
	return func(c *Config) error {
		c.EmulateFS = true
		return nil
	}
}

func SkipFRI() Option {
	return func(c *Config) error {
		c.SkipFRI = true
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
	zeta           ext.E4 // point of evaluation to check the AIR relation with SZ
	alpha          ext.E4 // folding challenge for N-grouped polynomials, used to build the DEEP quotient
	mu             sync.Mutex
	setup          setup.PublicKey
	queryPositions []int
	fs             *fiatshamir.Transcript
}

func newProverRuntime(t trace.Trace, setup setup.PublicKey, publicInputs proof.PublicInputs, program board.Program, config Config) (proverRuntime, error) {
	res := proverRuntime{
		Proof:        proof.NewProof(),
		config:       config,
		t:            t,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
		airTrace:     trace.New(),
		mu:           sync.Mutex{}, // mutex to protect the trace when reading/writing (in case of parallelisation)
	}

	// Build the canonical commitment layout for this run.
	res.layout = BuildLayout(program, len(setup))

	// allTrees holds setup trees up front; trace and AIR slots get filled as
	// commitments happen. proof.Commitments stores ONLY the trace+AIR roots
	// (setup roots come from the verifier's setup.PublicKey input, not the proof).
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

	// initialize FS transcript and pre-register all challenges
	// (challenge@loom_0..n-1, zeta, and alpha_DEEP)
	res.fs = fiatshamir.NewTranscript(sha256.New())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)
	res.fs.NewChallenge(constants.DEEP_ALPHA)

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

func setExtFromBytes(z *ext.E4, b []byte) error {
	if len(b) < 4*koalabear.Bytes {
		return fmt.Errorf("need at least %d bytes, got %d", 4*koalabear.Bytes, len(b))
	}
	z.B0.A0.SetBytes(b[0*koalabear.Bytes : 1*koalabear.Bytes])
	z.B0.A1.SetBytes(b[1*koalabear.Bytes : 2*koalabear.Bytes])
	z.B1.A0.SetBytes(b[2*koalabear.Bytes : 3*koalabear.Bytes])
	z.B1.A1.SetBytes(b[3*koalabear.Bytes : 4*koalabear.Bytes])
	return nil
}

func liftBaseToExt(v koalabear.Element) ext.E4 {
	var res ext.E4
	res.Lift(&v)
	return res
}

func liftPolynomialToExt(p poly.Polynomial) poly.ExtPolynomial {
	res := make(poly.ExtPolynomial, len(p))
	for i := range p {
		res[i].Lift(&p[i])
	}
	return res
}

type mixedCommitGroup struct {
	base []poly.Polynomial
	ext  []poly.ExtPolynomial
}

func traceColumnAsExt(t trace.Trace, name string) (poly.ExtPolynomial, bool) {
	if p, ok := t.Ext[name]; ok {
		return p, true
	}
	if p, ok := t.Base[name]; ok {
		return liftPolynomialToExt(p), true
	}
	return nil, false
}

func (pr *proverRuntime) commitTraceRound(roundIdx int, challengeName string) error {
	deps := pr.program.FScolumnsDependencies[roundIdx]
	polysByN := map[int]*mixedCommitGroup{}

	pr.mu.Lock()
	for _, dep := range deps {
		m, ok := pr.program.Modules[dep.Module]
		if !ok {
			pr.mu.Unlock()
			return fmt.Errorf("ExecuteSteps: column %q references unknown module %q", dep.Name, dep.Module)
		}
		group := polysByN[m.N]
		if group == nil {
			group = &mixedCommitGroup{}
			polysByN[m.N] = group
		}
		if dep.Field == field.Ext {
			p, ok := traceColumnAsExt(pr.t, dep.Name)
			if !ok {
				pr.mu.Unlock()
				return fmt.Errorf("ExecuteSteps: extension column %q not found in trace", dep.Name)
			}
			group.ext = append(group.ext, p)
			continue
		}
		p, ok := pr.t.Base[dep.Name]
		if !ok {
			pr.mu.Unlock()
			return fmt.Errorf("ExecuteSteps: base column %q not found in trace", dep.Name)
		}
		group.base = append(group.base, p)
	}
	pr.mu.Unlock()

	sizes := make([]int, 0, len(polysByN))
	for n := range polysByN {
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	base := pr.layout.TraceBegin[roundIdx]
	for i, N := range sizes {
		group := polysByN[N]
		committer := commitment.NewRSCommit(uint64(N), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)
		tree, err := committer.Commit(group.base, group.ext)
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

	return nil
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

				if err := pr.commitTraceRound(roundIdx, challengeName); err != nil {
					return err
				}

				var challengeVal ext.E4
				if pr.config.EmulateFS {
					challengeVal.MustSetRandom()
					if _, err := pr.fs.ComputeChallenge(challengeName); err != nil {
						return fmt.Errorf("ExecuteSteps: compute emulated challenge %s: %w", challengeName, err)
					}
				} else {
					challengeBytes, err := pr.fs.ComputeChallenge(challengeName)
					if err != nil {
						return err
					}
					if err := setExtFromBytes(&challengeVal, challengeBytes); err != nil {
						return err
					}
				}

				pr.mu.Lock()
				pr.t.SetExt(challengeName, []ext.E4{challengeVal})
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
	chunkDomains := make(map[string]*fft.Domain)

	for moduleName, module := range pr.program.Modules {
		if module.VanishingRelation.Degree() <= 0 {
			continue
		}

		N := module.N
		if module.VanishingRelation.Root.Field == field.Ext {
			quotient, err := poly.ComputeQuotientMixed(pr.t.Base, pr.t.Ext, *module.VanishingRelation, N)
			if err != nil {
				return err
			}

			poly.CosetExtLagrangeToLagrangeNormal(quotient)
			bigSize := len(quotient)
			bigD := fft.NewDomain(uint64(bigSize))
			bigD.FFTInverseExt(quotient, fft.DIF)
			utils.BitReverse(quotient)

			numChunks := bigSize / N
			for i := 0; i < numChunks; i++ {
				chunk := make(poly.ExtPolynomial, N)
				copy(chunk, quotient[i*N:(i+1)*N])
				module.D.FFTExt(chunk, fft.DIF)
				utils.BitReverse(chunk)
				chunkName := constants.QuotientChunkName(moduleName, i)
				pr.airTrace.SetExt(chunkName, chunk)
				chunkDomains[chunkName] = module.D
			}
			continue
		}

		quotient, err := poly.ComputeQuotient(pr.t.Base, *module.VanishingRelation, N)
		if err != nil {
			return err
		}

		poly.CosetLagrangeToLagrangeNormal(quotient)
		bigSize := len(quotient)
		bigD := fft.NewDomain(uint64(bigSize))
		bigD.FFTInverse(quotient, fft.DIF)
		utils.BitReverse(quotient)

		numChunks := bigSize / N
		for i := 0; i < numChunks; i++ {
			chunk := make(poly.Polynomial, N)
			copy(chunk, quotient[i*N:(i+1)*N])
			module.D.FFT(chunk, fft.DIF)
			utils.BitReverse(chunk)
			chunkName := constants.QuotientChunkName(moduleName, i)
			pr.airTrace.SetBase(chunkName, chunk)
			chunkDomains[chunkName] = module.D
		}
	}

	chunksByN := map[int]*mixedCommitGroup{}
	moduleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)
	for _, moduleName := range moduleNames {
		module := pr.program.Modules[moduleName]
		N := module.N
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			group := chunksByN[N]
			if group == nil {
				group = &mixedCommitGroup{}
				chunksByN[N] = group
			}
			if chunk, ok := pr.airTrace.Base[chunkName]; ok {
				group.base = append(group.base, chunk)
				continue
			}
			if chunk, ok := pr.airTrace.Ext[chunkName]; ok {
				group.ext = append(group.ext, chunk)
				continue
			}
			if group.base == nil && group.ext == nil {
				delete(chunksByN, N)
			}
			break
		}
	}
	sizes := make([]int, 0, len(chunksByN))
	for n, group := range chunksByN {
		if len(group.base) == 0 && len(group.ext) == 0 {
			continue
		}
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	if len(sizes) != pr.layout.AIREnd-pr.layout.AIRBegin {
		return fmt.Errorf("ComputeAIRQuotients: %d AIR size groups, layout expects %d", len(sizes), pr.layout.AIREnd-pr.layout.AIRBegin)
	}
	for i, N := range sizes {
		group := chunksByN[N]
		committer := commitment.NewRSCommit(uint64(N), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash)
		tree, err := committer.Commit(group.base, group.ext)
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

	if pr.config.EmulateFS {
		pr.zeta.MustSetRandom()
		if _, err := pr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
			return fmt.Errorf("ComputeAIRQuotients: compute emulated zeta: %w", err)
		}
	} else {
		zetaBytes, err := pr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
		if err != nil {
			return err
		}
		if err := setExtFromBytes(&pr.zeta, zetaBytes); err != nil {
			return err
		}
	}

	for chunkName, chunkPoly := range pr.airTrace.Base {
		pr.Proof.SetValueAtZetaExt(chunkName, poly.EvaluateAtExt(chunkPoly, chunkDomains[chunkName], pr.zeta))
	}
	for chunkName, chunkPoly := range pr.airTrace.Ext {
		pr.Proof.SetValueAtZetaExt(chunkName, poly.ExtEvaluateAtExt(chunkPoly, chunkDomains[chunkName], pr.zeta))
	}

	return nil
}

// ComputeEvaluationsAtZeta computes the evaluations at zeta of every polynomial
// appearing in every vanishing relation of every module.
func (pr *proverRuntime) ComputeEvaluationsAtZeta() error {
	config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())

	for _, module := range pr.program.Modules {
		leaves := module.VanishingRelation.LeavesFull(config)
		for _, leaf := range leaves {
			evalPoint := pr.zeta
			if leaf.Type == expr.RotatedColumn {
				shift := ((leaf.Shift % module.N) + module.N) % module.N
				var omegaPow koalabear.Element
				omegaPow.SetOne()
				for k := 0; k < shift; k++ {
					omegaPow.Mul(&omegaPow, &module.D.Generator)
				}
				evalPoint.MulByElement(&evalPoint, &omegaPow)
			}

			if p, ok := pr.t.Ext[leaf.Name]; ok {
				val := poly.ExtEvaluateAtExt(p, module.D, evalPoint)
				pr.Proof.SetValueAtZetaExt(leaf.String(), val)
				continue
			}
			p, ok := pr.t.Base[leaf.Name]
			if !ok {
				return fmt.Errorf("ComputeEvaluationsAtZeta: column %q not found in trace", leaf.Name)
			}
			val := poly.EvaluateAtExt(p, module.D, evalPoint)
			pr.Proof.SetValueAtZetaExt(leaf.String(), val)
		}
	}
	return nil
}

func (pr *proverRuntime) ComputeDeepQuotient() error {
	dqLayout := BuildDeepQuotientLayout(pr.program)
	sizes := dqLayout.Sizes

	domainBySize := make(map[int]*fft.Domain, len(sizes))
	for _, m := range pr.program.Modules {
		if _, ok := domainBySize[m.N]; !ok {
			domainBySize[m.N] = m.D
		}
	}

	if err := pr.deriveDeepAlpha(dqLayout); err != nil {
		return err
	}
	deepQuotients := make(map[int]poly.ExtPolynomial, len(sizes))

	for i, N := range sizes {
		deepQuotient := make(poly.ExtPolynomial, N)

		var alphaAcc ext.E4
		alphaAcc.SetOne()

		domainN := domainBySize[N]

		for j, shift := range dqLayout.Shifts[i] {
			var omegaShift koalabear.Element
			omegaShift.SetOne()
			for k := 0; k < shift; k++ {
				omegaShift.Mul(&omegaShift, &domainN.Generator)
			}
			z_s := pr.zeta
			z_s.MulByElement(&z_s, &omegaShift)

			C_s := make(poly.ExtPolynomial, N)
			var v_s ext.E4
			names := dqLayout.Names[i][j]
			keys := dqLayout.Keys[i][j]
			for k := range names {
				evalAtZ, ok := pr.Proof.ValueAtZetaExt(keys[k])
				if !ok {
					return fmt.Errorf("ComputeDeepQuotient: %q not found in ValuesAtZeta", keys[k])
				}
				colExt, hasExt := pr.t.Ext[names[k]]
				colBase, hasBase := pr.t.Base[names[k]]
				if !hasExt && !hasBase {
					return fmt.Errorf("ComputeDeepQuotient: column %q not found in trace", names[k])
				}
				for x := 0; x < N; x++ {
					var value, term ext.E4
					if hasExt {
						if len(colExt) == 1 {
							value.Set(&colExt[0])
						} else {
							value.Set(&colExt[x])
						}
					} else if len(colBase) == 1 {
						value.Lift(&colBase[0])
					} else {
						value.Lift(&colBase[x])
					}
					term.Mul(&value, &alphaAcc)
					C_s[x].Add(&C_s[x], &term)
				}
				var term ext.E4
				term.Mul(&evalAtZ, &alphaAcc)
				v_s.Add(&v_s, &term)
				alphaAcc.Mul(&alphaAcc, &pr.alpha)
			}

			DQ_s := poly.DeepQuotientExt(C_s, v_s, z_s, domainN)
			for x := 0; x < N; x++ {
				deepQuotient[x].Add(&deepQuotient[x], &DQ_s[x])
			}
		}

		if len(dqLayout.AIRChunks[i]) > 0 {
			C_s := make(poly.ExtPolynomial, N)
			var v_s ext.E4
			for _, chunkName := range dqLayout.AIRChunks[i] {
				evalAtZ, ok := pr.Proof.ValueAtZetaExt(chunkName)
				if !ok {
					return fmt.Errorf("ComputeDeepQuotient: %q not found in ValuesAtZeta", chunkName)
				}
				chunkExt, hasExt := pr.airTrace.Ext[chunkName]
				chunkBase, hasBase := pr.airTrace.Base[chunkName]
				if !hasExt && !hasBase {
					return fmt.Errorf("ComputeDeepQuotient: AIR chunk %q not found in trace", chunkName)
				}
				for x := 0; x < N; x++ {
					var value, term ext.E4
					if hasExt {
						value.Set(&chunkExt[x])
					} else {
						value.Lift(&chunkBase[x])
					}
					term.Mul(&value, &alphaAcc)
					C_s[x].Add(&C_s[x], &term)
				}
				var term ext.E4
				term.Mul(&evalAtZ, &alphaAcc)
				v_s.Add(&v_s, &term)
				alphaAcc.Mul(&alphaAcc, &pr.alpha)
			}

			DQ_air := poly.DeepQuotientExt(C_s, v_s, pr.zeta, domainN)
			for x := 0; x < N; x++ {
				deepQuotient[x].Add(&deepQuotient[x], &DQ_air[x])
			}
		}

		deepQuotients[N] = deepQuotient
	}

	levels := make([]fri.Level, len(sizes))
	for li, N := range sizes {
		encoder := reedsolomon.NewEncoder(uint64(constants.RATE) * uint64(N))
		encoded := encoder.EncodeExt(deepQuotients[N], domainBySize[N])

		tree, err := pr.friParams.BuildLevelTreeExt(encoded)
		if err != nil {
			return fmt.Errorf("ComputeDeepQuotient: BuildLevelTreeExt N=%d: %w", N, err)
		}

		levels[li] = fri.Level{
			D:     N,
			Evals: fri.LevelEvals{Ext: encoded},
			Tree:  tree,
		}
	}

	pr.Proof.DeepQuotientCommitment = make([][]byte, len(levels))
	for li := range levels {
		pr.Proof.DeepQuotientCommitment[li] = levels[li].Tree.Root()
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
	leafCount := tree.NumLeaves()
	if leafCount == 0 {
		return commitment.WMerkleProof{}, fmt.Errorf("empty WMerkleTree")
	}
	pos := s % leafCount
	pth, err := tree.Tree.OpenProof(pos)
	if err != nil {
		return commitment.WMerkleProof{}, err
	}
	var rawLeafBase []commitment.PairBase
	if len(tree.UnhashedLeafsBase) > 0 {
		rawLeafBase = make([]commitment.PairBase, len(tree.UnhashedLeafsBase[pos]))
		copy(rawLeafBase, tree.UnhashedLeafsBase[pos])
	}
	var rawLeafExt []commitment.PairExt
	if len(tree.UnhashedLeafsExt) > 0 {
		rawLeafExt = make([]commitment.PairExt, len(tree.UnhashedLeafsExt[pos]))
		copy(rawLeafExt, tree.UnhashedLeafsExt[pos])
	}
	return commitment.WMerkleProof{RawLeafBase: rawLeafBase, RawLeafExt: rawLeafExt, Proof: pth}, nil
}

// SampleEvaluations opens every committed polynomial at every FRI query
// position so the verifier can bridge the FRI proof back to the column
// commitments. Trees are walked in the canonical layout order
// (setup → trace per round → AIR), and each tree is opened at
// `s mod tree.NumLeaves()` (= s reduced mod RATE·N/2 for the tree's size N).
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
func Prove(t trace.Trace, setup setup.PublicKey, publicInputs proof.PublicInputs, program board.Program, opts ...Option) (proof.Proof, error) {

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

	// ------ PCS related verification ------

	if !config.SkipFRI {
		// Compute DEEP quotient and FRI-prove that it is the evaluation of a polynomial of degree N
		if err := pr.ComputeDeepQuotient(); err != nil {
			return proof.Proof{}, err
		}

		// Brige FRI <-> polynomial commitments, using sample at queryPositions
		if err := pr.SampleEvaluations(); err != nil {
			return proof.Proof{}, err
		}
	}

	return pr.Proof, nil
}
