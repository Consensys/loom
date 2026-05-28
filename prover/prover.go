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
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/parallel"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/public"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
)

type Config struct {
	EmulateFS     bool
	SkipFRI       bool
	HashBackend   commitment.HashBackend
	PhaseCallback func(name string, d time.Duration)
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

func WithHashBackend(backend commitment.HashBackend) Option {
	return func(c *Config) error {
		c.HashBackend = backend
		return nil
	}
}

// WithPhaseCallback installs a callback that fires after each major prover
// phase with the phase name and wall-clock duration. Phases reported (in
// order): "execute-steps", "compute-air-quotients", "evaluations-at-zeta",
// "deep-quotient+fri-commit", "fri-query-open".
func WithPhaseCallback(cb func(name string, d time.Duration)) Option {
	return func(c *Config) error {
		c.PhaseCallback = cb
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
	// openingSources[i] reconstructs raw leaves for allTrees[i] after FRI
	// query positions are known.
	openingSources []commitmentOpeningSource

	t              trace.Trace
	airTrace       trace.Trace
	publicInputs   public.Inputs
	program        board.Program
	zeta           ext.E4 // point of evaluation to check the AIR relation with SZ
	alpha          ext.E4 // folding challenge for N-grouped polynomials, used to build the DEEP quotient
	mu             *sync.Mutex
	setup          setup.ProvingKey
	queryPositions []int
	fs             *fiatshamir.Transcript
	domainCache    poly.DomainCache
	hashBackend    commitment.HashBackend
}

func newProverRuntime(t trace.Trace, provingKey setup.ProvingKey, publicInputs public.Inputs, program board.Program, config Config) (proverRuntime, error) {
	var err error
	hashBackend, err := commitment.ResolveHashBackend(config.HashBackend, provingKey.HashBackendID)
	if err != nil {
		return proverRuntime{}, err
	}
	config.HashBackend = hashBackend

	if len(provingKey.Trace.Base) > 0 || len(provingKey.Trace.Ext) > 0 {
		t, err = trace.MergeMatching(t, provingKey.Trace)
		if err != nil {
			return proverRuntime{}, fmt.Errorf("newProverRuntime: merge setup trace: %w", err)
		}
	}

	res := proverRuntime{
		Proof:        proof.NewProof(),
		config:       config,
		t:            t,
		publicInputs: publicInputs,
		program:      program,
		setup:        provingKey,
		airTrace:     trace.New(),
		mu:           new(sync.Mutex), // mutex to protect the trace when reading/writing (in case of parallelisation)
		hashBackend:  hashBackend,
	}
	res.Proof.HashBackendID = hashBackend.ID

	// Build the canonical commitment layout for this run.
	res.layout = BuildLayout(program, len(provingKey.Trees))

	// allTrees holds setup trees up front; trace and AIR slots get filled as
	// commitments happen. proof.Commitments stores ONLY the trace+AIR roots
	// (setup roots come from the verifier's VerificationKey input, not the proof).
	res.allTrees = make([]commitment.WMerkleTree, res.layout.NumTrees)
	res.openingSources = make([]commitmentOpeningSource, res.layout.NumTrees)
	for i, tree := range provingKey.Trees {
		res.allTrees[res.layout.SetupBegin+i] = tree
	}
	if err := res.initSetupOpeningSources(); err != nil {
		return proverRuntime{}, err
	}
	res.Proof.Commitments = make([]hash.Digest, res.layout.NumTrees-res.layout.SetupEnd)

	// find the largest module size N in program (used to size FRI's outer domain)
	maxN := 0
	for _, m := range program.Modules {
		if m.N > maxN {
			maxN = m.N
		}
	}

	res.friParams, err = fri.NewParams(int(constants.RATE)*maxN, maxN, constants.NUM_QUERIES, hashBackend.LeafHasher, hashBackend.NodeHasher)
	if err != nil {
		return res, err
	}

	res.queryPositions = make([]int, constants.NUM_QUERIES)

	// initialize FS transcript and pre-register all challenges
	// (challenge@loom_0..n-1, zeta, and alpha_DEEP)
	res.fs = fiatshamir.NewTranscript(hashBackend.NewTranscriptHasher())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)
	res.fs.NewChallenge(constants.DEEP_ALPHA)

	initialChallenge := constants.InitialChallengeName(numRounds)
	if err := res.fs.Bind(initialChallenge, hash.StringToElements(constants.HASH_BACKEND_DOMAIN_TAG, hashBackend.ID)); err != nil {
		return res, err
	}

	// Bind every setup tree's root to the first challenge (decreasing-N order,
	// set by Setup) + public inputs.
	for _, tree := range provingKey.Trees {
		root := tree.Root()
		if err := res.fs.Bind(initialChallenge, root[:]); err != nil {
			return res, err
		}
	}
	if len(publicInputs) > 0 {
		if err := res.fs.Bind(initialChallenge, publicInputs.TranscriptElements()); err != nil {
			return res, err
		}
	}

	// materialise the public columns to the trace from the public inputs
	for colName, pi := range publicInputs {
		m, ok := program.Modules[pi.Module]
		if !ok {
			return res, fmt.Errorf("public input %q references unknown module %q", colName, pi.Module)
		}
		kind := field.Base
		for _, e := range pi.Entries {
			if e.Idx < 0 || e.Idx >= m.N {
				return res, fmt.Errorf("public input %q entry index %d out of bounds for module %q of size %d", colName, e.Idx, pi.Module, m.N)
			}
			kind = field.Join(e.Field, kind)
		}
		if kind == field.Base {
			col := make([]koalabear.Element, m.N)
			for _, e := range pi.Entries {
				col[e.Idx].Set(&e.Value)
			}
			err := t.PutBase(colName, col)
			if err != nil {
				return res, err
			}
		} else {
			col := make([]ext.E4, m.N)
			for _, e := range pi.Entries {
				if e.Field == field.Base {
					col[e.Idx].Lift(&e.Value)
				} else {
					col[e.Idx].Set(&e.ValueExt)
				}
			}
			err := t.PutExt(colName, col)
			if err != nil {
				return res, err
			}
		}
	}

	return res, nil
}

// commitIdxOf converts a canonical tree index into the offset in
// pr.Proof.Commitments (which excludes the setup section).
func (pr *proverRuntime) commitIdxOf(treeIdx int) int {
	return treeIdx - pr.layout.SetupEnd
}

func (pr *proverRuntime) initSetupOpeningSources() error {
	for _, ref := range pr.program.PublicColumns {
		slot, ok := pr.layout.ColSlot[ref.Name]
		if !ok {
			continue
		}
		if slot.TreeIdx < pr.layout.SetupBegin || slot.TreeIdx >= pr.layout.SetupEnd {
			return fmt.Errorf("initSetupOpeningSources: public column %q mapped outside setup section", ref.Name)
		}
		if slot.TreeIdx >= len(pr.layout.TreeSize) {
			return fmt.Errorf("initSetupOpeningSources: setup tree index %d out of range", slot.TreeIdx)
		}
		source := &pr.openingSources[slot.TreeIdx]
		source.setFullDomainSize(pr.layout.TreeSize[slot.TreeIdx])
		switch ref.Field {
		case field.Base:
			p, ok := pr.setup.Trace.Base[ref.Name]
			if !ok {
				return fmt.Errorf("initSetupOpeningSources: base setup column %q not found", ref.Name)
			}
			source.setBase(slot.PolyIdx, p)
		case field.Ext:
			p, ok := pr.setup.Trace.Ext[ref.Name]
			if !ok {
				return fmt.Errorf("initSetupOpeningSources: extension setup column %q not found", ref.Name)
			}
			source.setExt(slot.PolyIdx, p)
		default:
			return fmt.Errorf("initSetupOpeningSources: unsupported field kind for setup column %q", ref.Name)
		}
	}
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
		committer := commitment.NewRSCommitWithDomainCache(uint64(N), uint64(constants.RATE), pr.hashBackend.LeafHasher, pr.hashBackend.NodeHasher, &pr.domainCache)
		tree, err := committer.Commit(group.base, group.ext, commitment.WithDomainCache(&pr.domainCache))
		if err != nil {
			return err
		}
		treeIdx := base + i
		pr.allTrees[treeIdx] = tree
		pr.openingSources[treeIdx] = newCommitmentOpeningSource(group.base, group.ext, N)
		root := tree.Root()
		pr.Proof.Commitments[pr.commitIdxOf(treeIdx)] = root
		if err := pr.fs.Bind(challengeName, root[:]); err != nil {
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
					challenge, err := pr.fs.ComputeChallenge(challengeName)
					if err != nil {
						return err
					}
					challengeVal = hash.OutputToExt(challenge)
				}

				pr.mu.Lock()
				pr.t.SetExt(challengeName, []ext.E4{challengeVal})
				pr.mu.Unlock()

				roundIdx++

				continue
			}
			err := s.Execute(pr.t, &pr.program, &pr.Proof, pr.mu)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// computeExtAIRQuotientChunks computes the AIR quotient for a single ext-rooted module
// and returns its N-sized chunks in Lagrange form, ready to commit. Chunks
// alias non-overlapping windows of the quotient backing array (no per-chunk
// copy); after this returns the caller owns the chunks and the original
// quotient is unreachable.
// fftNbTasks caps the inner parallelism of the per-chunk FFTs so that, when
// this function is itself invoked inside a parallel.Execute over modules,
// outer × inner goroutines stays bounded.
func computeExtAIRQuotientChunks(piBase map[string]poly.Polynomial, piExt map[string]poly.ExtPolynomial, vrel *dag.DAG, N int, D *fft.Domain, cache *poly.DomainCache, fftNbTasks int) ([]poly.ExtPolynomial, error) {
	quotient, err := poly.ComputeQuotientMixed(piBase, piExt, *vrel, N, poly.WithDomainCache(cache))
	if err != nil {
		return nil, err
	}
	// quotient is in coset-Lagrange Normal; convert directly to canonical
	// Normal so chunking can sub-slice the backing array.
	poly.CosetExtLagrangeNormalToCanonicalWithCache(quotient, cache)

	fftOpt := fft.WithNbTasks(fftNbTasks)
	chunks := make([]poly.ExtPolynomial, len(quotient)/N)
	for i := range chunks {
		chunk := quotient[i*N : (i+1)*N : (i+1)*N]
		D.FFTExt(chunk, fft.DIF, fftOpt)
		utils.BitReverse(chunk)
		chunks[i] = chunk
	}
	return chunks, nil
}

// computeBaseAIRQuotientChunks is the base-field counterpart of computeExtAIRQuotientChunks.
func computeBaseAIRQuotientChunks(piBase map[string]poly.Polynomial, vrel *dag.DAG, N int, D *fft.Domain, cache *poly.DomainCache, fftNbTasks int) ([]poly.Polynomial, error) {
	quotient, err := poly.ComputeQuotient(piBase, *vrel, N, poly.WithDomainCache(cache))
	if err != nil {
		return nil, err
	}
	poly.CosetLagrangeNormalToCanonicalWithCache(quotient, cache)

	fftOpt := fft.WithNbTasks(fftNbTasks)
	chunks := make([]poly.Polynomial, len(quotient)/N)
	for i := range chunks {
		chunk := quotient[i*N : (i+1)*N : (i+1)*N]
		D.FFT(chunk, fft.DIF, fftOpt)
		utils.BitReverse(chunk)
		chunks[i] = chunk
	}
	return chunks, nil
}

func (pr *proverRuntime) ComputeAIRQuotients() error {

	moduleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	// Per-module quotient computation is independent: each writes disjoint chunk
	// names into airTrace, reads only from the shared pr.t. pr.domainCache is
	// internally locked; trace map writes need an explicit lock. The DAG is
	// cloned per goroutine because ComputeQuotient* mutates Leaf.Idx and modules
	// can share *expr.Leaf pointers via cross-module arguments (Lookup, etc.).
	var (
		writeMu  sync.Mutex
		errMu    sync.Mutex
		firstErr error
	)
	// Per-chunk FFTs inside each module run with their internal parallelism
	// capped so the outer module fan-out doesn't multiply with the FFT's own.
	fftNbTasks := parallel.NbTasksPerJob(len(moduleNames))
	parallel.Execute(len(moduleNames), func(start, end int) {
		for idx := start; idx < end; idx++ {
			moduleName := moduleNames[idx]
			module := pr.program.Modules[moduleName]
			if module.VanishingRelation.Degree() <= 0 {
				continue
			}

			N := module.N
			vrel := module.VanishingRelation.Clone()

			var (
				baseChunks []poly.Polynomial
				extChunks  []poly.ExtPolynomial
				err        error
			)
			if module.VanishingRelation.Root.Field == field.Ext {
				extChunks, err = computeExtAIRQuotientChunks(pr.t.Base, pr.t.Ext, vrel, N, module.D, &pr.domainCache, fftNbTasks)
			} else {
				baseChunks, err = computeBaseAIRQuotientChunks(pr.t.Base, vrel, N, module.D, &pr.domainCache, fftNbTasks)
			}
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}

			writeMu.Lock()
			for i, c := range baseChunks {
				name := constants.QuotientChunkName(moduleName, i)
				pr.airTrace.SetBase(name, c)
			}
			for i, c := range extChunks {
				name := constants.QuotientChunkName(moduleName, i)
				pr.airTrace.SetExt(name, c)
			}
			writeMu.Unlock()
		}
	})
	if firstErr != nil {
		return firstErr
	}

	chunksByN := map[int]*mixedCommitGroup{}
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
		committer := commitment.NewRSCommitWithDomainCache(uint64(N), uint64(constants.RATE), pr.hashBackend.LeafHasher, pr.hashBackend.NodeHasher, &pr.domainCache)
		tree, err := committer.Commit(group.base, group.ext, commitment.WithDomainCache(&pr.domainCache))
		if err != nil {
			return err
		}
		treeIdx := pr.layout.AIRBegin + i
		pr.allTrees[treeIdx] = tree
		pr.openingSources[treeIdx] = newCommitmentOpeningSource(group.base, group.ext, N)
		root := tree.Root()
		pr.Proof.Commitments[pr.commitIdxOf(treeIdx)] = root
		if err := pr.fs.Bind(constants.FINAL_EVALUATION_POINT, root[:]); err != nil {
			return err
		}
	}

	if pr.config.EmulateFS {
		pr.zeta.MustSetRandom()
		if _, err := pr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
			return fmt.Errorf("ComputeAIRQuotients: compute emulated zeta: %w", err)
		}
	} else {
		zeta, err := pr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
		if err != nil {
			return err
		}
		pr.zeta = hash.OutputToExt(zeta)
	}

	return nil
}

// ComputeEvaluationsAtZeta computes the evaluations at zeta of every polynomial
// appearing in every vanishing relation of every module.
//
// Each per-column evaluation is an independent FFTInverse + Horner pass, so we
// gather every (poly, evaluation point) pair across all modules into a single
// task list and fan it out across goroutines. Each inner FFT is capped to 1
// goroutine (fft.WithNbTasks(1)) since the column-level fan-out already
// saturates the CPUs.
func (pr *proverRuntime) ComputeEvaluationsAtZeta() error {
	config := expr.NewConfig(
		expr.WithoutLagrangeColumns(),
		expr.WithoutChallenges(),
		expr.WithoutExposedColumns(),
		expr.WithoutPublicColumns(),
	)

	moduleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	lagrangesByN := make(map[int][]ext.E4)
	for _, moduleName := range moduleNames {
		N := pr.program.Modules[moduleName].N
		if _, ok := lagrangesByN[N]; !ok {
			lagrangesByN[N] = poly.LagrangesAtZeta(pr.zeta, N)
		}
	}

	type evalTask struct {
		key       string
		field     field.Kind
		shift     int
		lagranges []ext.E4
		base      poly.Polynomial
		ext       poly.ExtPolynomial
	}

	tasks := make([]evalTask, 0)
	addBaseTask := func(key string, p poly.Polynomial, moduleN, shift int) error {
		if len(p) != 1 && len(p) != moduleN {
			return fmt.Errorf("ComputeEvaluationsAtZeta: base polynomial %q has size %d, module has size %d", key, len(p), moduleN)
		}
		tasks = append(tasks, evalTask{
			key:       key,
			field:     field.Base,
			shift:     shift,
			lagranges: lagrangesByN[moduleN],
			base:      p,
		})
		return nil
	}
	addExtTask := func(key string, p poly.ExtPolynomial, moduleN, shift int) error {
		if len(p) != 1 && len(p) != moduleN {
			return fmt.Errorf("ComputeEvaluationsAtZeta: extension polynomial %q has size %d, module has size %d", key, len(p), moduleN)
		}
		tasks = append(tasks, evalTask{
			key:       key,
			field:     field.Ext,
			shift:     shift,
			lagranges: lagrangesByN[moduleN],
			ext:       p,
		})
		return nil
	}

	for _, moduleName := range moduleNames {
		module := pr.program.Modules[moduleName]
		for _, leaf := range module.VanishingRelation.LeavesFull(config) {
			shift := 0
			if leaf.Type == expr.RotatedColumn {
				shift = ((leaf.Shift % module.N) + module.N) % module.N
			}
			if p, ok := pr.t.Ext[leaf.Name]; ok {
				if err := addExtTask(leaf.String(), p, module.N, shift); err != nil {
					return err
				}
				continue
			}
			p, ok := pr.t.Base[leaf.Name]
			if !ok {
				return fmt.Errorf("ComputeEvaluationsAtZeta: column %q not found in trace", leaf.Name)
			}
			if err := addBaseTask(leaf.String(), p, module.N, shift); err != nil {
				return err
			}
		}

		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			if chunk, ok := pr.airTrace.Base[chunkName]; ok {
				if err := addBaseTask(chunkName, chunk, module.N, 0); err != nil {
					return err
				}
				continue
			}
			if chunk, ok := pr.airTrace.Ext[chunkName]; ok {
				if err := addExtTask(chunkName, chunk, module.N, 0); err != nil {
					return err
				}
				continue
			}
			break
		}
	}

	values := make([]ext.E4, len(tasks))
	parallel.Execute(len(tasks), func(start, end int) {
		for i := start; i < end; i++ {
			task := tasks[i]
			if task.field == field.Ext {
				if len(task.ext) == 1 {
					values[i].Set(&task.ext[0])
				} else {
					values[i] = poly.ExtEvaluateLagrangeAtExt(task.ext, task.lagranges, task.shift)
				}
				continue
			}
			if len(task.base) == 1 {
				values[i] = liftBaseToExt(task.base[0])
			} else {
				values[i] = poly.EvaluateLagrangeAtExt(task.base, task.lagranges, task.shift)
			}
		}
	})
	for i, task := range tasks {
		pr.Proof.SetValueAtZetaExt(task.key, values[i])
	}

	return nil
}

// deepQuotientBundle aggregates everything needed to add one DEEP-quotient
// shift block's contribution to deepQuotient[*]:
//
//	deepQuotient[x] += (vs - sum_k(scales_k * cols_k[x])) / (zs - omega^x)
//
// The serial alpha-power chain in the original code is unrolled into the
// scales slices below, so the per-row loop has no cross-column data dependency
// and can be chunked across goroutines.
type deepQuotientBundle struct {
	zs ext.E4 // shifted evaluation point
	vs ext.E4 // alpha-weighted sum of evaluations at zs

	// constContrib is the contribution from constant (len-1) columns, summed
	// in advance so the per-row loop only iterates real-width columns.
	constContrib ext.E4

	extCols    []poly.ExtPolynomial
	extScales  []ext.E4
	baseCols   []poly.Polynomial
	baseScales []ext.E4
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

		// ---- Phase 1: vanishing-relation columns, one bundle per shift ----
		bundles := make([]deepQuotientBundle, 0, len(dqLayout.Shifts[i])+1)
		for j, shift := range dqLayout.Shifts[i] {
			var omegaShift koalabear.Element
			omegaShift.Exp(domainN.Generator, big.NewInt(int64(shift)))
			zs := pr.zeta
			zs.MulByElement(&zs, &omegaShift)

			b, nextAlpha, err := pr.buildDeepQuotientBundle(
				zs,
				dqLayout.Names[i][j],
				dqLayout.Keys[i][j],
				pr.t.Base, pr.t.Ext,
				alphaAcc,
			)
			if err != nil {
				return err
			}
			bundles = append(bundles, b)
			alphaAcc = nextAlpha
		}

		// ---- Phase 2: AIR chunks at z=zeta (no shift) ----
		if len(dqLayout.AIRChunks[i]) > 0 {
			b, nextAlpha, err := pr.buildDeepQuotientBundle(
				pr.zeta,
				dqLayout.AIRChunks[i],
				dqLayout.AIRChunks[i], // keys == names for AIR chunks
				pr.airTrace.Base, pr.airTrace.Ext,
				alphaAcc,
			)
			if err != nil {
				return err
			}
			bundles = append(bundles, b)
			alphaAcc = nextAlpha
		}

		accumulateDeepQuotient(deepQuotient, bundles, domainN)

		deepQuotients[N] = deepQuotient
	}

	// The DEEP quotients chunks are computed and grouped in decreasing size order, we can build the levels to call
	// multi degree FRI
	levels := make([]fri.Level, len(sizes))
	for li, N := range sizes {
		encoder := reedsolomon.NewEncoderWithDomainCache(uint64(constants.RATE)*uint64(N), &pr.domainCache)
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

	pr.Proof.DeepQuotientCommitment = make([]hash.Digest, len(levels))
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

// buildDeepQuotientBundle collects column data + per-column alpha scale factors
// for one shift block and returns the bundle plus the next alpha accumulator.
// Constant (len-1) columns are folded into bundle.constContrib so the per-row
// loop only iterates real-width columns.
//
// names and keys are parallel: names[k] looks up the trace polynomial,
// keys[k] looks up the value at zeta in pr.Proof (for AIR chunks the two
// coincide).
func (pr *proverRuntime) buildDeepQuotientBundle(
	zs ext.E4,
	names, keys []string,
	traceBase map[string]poly.Polynomial,
	traceExt map[string]poly.ExtPolynomial,
	alphaStart ext.E4,
) (deepQuotientBundle, ext.E4, error) {
	b := deepQuotientBundle{zs: zs}
	scale := alphaStart
	for k, name := range names {
		evalAtZ, ok := pr.Proof.ValueAtZetaExt(keys[k])
		if !ok {
			return deepQuotientBundle{}, ext.E4{}, fmt.Errorf("ComputeDeepQuotient: %q not found in ValuesAtZeta", keys[k])
		}
		colExt, hasExt := traceExt[name]
		colBase, hasBase := traceBase[name]
		if !hasExt && !hasBase {
			return deepQuotientBundle{}, ext.E4{}, fmt.Errorf("ComputeDeepQuotient: column %q not found in trace", name)
		}

		var term ext.E4
		term.Mul(&evalAtZ, &scale)
		b.vs.Add(&b.vs, &term)

		switch {
		case hasExt && len(colExt) == 1:
			term.Mul(&colExt[0], &scale)
			b.constContrib.Add(&b.constContrib, &term)
		case hasExt:
			b.extCols = append(b.extCols, colExt)
			b.extScales = append(b.extScales, scale)
		case len(colBase) == 1:
			term.MulByElement(&scale, &colBase[0])
			b.constContrib.Add(&b.constContrib, &term)
		default:
			b.baseCols = append(b.baseCols, colBase)
			b.baseScales = append(b.baseScales, scale)
		}

		scale.Mul(&scale, &pr.alpha)
	}
	return b, scale, nil
}

// accumulateDeepQuotient adds every bundle's DEEP-quotient contribution into
// deepQuotient using a single row-chunked parallel pass: each chunk computes
// (z_s - omega^x)^-1 in batch (BatchInvertE4), then sweeps every bundle to
// fold its (vs - sum_k scale_k * col_k[x]) numerator and add to deepQuotient[x].
// One pass amortises C_s materialisation away — only a row-sized denominator
// buffer per chunk is allocated.
func accumulateDeepQuotient(deepQuotient poly.ExtPolynomial, bundles []deepQuotientBundle, domain *fft.Domain) {
	N := len(deepQuotient)
	if N == 0 || len(bundles) == 0 {
		return
	}

	parallel.Execute(N, func(start, end int) {
		chunkLen := end - start

		// Compute denominators (z_s - omega^x) for every bundle, batch invert.
		denoms := make([]ext.E4, chunkLen*len(bundles))
		var omegaX koalabear.Element
		if start == 0 {
			omegaX.SetOne()
		} else {
			omegaX.Exp(domain.Generator, big.NewInt(int64(start)))
		}
		for x := 0; x < chunkLen; x++ {
			var omegaExt ext.E4
			omegaExt.Lift(&omegaX)
			for b := range bundles {
				denoms[b*chunkLen+x].Sub(&bundles[b].zs, &omegaExt)
			}
			omegaX.Mul(&omegaX, &domain.Generator)
		}
		invs := ext.BatchInvertE4(denoms)

		// Sweep bundles into deepQuotient row by row.
		for b := range bundles {
			bun := &bundles[b]
			invRow := invs[b*chunkLen : (b+1)*chunkLen]
			for x := start; x < end; x++ {
				Cx := bun.constContrib
				for k, col := range bun.extCols {
					var term ext.E4
					term.Mul(&bun.extScales[k], &col[x])
					Cx.Add(&Cx, &term)
				}
				for k, col := range bun.baseCols {
					var term ext.E4
					term.MulByElement(&bun.baseScales[k], &col[x])
					Cx.Add(&Cx, &term)
				}
				var num, dqx ext.E4
				num.Sub(&bun.vs, &Cx)
				dqx.Mul(&num, &invRow[x-start])
				deepQuotient[x].Add(&deepQuotient[x], &dqx)
			}
		}
	})
}

// openWMerkleAt opens a WMerkleTree at the leaf index corresponding to FRI
// query position `s`, reduced mod the tree's paired-leaf count (=
// encoded_size/2 = RATE·N/2).
func openWMerkleAt(tree commitment.WMerkleTree, source commitmentOpeningSource, s int, domainCache *poly.DomainCache) (commitment.WMerkleProof, error) {
	leafCount := tree.NumLeaves()
	if leafCount == 0 {
		return commitment.WMerkleProof{}, fmt.Errorf("empty WMerkleTree")
	}
	pos := s % leafCount
	pth, err := tree.OpenProof(pos)
	if err != nil {
		return commitment.WMerkleProof{}, err
	}
	rawLeafBase, rawLeafExt, err := source.rawLeaf(pos, leafCount, domainCache)
	if err != nil {
		return commitment.WMerkleProof{}, err
	}
	if len(rawLeafBase) != tree.BaseWidth() {
		return commitment.WMerkleProof{}, fmt.Errorf("base raw leaf width %d, tree expects %d", len(rawLeafBase), tree.BaseWidth())
	}
	if len(rawLeafExt) != tree.ExtWidth() {
		return commitment.WMerkleProof{}, fmt.Errorf("extension raw leaf width %d, tree expects %d", len(rawLeafExt), tree.ExtWidth())
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
			wp, err := openWMerkleAt(tree, pr.openingSources[i], s, &pr.domainCache)
			if err != nil {
				return fmt.Errorf("SampleEvaluations: tree %d query %d: %w", i, q, err)
			}
			samplings[i] = wp
		}
		pr.Proof.PointSamplings[q] = samplings
	}
	return nil
}

func Prove(t trace.Trace, provingKey setup.ProvingKey, publicInputs public.Inputs, program board.Program, opts ...Option) (proof.Proof, error) {

	var config Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return proof.Proof{}, err
		}
	}

	pr, err := newProverRuntime(t, provingKey, publicInputs, program, config)
	if err != nil {
		return proof.Proof{}, err
	}

	report := func(name string, d time.Duration) {
		if config.PhaseCallback != nil {
			config.PhaseCallback(name, d)
		}
	}

	// run ExecuteSteps
	t0 := time.Now()
	if err := pr.ExecuteSteps(); err != nil {
		return proof.Proof{}, err
	}
	report("execute-steps", time.Since(t0))

	// run ComputeAIRQuotients
	t0 = time.Now()
	if err := pr.ComputeAIRQuotients(); err != nil {
		return proof.Proof{}, err
	}
	report("compute-air-quotients", time.Since(t0))

	// run ComputeEvaluationsAtZeta
	t0 = time.Now()
	if err := pr.ComputeEvaluationsAtZeta(); err != nil {
		return proof.Proof{}, err
	}
	report("evaluations-at-zeta", time.Since(t0))

	// ------ PCS related verification ------

	if !config.SkipFRI {
		// Compute DEEP quotient and FRI-prove that it is the evaluation of a polynomial of degree N
		t0 = time.Now()
		if err := pr.ComputeDeepQuotient(); err != nil {
			return proof.Proof{}, err
		}
		report("deep-quotient+fri-commit", time.Since(t0))

		// Brige FRI <-> polynomial commitments, using sample at queryPositions
		t0 = time.Now()
		if err := pr.SampleEvaluations(); err != nil {
			return proof.Proof{}, err
		}
		report("fri-query-open", time.Since(t0))
	}

	return pr.Proof, nil
}
