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
	"sort"
	"sync"

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
	EmulateFS   bool
	SkipFRI     bool
	HashBackend commitment.HashBackend
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
	mu             sync.Mutex
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
		mu:           sync.Mutex{}, // mutex to protect the trace when reading/writing (in case of parallelisation)
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
			err := s.Execute(pr.t, &pr.program, &pr.Proof, &pr.mu)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// computeExtAIRChunks computes the AIR quotient for a single ext-rooted module
// and returns its N-sized chunks in Lagrange form, ready to commit. Chunks
// alias non-overlapping windows of the quotient backing array (no per-chunk
// copy); after this returns the caller owns the chunks and the original
// quotient is unreachable.
func computeExtAIRChunks(piBase map[string]poly.Polynomial, piExt map[string]poly.ExtPolynomial, vrel *dag.DAG, N int, D *fft.Domain, cache *poly.DomainCache) ([]poly.ExtPolynomial, error) {
	quotient, err := poly.ComputeQuotientMixed(piBase, piExt, *vrel, N, poly.WithDomainCache(cache))
	if err != nil {
		return nil, err
	}
	// quotient is in coset-Lagrange Normal; convert directly to canonical
	// Normal so chunking can sub-slice the backing array.
	poly.CosetExtLagrangeNormalToCanonicalWithCache(quotient, cache)

	chunks := make([]poly.ExtPolynomial, len(quotient)/N)
	for i := range chunks {
		chunk := quotient[i*N : (i+1)*N : (i+1)*N]
		D.FFTExt(chunk, fft.DIF)
		utils.BitReverse(chunk)
		chunks[i] = chunk
	}
	return chunks, nil
}

// computeBaseAIRChunks is the base-field counterpart of computeExtAIRChunks.
func computeBaseAIRChunks(piBase map[string]poly.Polynomial, vrel *dag.DAG, N int, D *fft.Domain, cache *poly.DomainCache) ([]poly.Polynomial, error) {
	quotient, err := poly.ComputeQuotient(piBase, *vrel, N, poly.WithDomainCache(cache))
	if err != nil {
		return nil, err
	}
	poly.CosetLagrangeNormalToCanonicalWithCache(quotient, cache)

	chunks := make([]poly.Polynomial, len(quotient)/N)
	for i := range chunks {
		chunk := quotient[i*N : (i+1)*N : (i+1)*N]
		D.FFT(chunk, fft.DIF)
		utils.BitReverse(chunk)
		chunks[i] = chunk
	}
	return chunks, nil
}

func (pr *proverRuntime) ComputeAIRQuotients() error {
	chunkDomains := make(map[string]*fft.Domain)

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
				extChunks, err = computeExtAIRChunks(pr.t.Base, pr.t.Ext, vrel, N, module.D, &pr.domainCache)
			} else {
				baseChunks, err = computeBaseAIRChunks(pr.t.Base, vrel, N, module.D, &pr.domainCache)
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
				chunkDomains[name] = module.D
			}
			for i, c := range extChunks {
				name := constants.QuotientChunkName(moduleName, i)
				pr.airTrace.SetExt(name, c)
				chunkDomains[name] = module.D
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

	chunkNames := make([]string, 0, len(pr.airTrace.Base)+len(pr.airTrace.Ext))
	for name := range pr.airTrace.Base {
		chunkNames = append(chunkNames, name)
	}
	for name := range pr.airTrace.Ext {
		chunkNames = append(chunkNames, name)
	}
	sort.Strings(chunkNames)

	evals := make([]ext.E4, len(chunkNames))
	parallel.Execute(len(chunkNames), func(start, end int) {
		for i := start; i < end; i++ {
			name := chunkNames[i]
			if p, ok := pr.airTrace.Base[name]; ok {
				evals[i] = poly.EvaluateAtExt(p, chunkDomains[name], pr.zeta)
			} else {
				evals[i] = poly.ExtEvaluateAtExt(pr.airTrace.Ext[name], chunkDomains[name], pr.zeta)
			}
		}
	})
	for i, name := range chunkNames {
		pr.Proof.SetValueAtZetaExt(name, evals[i])
	}

	return nil
}

// ComputeEvaluationsAtZeta computes the evaluations at zeta of every polynomial
// appearing in every vanishing relation of every module.
func (pr *proverRuntime) ComputeEvaluationsAtZeta() error {
	config := expr.NewConfig(
		expr.WithoutLagrangeColumns(),
		expr.WithoutChallenges(),
		expr.WithoutExposedColumns(),
		expr.WithoutPublicColumns(),
	)

	type zetaEval struct {
		key string
		val ext.E4
	}

	moduleNames := make([]string, 0, len(pr.program.Modules))
	for name := range pr.program.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	results := make([][]zetaEval, len(moduleNames))
	errs := make([]error, len(moduleNames))
	parallel.Execute(len(moduleNames), func(start, end int) {
		for idx := start; idx < end; idx++ {
			module := pr.program.Modules[moduleNames[idx]]
			leaves := module.VanishingRelation.LeavesFull(config)
			local := make([]zetaEval, 0, len(leaves))
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
					local = append(local, zetaEval{key: leaf.String(), val: val})
					continue
				}
				p, ok := pr.t.Base[leaf.Name]
				if !ok {
					errs[idx] = fmt.Errorf("ComputeEvaluationsAtZeta: column %q not found in trace", leaf.Name)
					return
				}
				val := poly.EvaluateAtExt(p, module.D, evalPoint)
				local = append(local, zetaEval{key: leaf.String(), val: val})
			}
			results[idx] = local
		}
	})
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	for _, local := range results {
		for _, ev := range local {
			pr.Proof.SetValueAtZetaExt(ev.key, ev.val)
		}
	}
	return nil
}

func addScaledExtColumn(dst, col, scratch poly.ExtPolynomial, alpha *ext.E4) {
	if len(col) == 1 {
		var term ext.E4
		term.Mul(&col[0], alpha)
		for i := range dst {
			dst[i].Add(&dst[i], &term)
		}
		return
	}
	ext.Vector(scratch).ScalarMul(ext.Vector(col), alpha)
	ext.Vector(dst).Add(ext.Vector(dst), ext.Vector(scratch))
}

func addScaledBaseColumn(dst poly.ExtPolynomial, col poly.Polynomial, alpha *ext.E4) {
	if len(col) == 1 {
		var term ext.E4
		term.MulByElement(alpha, &col[0])
		for i := range dst {
			dst[i].Add(&dst[i], &term)
		}
		return
	}
	ext.Vector(dst).MulAccByElement(col, alpha)
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
		scratch := make(poly.ExtPolynomial, N)

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
				if hasExt {
					addScaledExtColumn(C_s, colExt, scratch, &alphaAcc)
				} else {
					addScaledBaseColumn(C_s, colBase, &alphaAcc)
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
				if hasExt {
					addScaledExtColumn(C_s, chunkExt, scratch, &alphaAcc)
				} else {
					addScaledBaseColumn(C_s, chunkBase, &alphaAcc)
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
