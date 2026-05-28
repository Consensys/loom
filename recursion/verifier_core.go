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

package recursion

import (
	"fmt"
	"sort"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/public"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/airzeta"
	"github.com/consensys/loom/recursion/gadgets/challenger24"
	"github.com/consensys/loom/trace"
)

// fiatshamir-private constant from internal/fiat-shamir/transcript.go.
// Duplicated here because the original is unexported. If Loom ever
// changes that value, this constant must change too.
const challengeIDDomainTag uint64 = 0x46534944 // "FSID"


// buildVerifierCore compiles a board.Program that verifies a single
// inner Loom proof, along with a witness trace satisfying it.
//
// STAGE 1 SCOPE: implements only the per-module AIR-at-zeta check
//
//	V(zeta) == (zeta^N - 1) * Q(zeta)
//
// for every module of the inner program. The verifier trusts the
// trace generator to populate the column-at-zeta values correctly
// from the inner proof — FRI, Merkle openings, DEEP bridge, and FS
// challenge derivation are NOT yet enforced in-circuit. Adding those
// is the work of subsequent stages; the AIR check is the foundation
// they all bolt onto.
//
// Outer-program layout:
//
//   - A single "verifier" module of size N=2 carrying every witness
//     column: zeta (4 limbs), per-leaf E4 values (4 limbs each), and
//     per-AIR-quotient-chunk E4 values (4 limbs each).
//   - Per inner module: one airzeta.RegisterAIRCheck call wires the
//     per-module DAG + chunks + N into 4 equality constraints (one
//     per E4 limb).
//
// Inner DAG leaves currently supported:
//   - CommittedColumn / RotatedColumn / ChallengeColumn — pulled
//     directly from inner proof.ValuesAtZeta.
//   - LagrangeColumn — computed natively via poly.LagrangeAtZetaExt.
//
// Inner DAG leaves NOT YET supported (returns error):
//   - PublicInputColumn — requires reading from the inner statement's
//     PublicInputs; future work.
//   - ExposedColumn — requires reconstructing from proof.ExposedValues;
//     future work.
func buildVerifierCore(input RecursionInput, cfg Config) (board.Program, trace.Trace, error) {
	if err := validateInnerProof(input.Proof, cfg); err != nil {
		return board.Program{}, trace.Trace{}, err
	}

	// Derive zeta natively by replaying the inner proof's FS transcript.
	// Stage 2+ will re-derive zeta in-circuit via the challenger gadget.
	zeta, challengeVals, err := replayInnerFS(input)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: replay inner FS: %w", err)
	}
	// Mirror the prover's challenge populating so that any ChallengeColumn
	// leaves resolve correctly.
	for name, val := range challengeVals {
		if _, ok := input.Proof.ValueAtZetaExt(name); !ok {
			input.Proof.SetValueAtZetaExt(name, val)
		}
	}

	// Resolve every leaf-at-zeta value for every inner module's DAG.
	type moduleData struct {
		name     string
		mod      board.CompiledModule
		leafVals map[string]ext.E4
		chunks   []ext.E4
	}
	mods := make([]moduleData, 0, len(input.Program.Modules))

	for _, name := range sortedModuleNames(input.Program) {
		m := input.Program.Modules[name]
		data := moduleData{name: name, mod: m, leafVals: map[string]ext.E4{}}

		if err := collectLeafValuesAtZeta(name, m, zeta, input.Proof, input.PublicInputs, data.leafVals); err != nil {
			return board.Program{}, trace.Trace{}, err
		}

		// Collect AIR quotient chunks for this module.
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(name, i)
			v, ok := input.Proof.ValueAtZetaExt(chunkName)
			if !ok {
				break
			}
			data.chunks = append(data.chunks, v)
		}
		mods = append(mods, data)
	}

	// Stage 3: derive zeta in-circuit via a chain of challenger24 sponges
	// (one per FS challenge in the inner proof's transcript). Each
	// sponge's input expressions include constants for name/bindings
	// and Rot references to the previous sponge's digest for the
	// previous-challenge slot.
	chain, err := computeChallengeChain(input)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: build challenge chain: %w", err)
	}

	// Total sponge rows across the chain.
	totalPerms := 0
	for _, step := range chain {
		totalPerms += challenger24.NumPermutationsExternal(len(step.NativeInputs))
	}
	n := nextPow2Internal(totalPerms)
	if n < 2 {
		n = 2
	}

	builder := board.NewBuilder()
	verifierMod := board.NewModule("airverify")
	verifierMod.N = n

	// Register sponges in chain order. Each sponge gets its own prefix.
	chSpongeCNs := make([]challenger24.ColumnNames, len(chain))
	startRow := 0
	for i, step := range chain {
		inputs := make([]expr.Expr, len(step.NativeInputs))
		for j, v := range step.NativeInputs {
			inputs[j] = expr.Const(v)
		}
		// If this isn't the first challenge, override the previous-digest
		// slots with Rot references to the previous sponge's digest
		// columns. The Rot offset is -1 because the previous sponge's
		// digest lives at module row (startRow - 1).
		if !step.IsFirst {
			prevCN := chSpongeCNs[i-1]
			for d := 0; d < challenger24.DigestLen; d++ {
				inputs[step.PrevDigestStart+d] = expr.Rot(prevCN.Digest[d], -1)
			}
		}
		prefix := fmt.Sprintf("airverify.ch%d", i)
		cn := challenger24.RegisterAt(&verifierMod, prefix, inputs, startRow)
		chSpongeCNs[i] = cn
		startRow += cn.NPermutations
	}
	// Final challenger (last in chain) produces zeta.
	chCN := chSpongeCNs[len(chSpongeCNs)-1]

	// zeta limbs are the first 4 digest limbs in OutputToExt order:
	//   limb[0] = digest[0]   (B0.A0)
	//   limb[1] = digest[2]   (B1.A0)
	//   limb[2] = digest[1]   (B0.A1)
	//   limb[3] = digest[3]   (B1.A1)
	zetaCols := [extfield.Limbs]string{
		chCN.Digest[0], chCN.Digest[2], chCN.Digest[1], chCN.Digest[3],
	}
	zetaExpr := extfield.FromLimbs(
		expr.Col(zetaCols[0]), expr.Col(zetaCols[1]),
		expr.Col(zetaCols[2]), expr.Col(zetaCols[3]),
	)

	// Per-module witness columns + AIR check registration.
	type allocation struct {
		colName string
		value   koalabear.Element
	}
	var traceFill []allocation

	addE4 := func(prefix string, v ext.E4) extfield.E4Expr {
		limbs := extfield.FromE4(v)
		var names [extfield.Limbs]string
		for i := 0; i < extfield.Limbs; i++ {
			names[i] = prefix + "_" + string('0'+rune(i))
			traceFill = append(traceFill, allocation{colName: names[i], value: limbs[i]})
		}
		return extfield.FromLimbs(
			expr.Col(names[0]), expr.Col(names[1]),
			expr.Col(names[2]), expr.Col(names[3]),
		)
	}

	for _, data := range mods {
		// Allocate leaf-value E4 columns for this module's DAG.
		leafExprs := make(map[string]extfield.E4Expr, len(data.leafVals))
		leafKeys := make([]string, 0, len(data.leafVals))
		for k := range data.leafVals {
			leafKeys = append(leafKeys, k)
		}
		sort.Strings(leafKeys)
		for _, k := range leafKeys {
			leafExprs[k] = addE4(fmt.Sprintf("airverify.%s.leaf_%s", data.name, sanitizeName(k)), data.leafVals[k])
		}

		// Allocate quotient-chunk E4 columns.
		chunkExprs := make([]extfield.E4Expr, len(data.chunks))
		for i, c := range data.chunks {
			chunkExprs[i] = addE4(fmt.Sprintf("airverify.%s.chunk_%d", data.name, i), c)
		}

		// AIR check fires at the digest row only — that's the single row
		// where zeta-limb columns actually hold the FS-derived value.
		airzeta.RegisterAIRCheckAtRow(
			&verifierMod,
			data.mod.VanishingRelation,
			data.mod.N,
			leafExprs,
			zetaExpr,
			chunkExprs,
			chCN.DigestRow,
		)
	}

	builder.AddModule(verifierMod)

	// Fill trace: the witness leaf/chunk columns get their value at every
	// row (the value-at-zeta is constant; padding rows are fine since the
	// AIR check is row-gated). Then layer in the challenger24 sponge
	// sub-columns from the native sponge replay.
	tr := trace.New()
	for _, a := range traceFill {
		col := make([]koalabear.Element, verifierMod.N)
		for r := range col {
			col[r].Set(&a.value)
		}
		tr.SetBase(a.colName, col)
	}

	// Trace fill for each sponge in the chain. Each call to
	// GenerateTraceWithSize produces a different set of columns (its
	// own poseidon2sponge sub-trace under prefix airverify.ch<i>.sp).
	for i, step := range chain {
		chCols, _ := challenger24.GenerateTraceWithSize(chSpongeCNs[i], n, step.NativeInputs)
		for k, v := range chCols {
			tr.SetBase(k, v)
		}
	}

	// Sanity check: the final sponge's digest must equal the natively-
	// derived zeta. If this fails, the FS replay / chain build has a bug.
	expectedZeta := hashDigestToE4(chain[len(chain)-1].NativeDigest)
	if !expectedZeta.Equal(&zeta) {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: chain digest != native zeta")
	}

	pg, err := board.Compile(&builder)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: compile verifier: %w", err)
	}
	return pg, tr, nil
}

// challengeStep describes one challenge in the inner proof's FS chain.
// PrevDigestStart is the position in NativeInputs where the previous
// challenge's digest is absorbed (only meaningful when IsFirst is
// false). PrevDigestStart + 8 must be <= Rate so the prev digest fits
// in chunk_0 — that simplifies the in-circuit Rot wiring (currently
// the only supported layout).
type challengeStep struct {
	Name            string
	NativeInputs    []koalabear.Element
	NativeDigest    hash.Digest
	IsFirst         bool
	PrevDigestStart int
}

// computeChallengeChain replays the inner proof's FS transcript to
// produce, for every challenge in the chain, the absorbed-element
// sequence and the resulting digest. Each step's native sequence is:
//
//	NameEncoded || PrevDigest (if not first) || Bindings
//
// where Bindings is everything fs.Bind()ed to this challenge in order.
//
// The chain terminates with the __zeta challenge — DEEP_ALPHA and
// later challenges aren't included yet (they'd be the next milestone
// for full FS soundness).
func computeChallengeChain(input RecursionInput) ([]challengeStep, error) {
	hb, err := commitment.HashBackendByID(input.Proof.HashBackendID)
	if err != nil {
		return nil, err
	}

	pg := input.Program
	layout := prover.BuildLayout(pg, 0)

	roots := make([]hash.Digest, layout.NumTrees)
	for i, r := range input.Proof.Commitments {
		roots[layout.SetupEnd+i] = r
	}

	numRounds := len(pg.FScolumnsDependencies)
	fs := fiatshamir.NewTranscript(hb.NewTranscriptHasher())
	for i := 0; i < numRounds; i++ {
		if err := fs.NewChallenge(constants.CanonicalChallengeName(i)); err != nil {
			return nil, err
		}
	}
	if err := fs.NewChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
		return nil, err
	}

	// Build the per-challenge binding sequences in the order the inner
	// verifier accumulates them.
	bindings := make(map[string][]koalabear.Element)
	initialChallenge := constants.InitialChallengeName(numRounds)

	bindings[initialChallenge] = append(bindings[initialChallenge],
		hash.StringToElements(constants.HASH_BACKEND_DOMAIN_TAG, hb.ID)...)
	if err := fs.Bind(initialChallenge, hash.StringToElements(constants.HASH_BACKEND_DOMAIN_TAG, hb.ID)); err != nil {
		return nil, err
	}
	if len(input.PublicInputs) > 0 {
		te := input.PublicInputs.TranscriptElements()
		bindings[initialChallenge] = append(bindings[initialChallenge], te...)
		if err := fs.Bind(initialChallenge, te); err != nil {
			return nil, err
		}
	}

	// Per-round trace roots get bound to canonical_<r>.
	for r := 0; r < numRounds; r++ {
		name := constants.CanonicalChallengeName(r)
		for i := layout.TraceBegin[r]; i < layout.TraceEnd[r]; i++ {
			root := roots[i]
			bindings[name] = append(bindings[name], root[:]...)
			if err := fs.Bind(name, root[:]); err != nil {
				return nil, err
			}
		}
	}

	// AIR roots bind to __zeta.
	for i := layout.AIRBegin; i < layout.AIREnd; i++ {
		root := roots[i]
		bindings[constants.FINAL_EVALUATION_POINT] = append(bindings[constants.FINAL_EVALUATION_POINT], root[:]...)
		if err := fs.Bind(constants.FINAL_EVALUATION_POINT, root[:]); err != nil {
			return nil, err
		}
	}

	// Compute each challenge in order, recording the sequence absorbed.
	challengeNames := make([]string, 0, numRounds+1)
	for r := 0; r < numRounds; r++ {
		challengeNames = append(challengeNames, constants.CanonicalChallengeName(r))
	}
	challengeNames = append(challengeNames, constants.FINAL_EVALUATION_POINT)

	steps := make([]challengeStep, 0, len(challengeNames))
	for i, name := range challengeNames {
		var seq []koalabear.Element
		seq = append(seq, hash.StringToElements(challengeIDDomainTag, name)...)
		nameLen := len(seq)
		prevDigestStart := -1
		if i > 0 {
			prevDigestStart = nameLen
			seq = append(seq, steps[i-1].NativeDigest[:]...)
		}
		seq = append(seq, bindings[name]...)

		digest, err := fs.ComputeChallenge(name)
		if err != nil {
			return nil, err
		}
		// Cross-check: native digest should equal the value the fs
		// transcript just produced. (This is a sanity check on our
		// chain reconstruction.)
		if !chainDigestsEqual(digest, sumOf(seq, hb)) {
			return nil, fmt.Errorf("recursion: computeChallengeChain reconstruction mismatch for challenge %q", name)
		}

		if i > 0 && prevDigestStart+8 > challenger24.Rate {
			return nil, fmt.Errorf("recursion: challenge %q has prev_digest spanning sponge chunks (name encoding %d elts, total before bindings %d); current wiring requires it to fit in chunk_0 (Rate=%d)", name, nameLen, prevDigestStart+8, challenger24.Rate)
		}

		steps = append(steps, challengeStep{
			Name:            name,
			NativeInputs:    seq,
			NativeDigest:    digest,
			IsFirst:         i == 0,
			PrevDigestStart: prevDigestStart,
		})
	}
	return steps, nil
}

// chainDigestsEqual compares two digests element-wise (avoids needing a
// dependency on hash.Digest equality method).
func chainDigestsEqual(a, b hash.Digest) bool {
	for i := range a {
		if !a[i].Equal(&b[i]) {
			return false
		}
	}
	return true
}

// sumOf returns the Poseidon2-sponge digest of seq using a fresh hasher
// for hb — a standalone reference value to cross-check the FS replay.
func sumOf(seq []koalabear.Element, hb commitment.HashBackend) hash.Digest {
	h := hb.NewTranscriptHasher()
	h.Reset()
	h.WriteElements(seq...)
	return h.Sum()
}

// hashDigestToE4 mirrors hash.OutputToExt for an 8-element digest:
// the first 4 elements become an E4 with the OutputToExt mapping.
func hashDigestToE4(d hash.Digest) ext.E4 {
	var v ext.E4
	v.B0.A0.Set(&d[0])
	v.B0.A1.Set(&d[1])
	v.B1.A0.Set(&d[2])
	v.B1.A1.Set(&d[3])
	return v
}

func nextPow2Internal(n int) int {
	if n <= 1 {
		return 1
	}
	r := 1
	for r < n {
		r <<= 1
	}
	return r
}

// replayInnerFS replays the inner proof's Fiat-Shamir transcript to
// derive zeta and every canonical round challenge. Returns zeta plus a
// map of canonical-challenge-name → value so the caller can populate
// the inner proof's ValuesAtZeta with them (the prover does not write
// these — only the verifier does).
//
// Mirrors verifier.deriveChallenges + the FS-setup logic in
// newVerifierRuntime.
func replayInnerFS(input RecursionInput) (ext.E4, map[string]ext.E4, error) {
	hb, err := commitment.HashBackendByID(input.Proof.HashBackendID)
	if err != nil {
		return ext.E4{}, nil, err
	}

	pg := input.Program
	layout := prover.BuildLayout(pg, 0 /*numSetupSizes*/)

	// Flatten setup roots ++ proof.Commitments. We don't currently
	// support setup; setup section is empty.
	roots := make([]hash.Digest, layout.NumTrees)
	for i, r := range input.Proof.Commitments {
		roots[layout.SetupEnd+i] = r
	}

	fs := fiatshamir.NewTranscript(hb.NewTranscriptHasher())
	numRounds := len(pg.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		if err := fs.NewChallenge(constants.CanonicalChallengeName(i)); err != nil {
			return ext.E4{}, nil, err
		}
	}
	if err := fs.NewChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
		return ext.E4{}, nil, err
	}

	initialChallenge := constants.InitialChallengeName(numRounds)
	if err := fs.Bind(initialChallenge, hash.StringToElements(constants.HASH_BACKEND_DOMAIN_TAG, hb.ID)); err != nil {
		return ext.E4{}, nil, err
	}

	// PublicInputs (if any) are bound into the initial challenge before
	// any trace roots — matching newVerifierRuntime.
	if len(input.PublicInputs) > 0 {
		if err := fs.Bind(initialChallenge, input.PublicInputs.TranscriptElements()); err != nil {
			return ext.E4{}, nil, err
		}
	}

	// Per-round trace roots, then compute each round challenge.
	challengeVals := make(map[string]ext.E4)
	for r := 0; r < numRounds; r++ {
		name := constants.CanonicalChallengeName(r)
		for i := layout.TraceBegin[r]; i < layout.TraceEnd[r]; i++ {
			root := roots[i]
			if err := fs.Bind(name, root[:]); err != nil {
				return ext.E4{}, nil, err
			}
		}
		c, err := fs.ComputeChallenge(name)
		if err != nil {
			return ext.E4{}, nil, err
		}
		challengeVals[name] = hash.OutputToExt(c)
	}

	// AIR-quotient roots feed into the FINAL_EVALUATION challenge.
	for i := layout.AIRBegin; i < layout.AIREnd; i++ {
		root := roots[i]
		if err := fs.Bind(constants.FINAL_EVALUATION_POINT, root[:]); err != nil {
			return ext.E4{}, nil, err
		}
	}
	zetaDigest, err := fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return ext.E4{}, nil, err
	}
	return hash.OutputToExt(zetaDigest), challengeVals, nil
}

// sortedModuleNames returns the inner program's module names in
// deterministic order.
func sortedModuleNames(p board.Program) []string {
	names := make([]string, 0, len(p.Modules))
	for name := range p.Modules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// collectLeafValuesAtZeta walks the module's vanishing-relation DAG and
// resolves every non-constant leaf's value at zeta into the leafVals
// map.
//
//   - Committed / Rotated / Challenge: pulled directly from the inner
//     proof's ValuesAtZeta.
//   - Lagrange: computed natively via poly.LagrangeAtZetaExt.
//   - PublicInput: reconstructed as a sparse Lagrange sum from the
//     statement's PublicInputs entries.
//   - Exposed: reconstructed as a sparse Lagrange sum from the
//     proof's ExposedValues entries.
func collectLeafValuesAtZeta(
	modName string,
	m board.CompiledModule,
	zeta ext.E4,
	prf proof.Proof,
	publicInputs public.Inputs,
	out map[string]ext.E4,
) error {
	for _, node := range m.VanishingRelation.Nodes {
		if node.IsConst || node.Leaf == nil {
			continue
		}
		key := node.Leaf.String()
		if _, done := out[key]; done {
			continue
		}

		switch node.Leaf.Type {
		case expr.CommittedColumn, expr.RotatedColumn, expr.ChallengeColumn:
			v, ok := prf.ValueAtZetaExt(key)
			if !ok {
				return fmt.Errorf("recursion: %q (module %s) not in inner proof.ValuesAtZeta", key, modName)
			}
			out[key] = v
		case expr.LagrangeColumn:
			i := constants.ParseLagrangeName(node.Leaf.Name)
			if i < 0 {
				i = m.N + i
			}
			out[key] = poly.LagrangeAtZetaExt(zeta, m.N, i)
		case expr.PublicInputColumn:
			pi, ok := publicInputs[node.Leaf.Name]
			if !ok {
				return fmt.Errorf("recursion: PublicInputColumn %q (module %s) missing from RecursionInput.PublicInputs", key, modName)
			}
			if pi.Module != modName {
				return fmt.Errorf("recursion: PublicInputColumn %q claims module %q but is used from %q", key, pi.Module, modName)
			}
			out[key] = reconstructFromEntries(zeta, m.N, publicInputEntries(pi))
		case expr.ExposedColumn:
			ev, ok := prf.ExposedValues[node.Leaf.Name]
			if !ok {
				return fmt.Errorf("recursion: ExposedColumn %q (module %s) missing from inner proof.ExposedValues", key, modName)
			}
			out[key] = reconstructFromEntries(zeta, m.N, exposedEntries(ev))
		default:
			return fmt.Errorf("recursion: unknown leaf type %d for %q", node.Leaf.Type, key)
		}
	}
	return nil
}

// entryAtIdx pairs a Lagrange row index with its E4 value, abstracted
// so PublicInput entries and Exposed entries share a single
// reconstruction helper.
type entryAtIdx struct {
	Idx   int
	Value ext.E4
}

// reconstructFromEntries computes sum_e L_{N, e.Idx}(zeta) * e.Value,
// the Lagrange-interpolation form of a sparse column at zeta. Used to
// resolve both PublicInputColumn and ExposedColumn leaves.
func reconstructFromEntries(zeta ext.E4, N int, entries []entryAtIdx) ext.E4 {
	var acc ext.E4
	for _, e := range entries {
		lag := poly.LagrangeAtZetaExt(zeta, N, e.Idx)
		var term ext.E4
		term.Mul(&lag, &e.Value)
		acc.Add(&acc, &term)
	}
	return acc
}

func publicInputEntries(pi public.Input) []entryAtIdx {
	out := make([]entryAtIdx, len(pi.Entries))
	for i, e := range pi.Entries {
		out[i] = entryAtIdx{Idx: e.Idx, Value: e.ExtValue()}
	}
	return out
}

func exposedEntries(ev proof.ExposedValue) []entryAtIdx {
	out := make([]entryAtIdx, len(ev.Entries))
	for i, e := range ev.Entries {
		out[i] = entryAtIdx{Idx: e.Idx, Value: e.ExtValue()}
	}
	return out
}

// sanitizeName makes a leaf name safe for use as a column-name suffix:
// no whitespace, spaces, parens, or arithmetic operators that the AIR
// engine treats specially.
func sanitizeName(s string) string {
	r := make([]rune, 0, len(s))
	for _, c := range s {
		switch c {
		case ' ', '(', ')', '+', '-', '*', '^', '/', '\t', '\n':
			r = append(r, '_')
		default:
			r = append(r, c)
		}
	}
	return string(r)
}
