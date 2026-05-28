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
	"strings"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
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
	"github.com/consensys/loom/recursion/gadgets/bits"
	"github.com/consensys/loom/recursion/gadgets/challenger24"
	"github.com/consensys/loom/trace"
)

// fiatshamir-private constant from internal/fiat-shamir/transcript.go.
// Duplicated here because the original is unexported. If Loom ever
// changes that value, this constant must change too.
const challengeIDDomainTag uint64 = 0x46534944 // "FSID"


// BuildVerifierCore compiles a board.Program that verifies a single
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
func BuildVerifierCore(input RecursionInput, cfg Config) (board.Program, trace.Trace, error) {
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

	// Pre-pass: allocate every airverify witness column (per-module leaf
	// and chunk values) and build maps from inner-leaf/chunk keys to
	// limb column names. We do this BEFORE registering sponges so
	// DEEP_ALPHA can resolve its bindings to witness column refs.
	type allocation struct {
		colName string
		value   koalabear.Element
	}
	var traceFill []allocation
	keyToLeafCols := map[string][extfield.Limbs]string{}
	keyToChunkCols := map[string][extfield.Limbs]string{}

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

	type moduleWitnessRefs struct {
		leafExprs  map[string]extfield.E4Expr
		chunkExprs []extfield.E4Expr
	}
	witnesses := make([]moduleWitnessRefs, len(mods))

	for mi, data := range mods {
		leafExprs := make(map[string]extfield.E4Expr, len(data.leafVals))
		leafKeys := make([]string, 0, len(data.leafVals))
		for k := range data.leafVals {
			leafKeys = append(leafKeys, k)
		}
		sort.Strings(leafKeys)
		for _, k := range leafKeys {
			prefix := fmt.Sprintf("airverify.%s.leaf_%s", data.name, sanitizeName(k))
			leafExprs[k] = addE4(prefix, data.leafVals[k])
			if _, exists := keyToLeafCols[k]; !exists {
				keyToLeafCols[k] = [extfield.Limbs]string{
					prefix + "_0", prefix + "_1", prefix + "_2", prefix + "_3",
				}
			}
		}

		chunkExprs := make([]extfield.E4Expr, len(data.chunks))
		for i, c := range data.chunks {
			chunkName := constants.QuotientChunkName(data.name, i)
			prefix := fmt.Sprintf("airverify.%s.chunk_%d", data.name, i)
			chunkExprs[i] = addE4(prefix, c)
			if _, exists := keyToChunkCols[chunkName]; !exists {
				keyToChunkCols[chunkName] = [extfield.Limbs]string{
					prefix + "_0", prefix + "_1", prefix + "_2", prefix + "_3",
				}
			}
		}

		witnesses[mi] = moduleWitnessRefs{leafExprs: leafExprs, chunkExprs: chunkExprs}
	}

	// Now register sponges in chain order. For DEEP_ALPHA, substitute
	// the witness column references for its WitnessBindings positions.
	chSpongeCNs := make([]challenger24.ColumnNames, len(chain))
	startRow := 0
	for i, step := range chain {
		inputs := make([]expr.Expr, len(step.NativeInputs))
		for j, v := range step.NativeInputs {
			inputs[j] = expr.Const(v)
		}
		// Previous-digest Rot references for non-first challenges.
		if !step.IsFirst {
			prevCN := chSpongeCNs[i-1]
			for d := 0; d < challenger24.DigestLen; d++ {
				inputs[step.PrevDigestStart+d] = expr.Rot(prevCN.Digest[d], -1)
			}
		}
		// Witness-column substitutions for DEEP_ALPHA-style bindings.
		// extToElements order {B0.A0, B0.A1, B1.A0, B1.A1} maps to our
		// extfield limb order via {0, 2, 1, 3}.
		for _, b := range step.WitnessBindings {
			var cols [extfield.Limbs]string
			var ok bool
			if b.IsChunk {
				cols, ok = keyToChunkCols[b.Key]
			} else {
				cols, ok = keyToLeafCols[b.Key]
			}
			if !ok {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: WitnessBinding key %q (chunk=%v) has no witness column allocated", b.Key, b.IsChunk)
			}
			inputs[b.Start+0] = expr.Col(cols[0])
			inputs[b.Start+1] = expr.Col(cols[2])
			inputs[b.Start+2] = expr.Col(cols[1])
			inputs[b.Start+3] = expr.Col(cols[3])
		}

		prefix := fmt.Sprintf("airverify.ch%d", i)
		cn := challenger24.RegisterAt(&verifierMod, prefix, inputs, startRow)
		chSpongeCNs[i] = cn
		startRow += cn.NPermutations
	}

	// Locate zeta sponge for the AIR check.
	zetaSpongeIdx := -1
	for i, step := range chain {
		if step.Name == constants.FINAL_EVALUATION_POINT {
			zetaSpongeIdx = i
			break
		}
	}
	if zetaSpongeIdx < 0 {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: __zeta missing from chain")
	}
	chCN := chSpongeCNs[zetaSpongeIdx]

	// zeta limbs in OutputToExt order: limb[0]=digest[0] (B0.A0),
	// limb[1]=digest[2] (B1.A0), limb[2]=digest[1] (B0.A1),
	// limb[3]=digest[3] (B1.A1).
	zetaExpr := extfield.FromLimbs(
		expr.Col(chCN.Digest[0]), expr.Col(chCN.Digest[2]),
		expr.Col(chCN.Digest[1]), expr.Col(chCN.Digest[3]),
	)

	// Materialize a witness-column chain of zeta^(2^i) so per-module
	// zeta^N can be referenced as cheap expr.Col rather than inlined as
	// a degree-N polynomial in the four zeta limbs. Without this the
	// constraint tree blows up exponentially in N (each E4 squaring
	// roughly squares the per-limb expression size; by i=4 we hit
	// billions of nodes).
	//
	// chain[0] = zeta (the sparse witness from the __zeta sponge).
	// chain[i] (i>0) = 4 fresh witness columns, constrained at
	// chCN.DigestRow to equal chain[i-1].Square(). Off-row values are
	// free (the AIR check is row-gated too), so the constraint stays
	// sparse and degree-2.
	maxModN := 1
	for _, data := range mods {
		if data.mod.N > maxModN {
			maxModN = data.mod.N
		}
	}
	maxZetaLog2 := log2int(maxModN)
	zetaPowChain := make([]extfield.E4Expr, maxZetaLog2+1)
	zetaPowChain[0] = zetaExpr

	zetaPowNative := make([]ext.E4, maxZetaLog2+1)
	zetaPowNative[0] = zeta
	for i := 1; i <= maxZetaLog2; i++ {
		zetaPowNative[i].Square(&zetaPowNative[i-1])

		prefix := fmt.Sprintf("airverify.zetaPow_%d", 1<<i)
		curExpr := addE4(prefix, zetaPowNative[i])

		prevSquared := zetaPowChain[i-1].Square()
		for _, rel := range curExpr.EqualityConstraints(prevSquared) {
			verifierMod.AssertZeroAt(rel, chCN.DigestRow)
		}
		zetaPowChain[i] = curExpr
	}

	// Register the AIR-at-zeta check per inner module, using the
	// pre-materialized zeta^N where N = 2^logN for the module.
	for mi, data := range mods {
		logN := log2int(data.mod.N)
		airzeta.RegisterAIRCheckAtRowWithZetaPow(
			&verifierMod,
			data.mod.VanishingRelation,
			witnesses[mi].leafExprs,
			zetaPowChain[logN],
			witnesses[mi].chunkExprs,
			chCN.DigestRow,
		)
	}

	// Stage 8: per-query final-poly match check. For each query k, verify
	// that the last fold's output equals finalPoly[s_k mod len(finalPoly)],
	// where s_k is the query position extracted from fri_query_k's digest
	// limb by an in-circuit bit decomposition. This is the FRI verifier's
	// final-round check (internal/fri/fri.go checkQueryExt). Remaining FRI
	// soundness (cross-round fold chain, Merkle openings, DEEP bridge)
	// follows in subsequent stages.
	type sparseBitAlloc struct {
		colName string
		rowIdx  int
		bit     bool
	}
	var sparseBits []sparseBitAlloc
	if len(input.Proof.DeepQuotientCommitment) > 0 {
		friProof := input.Proof.DeepQuotientFriProof
		finalPolyExt := friProof.FinalPolyExt
		if len(finalPolyExt) == 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: FRI present but FinalPolyExt empty")
		}
		// Domain-size sanity: the final layer has cardinality len(finalPoly),
		// so the last-fold input domain has size 2*len(finalPoly).
		nLastRound := 2 * len(finalPolyExt)
		if nLastRound&(nLastRound-1) != 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: 2*len(finalPolyExt) = %d not power of two", nLastRound)
		}
		// base_last_k = s_k mod len(finalPolyExt). For Loom's typical
		// configuration (final layer ≥ 2), this is at least one bit; we
		// require ≥ 2 so the inline mux below has work to do.
		baseLastBits := log2int(len(finalPolyExt))
		if baseLastBits != 2 {
			// Generalising to arbitrary baseLastBits is a future-work item;
			// the inline mux is hardcoded for 2-bit indexing.
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 8 currently supports len(finalPoly)=4 only, got %d", len(finalPolyExt))
		}

		// Locate last-fold and per-query sponge indices in the chain.
		// friNumRounds = log2(maxN) by Loom's FRI parameter convention
		// (D == maxN of any inner module, numRounds := log2(D)).
		lastFoldName := friFoldName(log2int(maxModN) - 1)
		lastFoldStepIdx := -1
		var queryStepIdxs []int
		for i, step := range chain {
			if step.Name == lastFoldName {
				lastFoldStepIdx = i
			}
			if strings.HasPrefix(step.Name, "fri_query_") {
				queryStepIdxs = append(queryStepIdxs, i)
			}
		}
		if lastFoldStepIdx < 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: %s missing from chain", lastFoldName)
		}
		if len(queryStepIdxs) == 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: no fri_query_k steps in chain")
		}

		// Anchor alpha_last to the chain digest of fri_fold_{r-1}: at the
		// last-fold sponge's digest row, the witness column equals the
		// digest in OutputToExt limb order. The same witness column then
		// supplies a usable E4Expr at every other row.
		lastFoldCN := chSpongeCNs[lastFoldStepIdx]
		lastFoldDigestExpr := extfield.FromLimbs(
			expr.Col(lastFoldCN.Digest[0]), expr.Col(lastFoldCN.Digest[2]),
			expr.Col(lastFoldCN.Digest[1]), expr.Col(lastFoldCN.Digest[3]),
		)
		// alpha_last is the OutputToExt of the chain's last-fold digest.
		// replayInnerFS doesn't compute past FINAL_EVALUATION_POINT, so
		// we read it from the chain step's NativeDigest directly.
		alphaLastNative := hashDigestToE4(chain[lastFoldStepIdx].NativeDigest)
		alphaLastExpr := addE4("airverify.fri_alpha_last", alphaLastNative)
		for _, rel := range alphaLastExpr.EqualityConstraints(lastFoldDigestExpr) {
			verifierMod.AssertZeroAt(rel, lastFoldCN.DigestRow)
		}

		// Build the constant xInv table {omega^{-i}} and the finalPoly
		// table as 4-element ext.E4 slices.
		omegaLast, err := koalabear.Generator(uint64(nLastRound))
		if err != nil {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: omega_last gen: %w", err)
		}
		var omegaInv koalabear.Element
		omegaInv.Inverse(&omegaLast)
		xInvTable := make([]ext.E4, len(finalPolyExt))
		var pow koalabear.Element
		pow.SetOne()
		for i := range xInvTable {
			xInvTable[i].B0.A0.Set(&pow)
			pow.Mul(&pow, &omegaInv)
		}

		var invTwoBase koalabear.Element
		var twoBase koalabear.Element
		twoBase.SetUint64(2)
		invTwoBase.Inverse(&twoBase)
		invTwoConst := expr.Const(invTwoBase)
		oneConst := expr.Const(koalabear.One())

		// 4-element E4 select indexed by (b0 + 2*b1) — bit values in {0, 1}.
		e4Select4 := func(t [4]ext.E4, b0, b1 expr.Expr) extfield.E4Expr {
			notB0 := oneConst.Sub(b0)
			notB1 := oneConst.Sub(b1)
			s00 := notB0.Mul(notB1)
			s10 := b0.Mul(notB1)
			s01 := notB0.Mul(b1)
			s11 := b0.Mul(b1)
			return extfield.Const(t[0]).MulByBase(s00).
				Add(extfield.Const(t[1]).MulByBase(s10)).
				Add(extfield.Const(t[2]).MulByBase(s01)).
				Add(extfield.Const(t[3]).MulByBase(s11))
		}

		// Common 4-element table populated from finalPolyExt and xInvTable.
		var finalPolyArr [4]ext.E4
		var xInvArr [4]ext.E4
		for i := 0; i < 4; i++ {
			finalPolyArr[i] = finalPolyExt[i]
			xInvArr[i] = xInvTable[i]
		}

		for k, queryStepIdx := range queryStepIdxs {
			querySpongeCN := chSpongeCNs[queryStepIdx]
			queryDigestRow := querySpongeCN.DigestRow

			// 31-bit decomposition of digest[1] at the digest row. We only
			// use bits[0..1] downstream, but the full 31-bit sum constraint
			// is what makes the decomposition sound (see bits.RegisterAt
			// doc note on the 2^-7 Koalabear corner case).
			bitsPrefix := fmt.Sprintf("airverify.fri_q%d_bits", k)
			bitsCN := bits.RegisterAt(&verifierMod, bitsPrefix, querySpongeCN.Digest[1], 31, queryDigestRow)

			// Native digest[1] for trace fill. Emit a sparseBits entry
			// for EVERY bit column (even when the bit is 0) so the trace
			// fill loop registers the column with a zero-padded vector;
			// otherwise the prover errors out at columns referenced by
			// constraints but missing from the trace.
			digestVal := chain[queryStepIdx].NativeDigest[1].Uint64()
			for bi := 0; bi < bitsCN.NumBits; bi++ {
				bit := (digestVal>>uint(bi))&1 == 1
				sparseBits = append(sparseBits, sparseBitAlloc{colName: bitsCN.Bits[bi], rowIdx: queryDigestRow, bit: bit})
			}

			// Per-query trusted witnesses: P, Q at the last fold round.
			// These are taken on trust until Merkle openings land in a
			// future stage.
			lastLayer := friProof.FRIQueries[k].Layers[len(friProof.FRIQueries[k].Layers)-1]
			pExpr := addE4(fmt.Sprintf("airverify.fri_q%d_P_last", k), lastLayer.LeafPExt)
			qExpr := addE4(fmt.Sprintf("airverify.fri_q%d_Q_last", k), lastLayer.LeafQExt)

			b0 := expr.Col(bitsCN.Bits[0])
			b1 := expr.Col(bitsCN.Bits[1])

			xInvExpr := e4Select4(xInvArr, b0, b1)
			finalPolyAtBase := e4Select4(finalPolyArr, b0, b1)

			// expected = (P+Q)/2 + alpha * (P-Q) * (1/2) * xInv.
			sumHalf := pExpr.Add(qExpr).MulByBase(invTwoConst)
			diff := pExpr.Sub(qExpr)
			diffScaled := diff.MulByBase(invTwoConst)
			folded := alphaLastExpr.Mul(diffScaled).Mul(xInvExpr)
			expected := sumHalf.Add(folded)

			for _, rel := range expected.EqualityConstraints(finalPolyAtBase) {
				verifierMod.AssertZeroAt(rel, queryDigestRow)
			}
		}
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

	// Sparse trace fill for FRI bit-decomposition witnesses: only the
	// gated row holds a real bit; every other row is zero. Multiple
	// bits within the same column would coexist if the gadget ever
	// shared columns, so we accumulate first and apply once at the end.
	bitColCells := map[string]map[int]koalabear.Element{}
	for _, a := range sparseBits {
		m, ok := bitColCells[a.colName]
		if !ok {
			m = map[int]koalabear.Element{}
			bitColCells[a.colName] = m
		}
		var ke koalabear.Element
		if a.bit {
			ke.SetOne()
		}
		m[a.rowIdx] = ke
	}
	for colName, cells := range bitColCells {
		col := make([]koalabear.Element, verifierMod.N)
		for rowIdx, val := range cells {
			col[rowIdx].Set(&val)
		}
		tr.SetBase(colName, col)
	}

	// Sanity check: locate the zeta step's digest and confirm it equals
	// the natively-derived zeta (replayInnerFS). If this fails, the
	// chain reconstruction has a bug.
	zetaStepIdx := -1
	for i, step := range chain {
		if step.Name == constants.FINAL_EVALUATION_POINT {
			zetaStepIdx = i
			break
		}
	}
	if zetaStepIdx < 0 {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: __zeta step missing from chain")
	}
	expectedZeta := hashDigestToE4(chain[zetaStepIdx].NativeDigest)
	if !expectedZeta.Equal(&zeta) {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: chain zeta-step digest != native zeta")
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
// in chunk_0 — that simplifies the in-circuit Rot wiring.
//
// WitnessBindings (used by Stage 5+) identifies the slice of
// NativeInputs that should be wired in-circuit to witness column
// references rather than constants. Each entry describes one E4
// binding (4 contiguous native elements in extToElements order
// {B0.A0, B0.A1, B1.A0, B1.A1}).
type challengeStep struct {
	Name            string
	NativeInputs    []koalabear.Element
	NativeDigest    hash.Digest
	IsFirst         bool
	PrevDigestStart int
	WitnessBindings []witnessBinding
}

// witnessBinding marks one E4 worth of NativeInputs that should be
// resolved to expr.Col references into the airverify module's witness
// columns instead of being baked in as constants.
type witnessBinding struct {
	// Position in NativeInputs where the 4 elements of this binding start
	// (extToElements order: {B0.A0, B0.A1, B1.A0, B1.A1}).
	Start int
	// Key the binding refers to: a leaf.String() name when IsChunk is
	// false (a committed column at zeta) or a chunk-column name when
	// IsChunk is true (an AIR quotient chunk at zeta).
	Key     string
	IsChunk bool
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
	if err := fs.NewChallenge(constants.DEEP_ALPHA); err != nil {
		return nil, err
	}
	// Stage 6/7: extend transcript registration through every FRI
	// challenge when the inner proof carries FRI data. The registration
	// order must mirror fri.registerChallenges:
	//
	//   fri_fold_0
	//   for j in 1..friNumRounds-1: (fri_level_l_gamma)? fri_fold_j
	//   fri_query_0 .. fri_query_{NUM_QUERIES-1}
	hasFRI := len(input.Proof.DeepQuotientCommitment) > 0
	var (
		friNumRounds int
		levelAtRound map[int]int // round j -> level index l
	)
	if hasFRI {
		maxN := 0
		for _, m := range pg.Modules {
			if m.N > maxN {
				maxN = m.N
			}
		}
		friNumRounds = log2int(maxN)

		// Distinct sizes (decreasing) — level 0 = largest, then smaller.
		sizesSet := map[int]bool{}
		for _, m := range pg.Modules {
			sizesSet[m.N] = true
		}
		sortedSizes := make([]int, 0, len(sizesSet))
		for sz := range sizesSet {
			sortedSizes = append(sortedSizes, sz)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(sortedSizes)))

		levelAtRound = map[int]int{}
		for l := 1; l < len(sortedSizes); l++ {
			ratio := sortedSizes[0] / sortedSizes[l]
			jl := log2int(ratio)
			if jl >= 1 && jl < friNumRounds {
				levelAtRound[jl] = l
			}
		}

		// Register in fri.Prove's order.
		if err := fs.NewChallenge(friFoldName(0)); err != nil {
			return nil, err
		}
		for j := 1; j < friNumRounds; j++ {
			if l, ok := levelAtRound[j]; ok {
				if err := fs.NewChallenge(friLevelGammaName(l)); err != nil {
					return nil, err
				}
			}
			if err := fs.NewChallenge(friFoldName(j)); err != nil {
				return nil, err
			}
		}
		for k := 0; k < constants.NUM_QUERIES; k++ {
			if err := fs.NewChallenge(friQueryName(k)); err != nil {
				return nil, err
			}
		}
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

	// DEEP_ALPHA bindings: every value-at-zeta entry the inner DEEP
	// quotient batches (per BuildDeepQuotientLayout: per-size, per-shift
	// committed-column at-zeta values + per-size AIR quotient chunks).
	// Each (key, value) pair is also tracked as a witnessBinding so the
	// in-circuit sponge can reference the airverify witness column
	// rather than baking the value in as a constant.
	dqLayout := prover.BuildDeepQuotientLayout(pg)
	var deepBindings []witnessBinding
	deepStart := 0 // running offset within bindings[constants.DEEP_ALPHA]
	for i := range dqLayout.Sizes {
		for _, keysAtShift := range dqLayout.Keys[i] {
			for _, key := range keysAtShift {
				v, ok := input.Proof.ValueAtZetaExt(key)
				if !ok {
					return nil, fmt.Errorf("recursion: DEEP_ALPHA binding key %q not in inner proof.ValuesAtZeta", key)
				}
				els := extToElements(v)
				bindings[constants.DEEP_ALPHA] = append(bindings[constants.DEEP_ALPHA], els...)
				if err := fs.Bind(constants.DEEP_ALPHA, els); err != nil {
					return nil, err
				}
				deepBindings = append(deepBindings, witnessBinding{Start: deepStart, Key: key, IsChunk: false})
				deepStart += 4
			}
		}
		for _, chunkName := range dqLayout.AIRChunks[i] {
			v, ok := input.Proof.ValueAtZetaExt(chunkName)
			if !ok {
				return nil, fmt.Errorf("recursion: DEEP_ALPHA chunk binding %q not in inner proof.ValuesAtZeta", chunkName)
			}
			els := extToElements(v)
			bindings[constants.DEEP_ALPHA] = append(bindings[constants.DEEP_ALPHA], els...)
			if err := fs.Bind(constants.DEEP_ALPHA, els); err != nil {
				return nil, err
			}
			deepBindings = append(deepBindings, witnessBinding{Start: deepStart, Key: chunkName, IsChunk: true})
			deepStart += 4
		}
	}

	// FRI static bindings:
	//   - fri_fold_0          binds DeepQuotientCommitment[0] (T_0 root)
	//   - fri_fold_j (j > 0)  binds DeepQuotientFriProof.FRIRoots[j-1] (T_j root)
	//   - fri_level_l_gamma   binds DeepQuotientCommitment[l] (level-l root)
	//   - fri_query_0         binds transcriptExtPoly(FinalPolyExt)
	//                          (or transcriptBasePoly for base-rail FRI;
	//                          Loom's DEEP rail is ext, so we expect ext)
	// fri_query_k (k > 0) bindings are DYNAMIC: bound in the step loop
	// from the previous query's just-computed digest.
	if hasFRI {
		root0 := input.Proof.DeepQuotientCommitment[0]
		bindings[friFoldName(0)] = append(bindings[friFoldName(0)], root0[:]...)
		if err := fs.Bind(friFoldName(0), root0[:]); err != nil {
			return nil, err
		}

		for j := 1; j < friNumRounds; j++ {
			if l, ok := levelAtRound[j]; ok {
				levelRoot := input.Proof.DeepQuotientCommitment[l]
				name := friLevelGammaName(l)
				bindings[name] = append(bindings[name], levelRoot[:]...)
				if err := fs.Bind(name, levelRoot[:]); err != nil {
					return nil, err
				}
			}
			tjRoot := input.Proof.DeepQuotientFriProof.FRIRoots[j-1]
			fname := friFoldName(j)
			bindings[fname] = append(bindings[fname], tjRoot[:]...)
			if err := fs.Bind(fname, tjRoot[:]); err != nil {
				return nil, err
			}
		}

		var finalEnc []koalabear.Element
		fp := input.Proof.DeepQuotientFriProof
		if fp.FinalField == field.Ext {
			finalEnc = transcriptExtPolyElements(fp.FinalPolyExt)
		} else {
			finalEnc = transcriptBasePolyElements(fp.FinalPolyBase)
		}
		q0 := friQueryName(0)
		bindings[q0] = append(bindings[q0], finalEnc...)
		if err := fs.Bind(q0, finalEnc); err != nil {
			return nil, err
		}
	}

	// Compute each challenge in order, recording the sequence absorbed.
	challengeNames := make([]string, 0, numRounds+3)
	for r := 0; r < numRounds; r++ {
		challengeNames = append(challengeNames, constants.CanonicalChallengeName(r))
	}
	challengeNames = append(challengeNames, constants.FINAL_EVALUATION_POINT)
	challengeNames = append(challengeNames, constants.DEEP_ALPHA)
	if hasFRI {
		challengeNames = append(challengeNames, friFoldName(0))
		for j := 1; j < friNumRounds; j++ {
			if l, ok := levelAtRound[j]; ok {
				challengeNames = append(challengeNames, friLevelGammaName(l))
			}
			challengeNames = append(challengeNames, friFoldName(j))
		}
		for k := 0; k < constants.NUM_QUERIES; k++ {
			challengeNames = append(challengeNames, friQueryName(k))
		}
	}

	steps := make([]challengeStep, 0, len(challengeNames))
	for i, name := range challengeNames {
		// Dynamic binding: fri_query_k for k > 0 binds the previous
		// query's just-computed digest. We do this BEFORE computing
		// this challenge so it's included in the absorbed sequence.
		if k, ok := parseQueryK(name); ok && k > 0 {
			prev := steps[i-1].NativeDigest
			bindings[name] = append(bindings[name], prev[:]...)
			if err := fs.Bind(name, prev[:]); err != nil {
				return nil, err
			}
		}

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

		// Attach witness-binding metadata for DEEP_ALPHA: shift the
		// per-binding Start offsets to account for the seq prefix
		// (name + prev_digest) inserted before the bindings.
		var wbs []witnessBinding
		if name == constants.DEEP_ALPHA && len(deepBindings) > 0 {
			bindingsOffset := len(seq) - len(bindings[name])
			wbs = make([]witnessBinding, len(deepBindings))
			for j, b := range deepBindings {
				wbs[j] = witnessBinding{
					Start:   bindingsOffset + b.Start,
					Key:     b.Key,
					IsChunk: b.IsChunk,
				}
			}
		}

		steps = append(steps, challengeStep{
			Name:            name,
			NativeInputs:    seq,
			NativeDigest:    digest,
			IsFirst:         i == 0,
			PrevDigestStart: prevDigestStart,
			WitnessBindings: wbs,
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

// friFoldName / friLevelGammaName / friQueryName duplicate fri's
// unexported challenge-name helpers. If the upstream format ever
// changes these must change too — there's no exported helper to call.
func friFoldName(j int) string       { return fmt.Sprintf("fri_fold_%d", j) }
func friLevelGammaName(l int) string { return fmt.Sprintf("fri_level_%d_gamma", l) }
func friQueryName(k int) string      { return fmt.Sprintf("fri_query_%d", k) }

// parseQueryK returns (k, true) if name has the form "fri_query_<k>".
func parseQueryK(name string) (int, bool) {
	const prefix = "fri_query_"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return 0, false
	}
	var k int
	if _, err := fmt.Sscanf(name[len(prefix):], "%d", &k); err != nil {
		return 0, false
	}
	return k, true
}

func log2int(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}

// transcriptBasePolyElements / transcriptExtPolyElements mirror fri's
// unexported helpers used to encode a final-poly for FS binding.
//
// "BASE" / "EXTP" domain tags must match fri.transcriptBasePoly and
// fri.transcriptExtPoly exactly.
const (
	friBaseDomainTag uint64 = 0x42415345 // "BASE"
	friExtDomainTag  uint64 = 0x45585450 // "EXTP"
)

func transcriptBasePolyElements(poly []koalabear.Element) []koalabear.Element {
	res := make([]koalabear.Element, 0, 2+len(poly))
	res = append(res, hash.NewElement(friBaseDomainTag), hash.NewElement(uint64(len(poly))))
	res = append(res, poly...)
	return res
}

func transcriptExtPolyElements(poly []ext.E4) []koalabear.Element {
	res := make([]koalabear.Element, 0, 2+4*len(poly))
	res = append(res, hash.NewElement(friExtDomainTag), hash.NewElement(uint64(len(poly))))
	for _, v := range poly {
		res = append(res, v.B0.A0, v.B0.A1, v.B1.A0, v.B1.A1)
	}
	return res
}

// extToElements flattens an E4 into the 4-element order Loom's FS uses
// when binding extension values: (B0.A0, B0.A1, B1.A0, B1.A1). Mirrors
// the unexported prover.extToElements.
func extToElements(v ext.E4) []koalabear.Element {
	return []koalabear.Element{v.B0.A0, v.B0.A1, v.B1.A0, v.B1.A1}
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
