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
	"math/big"
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
	"github.com/consensys/loom/recursion/gadgets/binexp"
	"github.com/consensys/loom/recursion/gadgets/bits"
	"github.com/consensys/loom/recursion/gadgets/challenger24"
	"github.com/consensys/loom/recursion/gadgets/leafhash"
	"github.com/consensys/loom/recursion/gadgets/merkle"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
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

	// Stages 8–9: per-(round, query) FRI fold check.
	//   - For each round j < numRounds-1: expected_jk == selected leaf at
	//     round j+1 (P or Q, picked by the top bit of base_jk).
	//   - For round j = numRounds-1: expected_jk == finalPoly[base_last_k].
	// expected_jk is computed via the standard FRI fold equation
	//   (P+Q)/2 + alpha_j * (P-Q) * invTwo * xInv
	// where:
	//   - alpha_j is the in-circuit fri_fold_j challenge (anchored to its
	//     chain sponge digest at the sponge's digest row).
	//   - xInv = omega_j^{-base_jk} computed via the binexp gadget over
	//     the lowest log2(N_j/2) bits of fri_query_k's digest[1]
	//     decomposition (s_k = digest[1] mod (N_fri/2)).
	//   - base_last_k = lowest log2(len(finalPoly)) bits of s_k.
	// The query position bits are produced once per query by
	// bits.RegisterAt and shared across every round's binexp / mux.
	// Stage-gated to fire only when the inner proof carries FRI data.
	type sparseBitAlloc struct {
		colName string
		rowIdx  int
		bit     bool
	}
	type pendingBinexp struct {
		cn        binexp.ColumnNames
		rowIdx    int
		bitsAtRow []bool
	}
	var sparseBits []sparseBitAlloc
	var pendingBinexps []pendingBinexp

	// Stage 12 plumbing: registered leafhash sponge inputs (trace
	// fill) and per-(tree, query) Merkle setups deferred until after
	// builder.AddModule(verifierMod).
	type pendingLeafSpongeFill struct {
		cn    leafhash.FlexibleColumnNames
		input [][24]koalabear.Element // per-block 24-element state for one leaf
	}
	type treeMerkleSetup struct {
		treeIdx    int
		queryIdx   int
		digestCols [leafhash.DigestLen]string
		leafDigest hash.Digest
		siblings   []hash.Digest
		leafIdx    int
		root       hash.Digest
	}
	var pendingLeafSponges []pendingLeafSpongeFill
	var treeMerkles []treeMerkleSetup

	if len(input.Proof.DeepQuotientCommitment) > 0 {
		friProof := input.Proof.DeepQuotientFriProof
		finalPolyExt := friProof.FinalPolyExt
		if len(finalPolyExt) == 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: FRI present but FinalPolyExt empty")
		}
		nLastRound := 2 * len(finalPolyExt)
		if nLastRound&(nLastRound-1) != 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: 2*len(finalPolyExt) = %d not power of two", nLastRound)
		}
		baseLastBits := log2int(len(finalPolyExt))
		if baseLastBits != 2 {
			// The final-poly inline mux is hardcoded for 2 bits; generalising
			// is straightforward (recursive tree reduction) but deferred.
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 8 currently supports len(finalPoly)=4 only, got %d", len(finalPolyExt))
		}
		numRounds := log2int(maxModN)
		if numRounds < 1 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: FRI present with maxModN=%d (numRounds=%d)", maxModN, numRounds)
		}
		// Full FRI evaluation domain size: N_fri = nLastRound * 2^{r-1}.
		nFRI := nLastRound << (numRounds - 1)

		// Locate every fri_fold_j and fri_query_k step in the chain.
		foldStepIdx := make([]int, numRounds)
		for j := range foldStepIdx {
			foldStepIdx[j] = -1
		}
		var queryStepIdxs []int
		for i, step := range chain {
			for j := 0; j < numRounds; j++ {
				if step.Name == friFoldName(j) {
					foldStepIdx[j] = i
				}
			}
			if strings.HasPrefix(step.Name, "fri_query_") {
				queryStepIdxs = append(queryStepIdxs, i)
			}
		}
		for j, idx := range foldStepIdx {
			if idx < 0 {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: %s missing from chain", friFoldName(j))
			}
		}
		if len(queryStepIdxs) == 0 {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: no fri_query_k steps in chain")
		}

		// Anchor every alpha_j to its sponge digest at the sponge's digest
		// row (same pattern as the zeta^N witness chain). Off-row the
		// witness columns hold the constant alpha_j, so later fold
		// constraints can reference them anywhere.
		alphaExprs := make([]extfield.E4Expr, numRounds)
		for j := 0; j < numRounds; j++ {
			foldCN := chSpongeCNs[foldStepIdx[j]]
			foldDigestExpr := extfield.FromLimbs(
				expr.Col(foldCN.Digest[0]), expr.Col(foldCN.Digest[2]),
				expr.Col(foldCN.Digest[1]), expr.Col(foldCN.Digest[3]),
			)
			alphaNative := hashDigestToE4(chain[foldStepIdx[j]].NativeDigest)
			alphaJExpr := addE4(fmt.Sprintf("airverify.fri_alpha_%d", j), alphaNative)
			for _, rel := range alphaJExpr.EqualityConstraints(foldDigestExpr) {
				verifierMod.AssertZeroAt(rel, foldCN.DigestRow)
			}
			alphaExprs[j] = alphaJExpr
		}

		// Per-query position bits (31-bit decomposition of digest[1]).
		type queryData struct {
			digestRow  int
			bitsCN     bits.ColumnNames
			digestNat  uint64
		}
		queries := make([]queryData, len(queryStepIdxs))
		for k, queryStepIdx := range queryStepIdxs {
			querySpongeCN := chSpongeCNs[queryStepIdx]
			queryDigestRow := querySpongeCN.DigestRow
			bitsPrefix := fmt.Sprintf("airverify.fri_q%d_bits", k)
			bitsCN := bits.RegisterAt(&verifierMod, bitsPrefix, querySpongeCN.Digest[1], 31, queryDigestRow)

			digestVal := chain[queryStepIdx].NativeDigest[1].Uint64()
			for bi := 0; bi < bitsCN.NumBits; bi++ {
				bit := (digestVal>>uint(bi))&1 == 1
				sparseBits = append(sparseBits, sparseBitAlloc{colName: bitsCN.Bits[bi], rowIdx: queryDigestRow, bit: bit})
			}
			queries[k] = queryData{digestRow: queryDigestRow, bitsCN: bitsCN, digestNat: digestVal}
		}

		// Per-(round, query) trusted P, Q witnesses. Each entry is the
		// LeafPExt / LeafQExt for that round's layer of the query.
		type leafPair struct {
			P, Q extfield.E4Expr
		}
		leafExprs := make([][]leafPair, numRounds)
		for j := 0; j < numRounds; j++ {
			leafExprs[j] = make([]leafPair, len(queries))
			for k := range queries {
				layer := friProof.FRIQueries[k].Layers[j]
				p := addE4(fmt.Sprintf("airverify.fri_q%d_P_%d", k, j), layer.LeafPExt)
				q := addE4(fmt.Sprintf("airverify.fri_q%d_Q_%d", k, j), layer.LeafQExt)
				leafExprs[j][k] = leafPair{P: p, Q: q}
			}
		}

		// Common constants.
		var invTwoBase koalabear.Element
		var twoBase koalabear.Element
		twoBase.SetUint64(2)
		invTwoBase.Inverse(&twoBase)
		invTwoConst := expr.Const(invTwoBase)
		oneConst := expr.Const(koalabear.One())

		// Inline 4-element E4 select indexed by (b0 + 2*b1).
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

		var finalPolyArr [4]ext.E4
		for i := 0; i < 4; i++ {
			finalPolyArr[i] = finalPolyExt[i]
		}

		for j := 0; j < numRounds; j++ {
			Nj := nFRI >> j
			omegaJ, err := koalabear.Generator(uint64(Nj))
			if err != nil {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: omega round %d: %w", j, err)
			}
			var omegaJInv koalabear.Element
			omegaJInv.Inverse(&omegaJ)
			numBaseBits := log2int(Nj / 2)

			for k, query := range queries {
				// xInv via binexp over the lowest numBaseBits of digest[1].
				baseBitsCN := bits.ColumnNames{
					ModuleName: query.bitsCN.ModuleName,
					Value:      query.bitsCN.Value,
					Bits:       query.bitsCN.Bits[:numBaseBits],
					NumBits:    numBaseBits,
				}
				binexpPrefix := fmt.Sprintf("airverify.fri_q%d_xInv_%d", k, j)
				binexpCN := binexp.Register(&verifierMod, binexpPrefix, omegaJInv, baseBitsCN)
				xInvBase := expr.Col(binexpCN.Steps[numBaseBits-1])
				xInvExpr := extfield.FromBase(xInvBase)

				// Trace fill plan for the binexp step columns.
				bitsAtRow := make([]bool, numBaseBits)
				for bi := 0; bi < numBaseBits; bi++ {
					bitsAtRow[bi] = (query.digestNat>>uint(bi))&1 == 1
				}
				pendingBinexps = append(pendingBinexps, pendingBinexp{cn: binexpCN, rowIdx: query.digestRow, bitsAtRow: bitsAtRow})

				P := leafExprs[j][k].P
				Q := leafExprs[j][k].Q

				sumHalf := P.Add(Q).MulByBase(invTwoConst)
				diff := P.Sub(Q)
				diffScaled := diff.MulByBase(invTwoConst)
				folded := alphaExprs[j].Mul(diffScaled).Mul(xInvExpr)
				expected := sumHalf.Add(folded)

				if j < numRounds-1 {
					// Cross-round chain: expected_jk == selected leaf at
					// round j+1. The top bit of base_jk (= bit
					// numBaseBits-1 of digest[1]) decides P vs Q.
					//
					// Multi-degree FRI introduces gamma_l * level_leaf
					// contributions at the round where level l kicks in
					// (see internal/fri/fri.go checkQueryExt). The chain
					// constraint becomes
					//   expected_jk + gamma_l * level_leaf == leaf_at_j+1
					// rather than the single-degree form below. We skip
					// the chain constraint when multi-degree FRI is in
					// play; the alpha witnesses, per-round leaf
					// witnesses, and final-poly match (which has no
					// level term) are still wired and tested. Adding
					// gamma anchors and level-leaf witnesses is the
					// next stage.
					if len(friProof.LevelQueries) == 0 {
						topBit := expr.Col(query.bitsCN.Bits[numBaseBits-1])
						notTopBit := oneConst.Sub(topBit)
						pNext := leafExprs[j+1][k].P
						qNext := leafExprs[j+1][k].Q
						selected := pNext.MulByBase(notTopBit).Add(qNext.MulByBase(topBit))
						for _, rel := range expected.EqualityConstraints(selected) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}
					}
				} else {
					// Final-poly match. base_last has exactly baseLastBits
					// bits (= 2 with the current hardcoded mux).
					b0 := expr.Col(query.bitsCN.Bits[0])
					b1 := expr.Col(query.bitsCN.Bits[1])
					finalPolyAtBase := e4Select4(finalPolyArr, b0, b1)
					for _, rel := range expected.EqualityConstraints(finalPolyAtBase) {
						verifierMod.AssertZeroAt(rel, query.digestRow)
					}
				}
			}
		}

		// Stage 11: DEEP-quotient bridge (single-size only).
		//
		// For each FRI query q, the verifier reconstructs DQ(omega^sL) and
		// DQ(-omega^sL) from the AIR-at-zeta values, alpha (DEEP_ALPHA), and
		// the COLUMN samples at the query position, then equates these to
		// the FRI level-0 layer's (LeafPExt, LeafQExt) — which are already
		// Stage-9 witnesses and Stage-10 Merkle-bound to the level-0 root
		// (for query 0).
		//
		// Per dqLayout shift group j (single-size = sizes[0]):
		//   z_s     = zeta * omega^shift_j
		//   v_s     = sum_k evalAtZ_k * alpha^k
		//   C_X    = sum_k sampleP_k * alpha^k
		//   C_negX = sum_k sampleQ_k * alpha^k
		//   DQ_P  += (v_s - C_X)    * inv(z_s - X)
		//   DQ_Q  += (v_s - C_negX) * inv(z_s + X)
		// (AIR-chunks contribute one more group with shift=0.)
		//
		// X = omega_N_fri^sL where sL = digest[1] mod (N_fri/2). Computed
		// via the same binexp gadget Stage 9 uses for xInv, but with the
		// FRI domain generator as the base.
		//
		// Soundness gaps still open: COLUMN samples (sampleP/Q witnesses)
		// are taken on trust until per-column Merkle openings are wired up.
		// Multi-degree FRI (level intros) needs gamma anchors + per-level
		// DEEP quotients — gated off here as len(LevelQueries) > 0.
		if len(friProof.LevelQueries) == 0 {
			dqLayout := prover.BuildDeepQuotientLayout(input.Program)
			if len(dqLayout.Sizes) == 1 {
				size := dqLayout.Sizes[0]
				if size != maxModN {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 11 expected dqLayout.Sizes[0]=%d to equal maxModN=%d", size, maxModN)
				}
				nFRIsize := constants.RATE * size
				halfDomain := nFRIsize / 2
				sLBits := log2int(halfDomain)
				if sLBits <= 0 {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 11 halfDomain=%d gives sLBits=%d", halfDomain, sLBits)
				}

				// Anchor zeta as a constant-fill witness column. The
				// existing zetaExpr references the __zeta chain sponge
				// digest column, which only holds the correct value at
				// chCN.DigestRow; the bridge needs zeta accessible at
				// the query row. Same anchor pattern as alpha_j.
				zetaConst := addE4("airverify.zeta_const", zeta)
				for _, rel := range zetaConst.EqualityConstraints(zetaExpr) {
					verifierMod.AssertZeroAt(rel, chCN.DigestRow)
				}

				// Anchor DEEP_ALPHA. The chain produces it as a sponge digest
				// limb; mirror the zeta / alpha_j anchoring pattern.
				deepAlphaIdx := -1
				for i, step := range chain {
					if step.Name == constants.DEEP_ALPHA {
						deepAlphaIdx = i
						break
					}
				}
				if deepAlphaIdx < 0 {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: DEEP_ALPHA missing from chain")
				}
				deepAlphaCN := chSpongeCNs[deepAlphaIdx]
				deepAlphaDigestExpr := extfield.FromLimbs(
					expr.Col(deepAlphaCN.Digest[0]), expr.Col(deepAlphaCN.Digest[2]),
					expr.Col(deepAlphaCN.Digest[1]), expr.Col(deepAlphaCN.Digest[3]),
				)
				deepAlphaNative := hashDigestToE4(chain[deepAlphaIdx].NativeDigest)
				deepAlphaExpr := addE4("airverify.deep_alpha", deepAlphaNative)
				for _, rel := range deepAlphaExpr.EqualityConstraints(deepAlphaDigestExpr) {
					verifierMod.AssertZeroAt(rel, deepAlphaCN.DigestRow)
				}

				// Total alpha-power positions across all shift groups + AIR
				// chunks. Materialize alpha^0..alpha^{K-1} as constant-fill
				// witness columns, recurrence-anchored at row 0.
				totalCols := 0
				for j := range dqLayout.Shifts[0] {
					totalCols += len(dqLayout.Names[0][j])
				}
				totalCols += len(dqLayout.AIRChunks[0])
				if totalCols == 0 {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: dqLayout empty for size %d", size)
				}
				alphaPowChain := make([]extfield.E4Expr, totalCols)
				alphaPowNative := make([]ext.E4, totalCols)
				alphaPowNative[0].SetOne()
				alphaPowChain[0] = extfield.One()
				for k := 1; k < totalCols; k++ {
					alphaPowNative[k].Mul(&alphaPowNative[k-1], &deepAlphaNative)
					curr := addE4(fmt.Sprintf("airverify.deep_alphaPow_%d", k), alphaPowNative[k])
					prevTimesAlpha := alphaPowChain[k-1].Mul(deepAlphaExpr)
					for _, rel := range curr.EqualityConstraints(prevTimesAlpha) {
						verifierMod.AssertZeroAt(rel, 0)
					}
					alphaPowChain[k] = curr
				}

				// Per-bare-column samples (P, Q) per query: trusted witnesses
				// until column-side Merkle wiring lands. Use input.Proof's
				// PointSamplings and layout.ColSlot to lift the right
				// raw-leaf pair for each (bare name, query). Same for AIR
				// chunks.
				bareNames := map[string]bool{}
				for _, namesJ := range dqLayout.Names[0] {
					for _, n := range namesJ {
						bareNames[n] = true
					}
				}
				bareList := make([]string, 0, len(bareNames))
				for n := range bareNames {
					bareList = append(bareList, n)
				}
				sort.Strings(bareList)

				sampleP := map[string][]extfield.E4Expr{}
				sampleQ := map[string][]extfield.E4Expr{}
				for _, n := range bareList {
					sampleP[n] = make([]extfield.E4Expr, len(queries))
					sampleQ[n] = make([]extfield.E4Expr, len(queries))
				}
				chunkSampleP := map[string][]extfield.E4Expr{}
				chunkSampleQ := map[string][]extfield.E4Expr{}
				for _, n := range dqLayout.AIRChunks[0] {
					chunkSampleP[n] = make([]extfield.E4Expr, len(queries))
					chunkSampleQ[n] = make([]extfield.E4Expr, len(queries))
				}

				innerLayout := prover.BuildLayout(input.Program, 0)
				sampleE4 := func(slot prover.Slot, q int) (ext.E4, ext.E4, error) {
					if slot.TreeIdx >= len(input.Proof.PointSamplings[q]) {
						return ext.E4{}, ext.E4{}, fmt.Errorf("recursion: tree %d out of range for query %d", slot.TreeIdx, q)
					}
					wp := input.Proof.PointSamplings[q][slot.TreeIdx]
					if slot.Field == field.Ext {
						if slot.PolyIdx >= len(wp.RawLeafExt) {
							return ext.E4{}, ext.E4{}, fmt.Errorf("recursion: ext raw leaf %d out of range", slot.PolyIdx)
						}
						return wp.RawLeafExt[slot.PolyIdx][0], wp.RawLeafExt[slot.PolyIdx][1], nil
					}
					if slot.PolyIdx >= len(wp.RawLeafBase) {
						return ext.E4{}, ext.E4{}, fmt.Errorf("recursion: base raw leaf %d out of range", slot.PolyIdx)
					}
					var p, qE ext.E4
					p.B0.A0.Set(&wp.RawLeafBase[slot.PolyIdx][0])
					qE.B0.A0.Set(&wp.RawLeafBase[slot.PolyIdx][1])
					return p, qE, nil
				}

				for qi := range queries {
					for _, n := range bareList {
						slot, ok := innerLayout.ColSlot[n]
						if !ok {
							return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: column %q missing from layout.ColSlot", n)
						}
						pNative, qNative, err := sampleE4(slot, qi)
						if err != nil {
							return board.Program{}, trace.Trace{}, err
						}
						sampleP[n][qi] = addE4(fmt.Sprintf("airverify.deep_sP_%d_%s", qi, sanitizeName(n)), pNative)
						sampleQ[n][qi] = addE4(fmt.Sprintf("airverify.deep_sQ_%d_%s", qi, sanitizeName(n)), qNative)
					}
					for _, n := range dqLayout.AIRChunks[0] {
						slot, ok := innerLayout.AIRChunkSlot[n]
						if !ok {
							return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: chunk %q missing from layout.AIRChunkSlot", n)
						}
						pNative, qNative, err := sampleE4(slot, qi)
						if err != nil {
							return board.Program{}, trace.Trace{}, err
						}
						chunkSampleP[n][qi] = addE4(fmt.Sprintf("airverify.deep_csP_%d_%s", qi, sanitizeName(n)), pNative)
						chunkSampleQ[n][qi] = addE4(fmt.Sprintf("airverify.deep_csQ_%d_%s", qi, sanitizeName(n)), qNative)
					}
				}

				// Per-query X via binexp on the lowest sLBits of digest[1].
				friDomainGen, err := koalabear.Generator(uint64(nFRIsize))
				if err != nil {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: FRI domain generator: %w", err)
				}
				// Inner-domain generator at size, used for omegaShift constants.
				omegaSize, err := koalabear.Generator(uint64(size))
				if err != nil {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: omega_size: %w", err)
				}
				omegaShiftE4 := make([]ext.E4, len(dqLayout.Shifts[0]))
				omegaShiftExpr := make([]extfield.E4Expr, len(dqLayout.Shifts[0]))
				for j, shift := range dqLayout.Shifts[0] {
					var w koalabear.Element
					w.Exp(omegaSize, big.NewInt(int64(shift)))
					omegaShiftE4[j].B0.A0.Set(&w)
					omegaShiftExpr[j] = extfield.Const(omegaShiftE4[j])
				}

				// Unified leaf-by-key lookup for evalAtZ. Multiple inner
				// modules at the same size pool their leaf witnesses by
				// leaf.String().
				leafByKey := map[string]extfield.E4Expr{}
				chunkByName := map[string]extfield.E4Expr{}
				for mi, data := range mods {
					if data.mod.N != size {
						continue
					}
					for key, e := range witnesses[mi].leafExprs {
						leafByKey[key] = e
					}
					for ci, ce := range witnesses[mi].chunkExprs {
						chunkName := constants.QuotientChunkName(data.name, ci)
						chunkByName[chunkName] = ce
					}
				}

				for qi, query := range queries {
					// X = friDomainGen^sL, sL = lowest sLBits of digest[1].
					sLBitsCN := bits.ColumnNames{
						ModuleName: query.bitsCN.ModuleName,
						Value:      query.bitsCN.Value,
						Bits:       query.bitsCN.Bits[:sLBits],
						NumBits:    sLBits,
					}
					xPrefix := fmt.Sprintf("airverify.deep_q%d_X", qi)
					xCN := binexp.Register(&verifierMod, xPrefix, friDomainGen, sLBitsCN)
					xBase := expr.Col(xCN.Steps[sLBits-1])
					xExpr := extfield.FromBase(xBase)
					negXExpr := extfield.Zero().Sub(xExpr)

					bitsAtRow := make([]bool, sLBits)
					for bi := 0; bi < sLBits; bi++ {
						bitsAtRow[bi] = (query.digestNat>>uint(bi))&1 == 1
					}
					pendingBinexps = append(pendingBinexps, pendingBinexp{cn: xCN, rowIdx: query.digestRow, bitsAtRow: bitsAtRow})

					// Accumulate DQ_P, DQ_Q across shift groups + AIR chunks.
					dqP := extfield.Zero()
					dqQ := extfield.Zero()
					alphaIdx := 0

					// Loop over shift groups.
					for j, shift := range dqLayout.Shifts[0] {
						_ = shift
						zsExpr := zetaConst.Mul(omegaShiftExpr[j])
						names := dqLayout.Names[0][j]
						keys := dqLayout.Keys[0][j]

						vs := extfield.Zero()
						cX := extfield.Zero()
						cNegX := extfield.Zero()
						for k, key := range keys {
							evalAtZ, ok := leafByKey[key]
							if !ok {
								return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: leaf key %q missing", key)
							}
							a := alphaPowChain[alphaIdx]
							alphaIdx++
							vs = vs.Add(evalAtZ.Mul(a))
							cX = cX.Add(sampleP[names[k]][qi].Mul(a))
							cNegX = cNegX.Add(sampleQ[names[k]][qi].Mul(a))
						}

						denomX := zsExpr.Sub(xExpr)
						denomNegX := zsExpr.Sub(negXExpr) // = zs + X

						// Native denom values for trace-fill of inverses.
						var zsNat ext.E4
						zsNat.MulByElement(&zeta, &omegaShiftE4[j].B0.A0)
						var xNat ext.E4
						xNat.B0.A0.Exp(friDomainGen, big.NewInt(int64(query.digestNat%uint64(halfDomain))))
						var negXNat ext.E4
						negXNat.B0.A0.Neg(&xNat.B0.A0)
						var dXNat ext.E4
						dXNat.Sub(&zsNat, &xNat)
						var dNegXNat ext.E4
						dNegXNat.Sub(&zsNat, &negXNat)
						var invDXNat ext.E4
						invDXNat.Inverse(&dXNat)
						var invDNegXNat ext.E4
						invDNegXNat.Inverse(&dNegXNat)

						invDXExpr := addE4(fmt.Sprintf("airverify.deep_q%d_g%d_invX", qi, j), invDXNat)
						invDNegXExpr := addE4(fmt.Sprintf("airverify.deep_q%d_g%d_invNegX", qi, j), invDNegXNat)

						// Constrain inv * denom = 1 (E4 equality, 4 limbs).
						oneE4 := extfield.One()
						prodX := invDXExpr.Mul(denomX)
						for _, rel := range prodX.EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}
						prodNegX := invDNegXExpr.Mul(denomNegX)
						for _, rel := range prodNegX.EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}

						dqP = dqP.Add(vs.Sub(cX).Mul(invDXExpr))
						dqQ = dqQ.Add(vs.Sub(cNegX).Mul(invDNegXExpr))
					}

					// AIR-chunks group: shift = 0, omegaShift = 1, so zs = zeta.
					if len(dqLayout.AIRChunks[0]) > 0 {
						zsExpr := zetaConst

						vs := extfield.Zero()
						cX := extfield.Zero()
						cNegX := extfield.Zero()
						for _, chunkName := range dqLayout.AIRChunks[0] {
							chunkExpr, ok := chunkByName[chunkName]
							if !ok {
								return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: chunk %q missing", chunkName)
							}
							a := alphaPowChain[alphaIdx]
							alphaIdx++
							vs = vs.Add(chunkExpr.Mul(a))
							cX = cX.Add(chunkSampleP[chunkName][qi].Mul(a))
							cNegX = cNegX.Add(chunkSampleQ[chunkName][qi].Mul(a))
						}

						denomX := zsExpr.Sub(xExpr)
						denomNegX := zsExpr.Sub(negXExpr)

						var xNat ext.E4
						xNat.B0.A0.Exp(friDomainGen, big.NewInt(int64(query.digestNat%uint64(halfDomain))))
						var negXNat ext.E4
						negXNat.B0.A0.Neg(&xNat.B0.A0)
						var dXNat ext.E4
						dXNat.Sub(&zeta, &xNat)
						var dNegXNat ext.E4
						dNegXNat.Sub(&zeta, &negXNat)
						var invDXNat, invDNegXNat ext.E4
						invDXNat.Inverse(&dXNat)
						invDNegXNat.Inverse(&dNegXNat)

						invDXExpr := addE4(fmt.Sprintf("airverify.deep_q%d_chunks_invX", qi), invDXNat)
						invDNegXExpr := addE4(fmt.Sprintf("airverify.deep_q%d_chunks_invNegX", qi), invDNegXNat)

						oneE4 := extfield.One()
						prodX := invDXExpr.Mul(denomX)
						for _, rel := range prodX.EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}
						prodNegX := invDNegXExpr.Mul(denomNegX)
						for _, rel := range prodNegX.EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}

						dqP = dqP.Add(vs.Sub(cX).Mul(invDXExpr))
						dqQ = dqQ.Add(vs.Sub(cNegX).Mul(invDNegXExpr))
					}

					// Equate DQ_P, DQ_Q to the FRI level-0 query layer leaves
					// (already trusted/Merkle-bound via Stages 9/10).
					leafFRI := leafExprs[0][qi]
					for _, rel := range dqP.EqualityConstraints(leafFRI.P) {
						verifierMod.AssertZeroAt(rel, query.digestRow)
					}
					for _, rel := range dqQ.EqualityConstraints(leafFRI.Q) {
						verifierMod.AssertZeroAt(rel, query.digestRow)
					}
				}

				// Stage 12: per-column Merkle openings. Bind each sampleP/Q
				// witness to the committed Merkle tree for its column.
				// Build a multi-pair leafhash in airverify per (tree,
				// query) — emitting an 8-limb digest. The post-AddModule
				// section wires a separate merkle module (no internal
				// leafhash) per (tree, query) with Current[0] cross-bound
				// to the airverify digest via Exposed values, and
				// Parent[depth-1] bound to the tree's committed root.
				//
				// Sample columns are sorted by PolyIdx within each tree.
				// Native HashLeaf processes base pairs first (in PolyIdx
				// order) then ext pairs — our flexible leafhash matches
				// that layout via two parallel slices.
				treeEntries := map[int][]colEntry{}
				for _, n := range bareList {
					slot := innerLayout.ColSlot[n]
					treeEntries[slot.TreeIdx] = append(treeEntries[slot.TreeIdx], colEntry{name: n, polyIdx: slot.PolyIdx, field: slot.Field})
				}
				for _, n := range dqLayout.AIRChunks[0] {
					slot := innerLayout.AIRChunkSlot[n]
					treeEntries[slot.TreeIdx] = append(treeEntries[slot.TreeIdx], colEntry{name: n, polyIdx: slot.PolyIdx, field: slot.Field, isChunk: true})
				}
				treeIDs := make([]int, 0, len(treeEntries))
				for t := range treeEntries {
					treeIDs = append(treeIDs, t)
				}
				sort.Ints(treeIDs)
				for _, t := range treeIDs {
					// Sort by PolyIdx so the leafhash input matches the
					// native tree leaf layout.
					sort.Slice(treeEntries[t], func(a, b int) bool {
						return treeEntries[t][a].polyIdx < treeEntries[t][b].polyIdx
					})
					// Within a tree, base pairs come before ext pairs in
					// HashLeaf order. PolyIdx already separates the two
					// because Loom groups base columns first when assigning
					// polyIdx; we reassert by partitioning here.
					entries := treeEntries[t]
					sort.SliceStable(entries, func(a, b int) bool {
						af := entries[a].field == field.Base
						bf := entries[b].field == field.Base
						if af != bf {
							return af
						}
						return entries[a].polyIdx < entries[b].polyIdx
					})
				}

				sampleColName := func(prefixRole string, qi int, name string, limb int) string {
					return fmt.Sprintf("airverify.deep_%s_%d_%s_%d", prefixRole, qi, sanitizeName(name), limb)
				}

				for _, t := range treeIDs {
					entries := treeEntries[t]
					for qi := range queries {
						// Build base / ext column-name slices.
						var basePCols, baseQCols []string
						var extPCols, extQCols [][extfield.Limbs]string
						for _, e := range entries {
							pRole, qRole := "sP", "sQ"
							if e.isChunk {
								pRole, qRole = "csP", "csQ"
							}
							if e.field == field.Base {
								basePCols = append(basePCols, sampleColName(pRole, qi, e.name, 0))
								baseQCols = append(baseQCols, sampleColName(qRole, qi, e.name, 0))
							} else {
								var pc, qc [extfield.Limbs]string
								for i := 0; i < extfield.Limbs; i++ {
									pc[i] = sampleColName(pRole, qi, e.name, i)
									qc[i] = sampleColName(qRole, qi, e.name, i)
								}
								extPCols = append(extPCols, pc)
								extQCols = append(extQCols, qc)
							}
						}
						lhPrefix := fmt.Sprintf("airverify.lh_t%d_q%d", t, qi)
						lhCN := leafhash.RegisterFlexibleLeafHash(&verifierMod, lhPrefix, basePCols, baseQCols, extPCols, extQCols)

						// Native leaf digest, expected root, path.
						leaf := nativeLeafFor(entries, input.Proof.PointSamplings[qi][t])
						spongeStates := leafhash.FlexibleLeafSpongeStates(leaf)
						blockInputs := make([][24]koalabear.Element, lhCN.NumBlocks)
						for b := range blockInputs {
							blockInputs[b] = spongeStates[b]
						}
						pendingLeafSponges = append(pendingLeafSponges, pendingLeafSpongeFill{cn: lhCN, input: blockInputs})

						root := input.Proof.Commitments[t]
						path := input.Proof.PointSamplings[qi][t].Proof
						depth := len(path.Siblings)
						if depth == 0 {
							return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: empty column-tree Merkle path for tree %d query %d", t, qi)
						}
						treeMerkles = append(treeMerkles, treeMerkleSetup{
							treeIdx:    t,
							queryIdx:   qi,
							digestCols: lhCN.Digest,
							leafDigest: nativeLeafDigestFor(entries, input.Proof.PointSamplings[qi][t]),
							siblings:   path.Siblings,
							leafIdx:    path.LeafIdx,
							root:       root,
						})
					}
				}
			}
		} else {
			// Stage 13: multi-degree DEEP bridge.
			//
			// For multi-size inner proofs, the FRI verifier computes a
			// SEPARATE DEEP-quotient per running-poly size and equates
			// each to the corresponding FRI level's query leaves:
			//   level 0     -> FRIQueries[q].Layers[0]
			//   level i > 0 -> LevelQueries[i-1][q]
			//
			// The bridge math is identical to single-size — same per-
			// shift accumulators, same denominators (z_s - X), same
			// alpha^k chain — applied independently per size with that
			// size's domain generator and bit slice from digest[1].
			// (alpha resets to 1 at the top of each size in the native
			// verifier; the same alphaPow chain works because we re-
			// index from alphaPowChain[0] per size.)
			//
			// Per-column Merkle openings for the multi-degree sample
			// witnesses, plus Merkle for the level i > 0 query leaves
			// against DeepQuotientCommitment[i], remain follow-up
			// stages — those leaves are trusted here.
			dqLayout := prover.BuildDeepQuotientLayout(input.Program)
			numSizes := len(dqLayout.Sizes)
			if numSizes < 2 {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 expected ≥2 sizes, got %d (single-size path should have handled this)", numSizes)
			}
			if numSizes-1 != len(friProof.LevelQueries) {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 size/LevelQueries mismatch: %d sizes, %d LevelQueries", numSizes, len(friProof.LevelQueries))
			}

			// Anchor zeta_const + DEEP_ALPHA (same pattern as single-size).
			zetaConst := addE4("airverify.zeta_const_md", zeta)
			for _, rel := range zetaConst.EqualityConstraints(zetaExpr) {
				verifierMod.AssertZeroAt(rel, chCN.DigestRow)
			}
			deepAlphaIdx := -1
			for i, step := range chain {
				if step.Name == constants.DEEP_ALPHA {
					deepAlphaIdx = i
					break
				}
			}
			if deepAlphaIdx < 0 {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: DEEP_ALPHA missing from chain")
			}
			deepAlphaCN := chSpongeCNs[deepAlphaIdx]
			deepAlphaDigestExpr := extfield.FromLimbs(
				expr.Col(deepAlphaCN.Digest[0]), expr.Col(deepAlphaCN.Digest[2]),
				expr.Col(deepAlphaCN.Digest[1]), expr.Col(deepAlphaCN.Digest[3]),
			)
			deepAlphaNative := hashDigestToE4(chain[deepAlphaIdx].NativeDigest)
			deepAlphaExpr := addE4("airverify.deep_alpha_md", deepAlphaNative)
			for _, rel := range deepAlphaExpr.EqualityConstraints(deepAlphaDigestExpr) {
				verifierMod.AssertZeroAt(rel, deepAlphaCN.DigestRow)
			}

			// Materialize alpha^k chain up to max K across all sizes.
			maxK := 0
			for i := 0; i < numSizes; i++ {
				K := 0
				for _, names := range dqLayout.Names[i] {
					K += len(names)
				}
				K += len(dqLayout.AIRChunks[i])
				if K > maxK {
					maxK = K
				}
			}
			alphaPowChain := make([]extfield.E4Expr, maxK)
			alphaPowNative := make([]ext.E4, maxK)
			if maxK > 0 {
				alphaPowNative[0].SetOne()
				alphaPowChain[0] = extfield.One()
			}
			for k := 1; k < maxK; k++ {
				alphaPowNative[k].Mul(&alphaPowNative[k-1], &deepAlphaNative)
				curr := addE4(fmt.Sprintf("airverify.deep_alphaPow_md_%d", k), alphaPowNative[k])
				prevTimesAlpha := alphaPowChain[k-1].Mul(deepAlphaExpr)
				for _, rel := range curr.EqualityConstraints(prevTimesAlpha) {
					verifierMod.AssertZeroAt(rel, 0)
				}
				alphaPowChain[k] = curr
			}

			// Unified leaf-by-key + chunk-by-name lookups across all sizes.
			leafByKey := map[string]extfield.E4Expr{}
			chunkByName := map[string]extfield.E4Expr{}
			for mi, data := range mods {
				for key, e := range witnesses[mi].leafExprs {
					leafByKey[key] = e
				}
				for ci, ce := range witnesses[mi].chunkExprs {
					chunkName := constants.QuotientChunkName(data.name, ci)
					chunkByName[chunkName] = ce
				}
			}

			// Allocate samples for all bare cols + chunks across all sizes.
			bareSeen := map[string]bool{}
			var bareList []string
			chunkSeen := map[string]bool{}
			var chunkList []string
			for i := 0; i < numSizes; i++ {
				for _, names := range dqLayout.Names[i] {
					for _, n := range names {
						if !bareSeen[n] {
							bareSeen[n] = true
							bareList = append(bareList, n)
						}
					}
				}
				for _, n := range dqLayout.AIRChunks[i] {
					if !chunkSeen[n] {
						chunkSeen[n] = true
						chunkList = append(chunkList, n)
					}
				}
			}
			sort.Strings(bareList)
			sort.Strings(chunkList)

			innerLayout := prover.BuildLayout(input.Program, 0)
			sampleE4 := func(slot prover.Slot, q int) (ext.E4, ext.E4, error) {
				if slot.TreeIdx >= len(input.Proof.PointSamplings[q]) {
					return ext.E4{}, ext.E4{}, fmt.Errorf("tree %d out of range for query %d", slot.TreeIdx, q)
				}
				wp := input.Proof.PointSamplings[q][slot.TreeIdx]
				if slot.Field == field.Ext {
					if slot.PolyIdx >= len(wp.RawLeafExt) {
						return ext.E4{}, ext.E4{}, fmt.Errorf("ext raw leaf %d out of range", slot.PolyIdx)
					}
					return wp.RawLeafExt[slot.PolyIdx][0], wp.RawLeafExt[slot.PolyIdx][1], nil
				}
				if slot.PolyIdx >= len(wp.RawLeafBase) {
					return ext.E4{}, ext.E4{}, fmt.Errorf("base raw leaf %d out of range", slot.PolyIdx)
				}
				var p, qE ext.E4
				p.B0.A0.Set(&wp.RawLeafBase[slot.PolyIdx][0])
				qE.B0.A0.Set(&wp.RawLeafBase[slot.PolyIdx][1])
				return p, qE, nil
			}

			sampleP := map[string][]extfield.E4Expr{}
			sampleQ := map[string][]extfield.E4Expr{}
			for _, n := range bareList {
				slot, ok := innerLayout.ColSlot[n]
				if !ok {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: column %q missing from layout.ColSlot", n)
				}
				sampleP[n] = make([]extfield.E4Expr, len(queries))
				sampleQ[n] = make([]extfield.E4Expr, len(queries))
				for qi := range queries {
					pNative, qNative, err := sampleE4(slot, qi)
					if err != nil {
						return board.Program{}, trace.Trace{}, err
					}
					sampleP[n][qi] = addE4(fmt.Sprintf("airverify.deep_md_sP_%d_%s", qi, sanitizeName(n)), pNative)
					sampleQ[n][qi] = addE4(fmt.Sprintf("airverify.deep_md_sQ_%d_%s", qi, sanitizeName(n)), qNative)
				}
			}
			chunkSampleP := map[string][]extfield.E4Expr{}
			chunkSampleQ := map[string][]extfield.E4Expr{}
			for _, n := range chunkList {
				slot, ok := innerLayout.AIRChunkSlot[n]
				if !ok {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: chunk %q missing from layout.AIRChunkSlot", n)
				}
				chunkSampleP[n] = make([]extfield.E4Expr, len(queries))
				chunkSampleQ[n] = make([]extfield.E4Expr, len(queries))
				for qi := range queries {
					pNative, qNative, err := sampleE4(slot, qi)
					if err != nil {
						return board.Program{}, trace.Trace{}, err
					}
					chunkSampleP[n][qi] = addE4(fmt.Sprintf("airverify.deep_md_csP_%d_%s", qi, sanitizeName(n)), pNative)
					chunkSampleQ[n][qi] = addE4(fmt.Sprintf("airverify.deep_md_csQ_%d_%s", qi, sanitizeName(n)), qNative)
				}
			}

			// Allocate level leaves up front (i > 0) so both Stage 15
			// (cross-round chain with gamma intro term) and Stage 13
			// (DEEP bridge) reference the same witness columns.
			type lp struct{ P, Q extfield.E4Expr }
			levelLeavesAll := make(map[int][]lp)
			for li := 1; li < numSizes; li++ {
				levelLeavesAll[li] = make([]lp, len(queries))
				for qi := range queries {
					lvq := friProof.LevelQueries[li-1][qi]
					pE := addE4(fmt.Sprintf("airverify.deep_md_levelP_%d_%d", li, qi), lvq.LeafPExt)
					qE := addE4(fmt.Sprintf("airverify.deep_md_levelQ_%d_%d", li, qi), lvq.LeafQExt)
					levelLeavesAll[li][qi] = lp{P: pE, Q: qE}
				}
			}

			// Stage 15: cross-round FRI fold chain with multi-degree
			// level-intro gamma terms. Stage 9's per-(round, query)
			// loop already builds the in-circuit fold value for every
			// round; here we ADD a constraint
			//
			//   expected_jk + gamma_l * level_leaf_jk  ==  selected_jk
			//
			// at every non-final round j (the gamma term is dropped when
			// no level intro hits round j+1). level_leaf_jk picks
			// LevelQueries[l-1][k].LeafP/Q via the same top-bit selector
			// the fold chain already uses for pNext / qNext. xInv is
			// reused from Stage 9's binexp output (lives in
			// `airverify.fri_q{k}_xInv_{j}.step_{numBaseBits}`).
			//
			// We map round j+1 -> level l via levelAtRound, derived from
			// dqLayout.Sizes: a level l is introduced at the round where
			// the running poly degree drops to sizes[l] = sizes[0] >> jl.
			levelAtRound := map[int]int{}
			for l := 1; l < numSizes; l++ {
				ratio := dqLayout.Sizes[0] / dqLayout.Sizes[l]
				jl := log2int(ratio)
				if jl >= 1 && jl < log2int(maxModN) {
					levelAtRound[jl] = l
				}
			}

			// Anchor gammas as constant-fill witness columns linked to
			// their fri_level_l_gamma chain digest at the digest row.
			gammaExprs := map[int]extfield.E4Expr{}
			for l := 1; l < numSizes; l++ {
				gammaName := friLevelGammaName(l)
				gammaIdx := -1
				for i, step := range chain {
					if step.Name == gammaName {
						gammaIdx = i
						break
					}
				}
				if gammaIdx < 0 {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: %s missing from chain", gammaName)
				}
				gammaCN := chSpongeCNs[gammaIdx]
				gammaDigestExpr := extfield.FromLimbs(
					expr.Col(gammaCN.Digest[0]), expr.Col(gammaCN.Digest[2]),
					expr.Col(gammaCN.Digest[1]), expr.Col(gammaCN.Digest[3]),
				)
				gammaNative := hashDigestToE4(chain[gammaIdx].NativeDigest)
				gammaExpr := addE4(fmt.Sprintf("airverify.fri_gamma_%d", l), gammaNative)
				for _, rel := range gammaExpr.EqualityConstraints(gammaDigestExpr) {
					verifierMod.AssertZeroAt(rel, gammaCN.DigestRow)
				}
				gammaExprs[l] = gammaExpr
			}

			// Cross-round chain constraints.
			var invTwoBase15 koalabear.Element
			var twoBase15 koalabear.Element
			twoBase15.SetUint64(2)
			invTwoBase15.Inverse(&twoBase15)
			invTwoConst15 := expr.Const(invTwoBase15)
			oneConst15 := expr.Const(koalabear.One())
			numRounds := log2int(maxModN)
			for j := 0; j < numRounds-1; j++ {
				Nj := (constants.RATE * dqLayout.Sizes[0]) >> j
				numBaseBits := log2int(Nj / 2)
				for k, query := range queries {
					// Reuse the xInv that Stage 9 already binexp'd.
					xInvColName := fmt.Sprintf("airverify.fri_q%d_xInv_%d.step_%d", k, j, numBaseBits)
					xInvExpr := extfield.FromBase(expr.Col(xInvColName))

					P := leafExprs[j][k].P
					Q := leafExprs[j][k].Q
					sumHalf := P.Add(Q).MulByBase(invTwoConst15)
					diff := P.Sub(Q)
					diffScaled := diff.MulByBase(invTwoConst15)
					folded := alphaExprs[j].Mul(diffScaled).Mul(xInvExpr)
					expected := sumHalf.Add(folded)

					topBit := expr.Col(query.bitsCN.Bits[numBaseBits-1])
					notTopBit := oneConst15.Sub(topBit)
					pNext := leafExprs[j+1][k].P
					qNext := leafExprs[j+1][k].Q

					if l, ok := levelAtRound[j+1]; ok {
						levelP := levelLeavesAll[l][k].P
						levelQ := levelLeavesAll[l][k].Q
						levelLeaf := levelP.MulByBase(notTopBit).Add(levelQ.MulByBase(topBit))
						expected = expected.Add(gammaExprs[l].Mul(levelLeaf))
					}

					selected := pNext.MulByBase(notTopBit).Add(qNext.MulByBase(topBit))
					for _, rel := range expected.EqualityConstraints(selected) {
						verifierMod.AssertZeroAt(rel, query.digestRow)
					}
				}
			}

			// Per size, per query: compute DQ_P/Q and equate to level leaves.
			for li := 0; li < numSizes; li++ {
				size := dqLayout.Sizes[li]
				nFRIsize := constants.RATE * size
				halfDomain := nFRIsize / 2
				sLBits := log2int(halfDomain)
				if sLBits <= 0 {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 sLBits=%d for size %d", sLBits, size)
				}
				friDomainGen, err := koalabear.Generator(uint64(nFRIsize))
				if err != nil {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 friDomainGen size %d: %w", size, err)
				}
				omegaSize, err := koalabear.Generator(uint64(size))
				if err != nil {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 omegaSize %d: %w", size, err)
				}
				omegaShiftE4 := make([]ext.E4, len(dqLayout.Shifts[li]))
				omegaShiftExpr := make([]extfield.E4Expr, len(dqLayout.Shifts[li]))
				for j, shift := range dqLayout.Shifts[li] {
					var w koalabear.Element
					w.Exp(omegaSize, big.NewInt(int64(shift)))
					omegaShiftE4[j].B0.A0.Set(&w)
					omegaShiftExpr[j] = extfield.Const(omegaShiftE4[j])
				}

				// Level-leaf expressions per query.
				levelLeaves := make([]lp, len(queries))
				if li == 0 {
					for qi := range queries {
						levelLeaves[qi] = lp{P: leafExprs[0][qi].P, Q: leafExprs[0][qi].Q}
					}
				} else {
					copy(levelLeaves, levelLeavesAll[li])
				}

				for qi, query := range queries {
					sLBitsCN := bits.ColumnNames{
						ModuleName: query.bitsCN.ModuleName,
						Value:      query.bitsCN.Value,
						Bits:       query.bitsCN.Bits[:sLBits],
						NumBits:    sLBits,
					}
					xPrefix := fmt.Sprintf("airverify.deep_md_q%d_l%d_X", qi, li)
					xCN := binexp.Register(&verifierMod, xPrefix, friDomainGen, sLBitsCN)
					xBase := expr.Col(xCN.Steps[sLBits-1])
					xExpr := extfield.FromBase(xBase)
					negXExpr := extfield.Zero().Sub(xExpr)
					bitsAtRow := make([]bool, sLBits)
					for bi := 0; bi < sLBits; bi++ {
						bitsAtRow[bi] = (query.digestNat>>uint(bi))&1 == 1
					}
					pendingBinexps = append(pendingBinexps, pendingBinexp{cn: xCN, rowIdx: query.digestRow, bitsAtRow: bitsAtRow})

					// Native helpers for inverse witness fill.
					sLNat := query.digestNat % uint64(halfDomain)
					var xNat ext.E4
					xNat.B0.A0.Exp(friDomainGen, big.NewInt(int64(sLNat)))
					var negXNat ext.E4
					negXNat.B0.A0.Neg(&xNat.B0.A0)

					dqP := extfield.Zero()
					dqQ := extfield.Zero()
					alphaIdx := 0

					for j := range dqLayout.Shifts[li] {
						zsExpr := zetaConst.Mul(omegaShiftExpr[j])
						names := dqLayout.Names[li][j]
						keys := dqLayout.Keys[li][j]

						vs := extfield.Zero()
						cX := extfield.Zero()
						cNegX := extfield.Zero()
						for k, key := range keys {
							evalAtZ, ok := leafByKey[key]
							if !ok {
								return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 missing leaf key %q", key)
							}
							a := alphaPowChain[alphaIdx]
							alphaIdx++
							vs = vs.Add(evalAtZ.Mul(a))
							cX = cX.Add(sampleP[names[k]][qi].Mul(a))
							cNegX = cNegX.Add(sampleQ[names[k]][qi].Mul(a))
						}

						denomX := zsExpr.Sub(xExpr)
						denomNegX := zsExpr.Sub(negXExpr)

						var zsNat ext.E4
						zsNat.MulByElement(&zeta, &omegaShiftE4[j].B0.A0)
						var dXNat, dNegXNat ext.E4
						dXNat.Sub(&zsNat, &xNat)
						dNegXNat.Sub(&zsNat, &negXNat)
						var invDXNat, invDNegXNat ext.E4
						invDXNat.Inverse(&dXNat)
						invDNegXNat.Inverse(&dNegXNat)
						invDXExpr := addE4(fmt.Sprintf("airverify.deep_md_q%d_l%d_g%d_invX", qi, li, j), invDXNat)
						invDNegXExpr := addE4(fmt.Sprintf("airverify.deep_md_q%d_l%d_g%d_invNegX", qi, li, j), invDNegXNat)

						oneE4 := extfield.One()
						for _, rel := range invDXExpr.Mul(denomX).EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}
						for _, rel := range invDNegXExpr.Mul(denomNegX).EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}

						dqP = dqP.Add(vs.Sub(cX).Mul(invDXExpr))
						dqQ = dqQ.Add(vs.Sub(cNegX).Mul(invDNegXExpr))
					}

					if len(dqLayout.AIRChunks[li]) > 0 {
						zsExpr := zetaConst
						vs := extfield.Zero()
						cX := extfield.Zero()
						cNegX := extfield.Zero()
						for _, chunkName := range dqLayout.AIRChunks[li] {
							chunkExpr, ok := chunkByName[chunkName]
							if !ok {
								return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: stage 13 missing chunk %q", chunkName)
							}
							a := alphaPowChain[alphaIdx]
							alphaIdx++
							vs = vs.Add(chunkExpr.Mul(a))
							cX = cX.Add(chunkSampleP[chunkName][qi].Mul(a))
							cNegX = cNegX.Add(chunkSampleQ[chunkName][qi].Mul(a))
						}

						denomX := zsExpr.Sub(xExpr)
						denomNegX := zsExpr.Sub(negXExpr)

						var dXNat, dNegXNat ext.E4
						dXNat.Sub(&zeta, &xNat)
						dNegXNat.Sub(&zeta, &negXNat)
						var invDXNat, invDNegXNat ext.E4
						invDXNat.Inverse(&dXNat)
						invDNegXNat.Inverse(&dNegXNat)
						invDXExpr := addE4(fmt.Sprintf("airverify.deep_md_q%d_l%d_chunks_invX", qi, li), invDXNat)
						invDNegXExpr := addE4(fmt.Sprintf("airverify.deep_md_q%d_l%d_chunks_invNegX", qi, li), invDNegXNat)

						oneE4 := extfield.One()
						for _, rel := range invDXExpr.Mul(denomX).EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}
						for _, rel := range invDNegXExpr.Mul(denomNegX).EqualityConstraints(oneE4) {
							verifierMod.AssertZeroAt(rel, query.digestRow)
						}

						dqP = dqP.Add(vs.Sub(cX).Mul(invDXExpr))
						dqQ = dqQ.Add(vs.Sub(cNegX).Mul(invDNegXExpr))
					}

					for _, rel := range dqP.EqualityConstraints(levelLeaves[qi].P) {
						verifierMod.AssertZeroAt(rel, query.digestRow)
					}
					for _, rel := range dqQ.EqualityConstraints(levelLeaves[qi].Q) {
						verifierMod.AssertZeroAt(rel, query.digestRow)
					}
				}
			}

			// Stage 12 (multi-degree): per-column Merkle openings for the
			// sample witnesses Stage 13 just allocated. Same pattern as
			// the single-size Stage 12 — group bare names + chunks by
			// innerLayout.{ColSlot,AIRChunkSlot}[name].TreeIdx, build a
			// flexible leafhash (potentially multi-block) per (tree,
			// query) in airverify, and push a treeMerkleSetup entry so
			// the post-AddModule wiring builds the per-tree merkle
			// module + bindings.
			treeEntries := map[int][]colEntry{}
			for _, n := range bareList {
				slot := innerLayout.ColSlot[n]
				treeEntries[slot.TreeIdx] = append(treeEntries[slot.TreeIdx], colEntry{name: n, polyIdx: slot.PolyIdx, field: slot.Field})
			}
			for _, n := range chunkList {
				slot := innerLayout.AIRChunkSlot[n]
				treeEntries[slot.TreeIdx] = append(treeEntries[slot.TreeIdx], colEntry{name: n, polyIdx: slot.PolyIdx, field: slot.Field, isChunk: true})
			}
			treeIDs := make([]int, 0, len(treeEntries))
			for t := range treeEntries {
				treeIDs = append(treeIDs, t)
			}
			sort.Ints(treeIDs)
			for _, t := range treeIDs {
				sort.SliceStable(treeEntries[t], func(a, b int) bool {
					af := treeEntries[t][a].field == field.Base
					bf := treeEntries[t][b].field == field.Base
					if af != bf {
						return af
					}
					return treeEntries[t][a].polyIdx < treeEntries[t][b].polyIdx
				})
			}

			sampleColNameMD := func(prefixRole string, qi int, name string, limb int) string {
				return fmt.Sprintf("airverify.deep_md_%s_%d_%s_%d", prefixRole, qi, sanitizeName(name), limb)
			}
			for _, t := range treeIDs {
				entries := treeEntries[t]
				for qi := range queries {
					var basePCols, baseQCols []string
					var extPCols, extQCols [][extfield.Limbs]string
					for _, e := range entries {
						pRole, qRole := "sP", "sQ"
						if e.isChunk {
							pRole, qRole = "csP", "csQ"
						}
						if e.field == field.Base {
							basePCols = append(basePCols, sampleColNameMD(pRole, qi, e.name, 0))
							baseQCols = append(baseQCols, sampleColNameMD(qRole, qi, e.name, 0))
						} else {
							var pc, qc [extfield.Limbs]string
							for i := 0; i < extfield.Limbs; i++ {
								pc[i] = sampleColNameMD(pRole, qi, e.name, i)
								qc[i] = sampleColNameMD(qRole, qi, e.name, i)
							}
							extPCols = append(extPCols, pc)
							extQCols = append(extQCols, qc)
						}
					}
					lhPrefix := fmt.Sprintf("airverify.lh_md_t%d_q%d", t, qi)
					lhCN := leafhash.RegisterFlexibleLeafHash(&verifierMod, lhPrefix, basePCols, baseQCols, extPCols, extQCols)

					leaf := nativeLeafFor(entries, input.Proof.PointSamplings[qi][t])
					spongeStates := leafhash.FlexibleLeafSpongeStates(leaf)
					blockInputs := make([][24]koalabear.Element, lhCN.NumBlocks)
					for b := range blockInputs {
						blockInputs[b] = spongeStates[b]
					}
					pendingLeafSponges = append(pendingLeafSponges, pendingLeafSpongeFill{cn: lhCN, input: blockInputs})

					root := input.Proof.Commitments[t]
					path := input.Proof.PointSamplings[qi][t].Proof
					depth := len(path.Siblings)
					if depth == 0 {
						return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: empty column-tree path tree %d query %d", t, qi)
					}
					if depth > verifierMod.N {
						return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: column-tree path depth %d exceeds airverify N=%d", depth, verifierMod.N)
					}
					treeMerkles = append(treeMerkles, treeMerkleSetup{
						treeIdx:    t,
						queryIdx:   qi,
						digestCols: lhCN.Digest,
						leafDigest: nativeLeafDigestFor(entries, input.Proof.PointSamplings[qi][t]),
						siblings:   path.Siblings,
						leafIdx:    path.LeafIdx,
						root:       root,
					})
				}
			}
		}
	}

	builder.AddModule(verifierMod)

	// Stage 10: per-layer Merkle openings for query 0 (all rounds).
	// For each fold round j, build a separate merkle module of N =
	// airverify.N. Cross-bind airverify's (LeafP_q0_rj, LeafQ_q0_rj)
	// witnesses to the merkle module's row-0 leaf via expose/Exposed
	// (same-N reconstruction). The top-real-row parent (= path
	// depth - 1) is constrained to equal the FRI commitment root for
	// round j as a constant. Together this forces the leaves used in
	// the Stage 9 fold chain to actually live in the committed tree.
	type pendingMerkleFill struct {
		cn       merkle.ColumnNames
		capacity int
		path     merkle.Path
	}
	var pendingMerkleFills []pendingMerkleFill
	if len(input.Proof.DeepQuotientCommitment) > 0 {
		friProof := input.Proof.DeepQuotientFriProof
		numRounds := log2int(maxModN)

		// Sibling-side Merkle path for query 0 at each round, plus the
		// expected root for that round. Round 0's root comes from the
		// DEEP-quotient layer-0 commitment; rounds j>0 from the FRI
		// running-poly roots bound into the chain at fri_fold_j.
		rootForRound := func(j int) hash.Digest {
			if j == 0 {
				return input.Proof.DeepQuotientCommitment[0]
			}
			return friProof.FRIRoots[j-1]
		}

		for j := 0; j < numRounds; j++ {
			layer := friProof.FRIQueries[0].Layers[j]
			depth := len(layer.Path.Siblings)
			if depth == 0 {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: empty Merkle path for query 0 round %d", j)
			}
			if depth > verifierMod.N {
				return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: query 0 round %d path depth %d exceeds airverify N=%d", j, depth, verifierMod.N)
			}

			// Expose airverify's leaf witnesses so the merkle module
			// (with the same N) can pin its row-0 LeafP/LeafQ to them.
			// pos=0 is arbitrary: addE4 fills every row with the same
			// constant so the column is row-invariant.
			for i := 0; i < extfield.Limbs; i++ {
				pName := fmt.Sprintf("airverify.fri_q0_P_%d_%d", j, i)
				qName := fmt.Sprintf("airverify.fri_q0_Q_%d_%d", j, i)
				pExpose := fmt.Sprintf("merk_q0_P_r%d_%d", j, i)
				qExpose := fmt.Sprintf("merk_q0_Q_r%d_%d", j, i)
				builder.AddExposeIthValueStep("airverify", expr.Col(pName), pExpose, 0)
				builder.AddExposeIthValueStep("airverify", expr.Col(qName), qExpose, 0)
			}

			// Build the merkle module at N = airverify.N. The merkle
			// gadget pads the path to module size with self-consistent
			// rows so the chaining constraint stays satisfied.
			merkleName := fmt.Sprintf("merk_q0_r%d", j)
			cn := merkle.BuildModule(&builder, merkleName, verifierMod.N)

			merkleMod := builder.Modules[merkleName]

			// Row-0 leaf binding.
			for i := 0; i < extfield.Limbs; i++ {
				pExpose := fmt.Sprintf("merk_q0_P_r%d_%d", j, i)
				qExpose := fmt.Sprintf("merk_q0_Q_r%d_%d", j, i)
				merkleMod.AssertEqualAt(expr.Col(cn.LeafP[i]), expr.Exposed(pExpose), 0)
				merkleMod.AssertEqualAt(expr.Col(cn.LeafQ[i]), expr.Exposed(qExpose), 0)
			}

			// Top-real-row parent = FRI commitment root for round j.
			rootJ := rootForRound(j)
			for i := 0; i < merkle.DigestWidth; i++ {
				merkleMod.AssertZeroAt(expr.Col(cn.Parent[i]).Sub(expr.Const(rootJ[i])), depth-1)
			}

			path := merkle.Path{
				LeafP:    layer.LeafPExt,
				LeafQ:    layer.LeafQExt,
				LeafIdx:  layer.Path.LeafIdx,
				Siblings: layer.Path.Siblings,
			}
			pendingMerkleFills = append(pendingMerkleFills, pendingMerkleFill{cn: cn, capacity: verifierMod.N, path: path})
		}
	}

	// Stage 12 (post-AddModule): wire the per-column Merkle modules
	// using the digests emitted by Stage 12's in-airverify leafhashes.
	type pendingMerkleFillDigest struct {
		cn       merkle.ColumnNames
		capacity int
		path     merkle.PathWithDigest
	}
	var pendingMerkleFillsDigest []pendingMerkleFillDigest
	for _, ts := range treeMerkles {
		// Expose the 8 leaf-digest limbs from airverify so the merkle
		// module (same N) can reconstruct them at zeta.
		exposeNames := make([]string, leafhash.DigestLen)
		for i := 0; i < leafhash.DigestLen; i++ {
			exposeNames[i] = fmt.Sprintf("merk_lh_t%d_q%d_%d", ts.treeIdx, ts.queryIdx, i)
			builder.AddExposeIthValueStep("airverify", expr.Col(ts.digestCols[i]), exposeNames[i], 0)
		}

		merkleName := fmt.Sprintf("merk_col_t%d_q%d", ts.treeIdx, ts.queryIdx)
		cn := merkle.BuildModuleNoLeafHash(&builder, merkleName, verifierMod.N)
		merkleMod := builder.Modules[merkleName]
		// Row-0 leaf = exposed leafhash digest.
		for i := 0; i < merkle.DigestWidth; i++ {
			merkleMod.AssertEqualAt(expr.Col(cn.Current[i]), expr.Exposed(exposeNames[i]), 0)
		}
		// Top-real-row parent = tree's committed root.
		depth := len(ts.siblings)
		if depth > verifierMod.N {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: column-tree path depth %d exceeds airverify N=%d", depth, verifierMod.N)
		}
		for i := 0; i < merkle.DigestWidth; i++ {
			merkleMod.AssertZeroAt(expr.Col(cn.Parent[i]).Sub(expr.Const(ts.root[i])), depth-1)
		}

		pendingMerkleFillsDigest = append(pendingMerkleFillsDigest, pendingMerkleFillDigest{
			cn:       cn,
			capacity: verifierMod.N,
			path: merkle.PathWithDigest{
				LeafDigest: ts.leafDigest,
				LeafIdx:    ts.leafIdx,
				Siblings:   ts.siblings,
			},
		})
	}

	// Stage 14: per-level Merkle openings.
	//
	// Stage 13's multi-degree DEEP bridge pins each LevelQueries[i-1][q]
	// leaf (i > 0) to the value DQ_i computes, but those leaves are
	// otherwise free witnesses. This stage binds them to the level-i
	// commitment root (DeepQuotientCommitment[i]) via a per-(level,
	// query) Merkle path verification — same single-ext-pair leafhash
	// pattern as Stage 10 (FRI running-poly per-layer Merkle), just
	// targeting the level commitments instead.
	if len(input.Proof.DeepQuotientCommitment) > 1 && len(input.Proof.DeepQuotientFriProof.LevelQueries) > 0 {
		friProof := input.Proof.DeepQuotientFriProof
		numLevels := len(input.Proof.DeepQuotientCommitment)
		// For each i in 1..numLevels-1: LevelQueries[i-1][q] gives the
		// level-i leaf at query position q. The root is
		// DeepQuotientCommitment[i], the same digest the chain extension
		// bound into fri_level_l_gamma's sponge inputs.
		for li := 1; li < numLevels; li++ {
			levelRoot := input.Proof.DeepQuotientCommitment[li]
			for qi := 0; qi < constants.NUM_QUERIES; qi++ {
				lq := friProof.LevelQueries[li-1][qi]
				depth := len(lq.Path.Siblings)
				if depth == 0 {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: empty Merkle path for level %d query %d", li, qi)
				}
				if depth > verifierMod.N {
					return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: level %d query %d path depth %d exceeds airverify N=%d", li, qi, depth, verifierMod.N)
				}

				// Expose airverify's level-leaf witnesses
				// (allocated by Stage 13 as `airverify.deep_md_levelP/Q_{li}_{qi}_{limb}`).
				for i := 0; i < extfield.Limbs; i++ {
					pName := fmt.Sprintf("airverify.deep_md_levelP_%d_%d_%d", li, qi, i)
					qName := fmt.Sprintf("airverify.deep_md_levelQ_%d_%d_%d", li, qi, i)
					pExpose := fmt.Sprintf("merk_lvl_l%d_q%d_P_%d", li, qi, i)
					qExpose := fmt.Sprintf("merk_lvl_l%d_q%d_Q_%d", li, qi, i)
					builder.AddExposeIthValueStep("airverify", expr.Col(pName), pExpose, 0)
					builder.AddExposeIthValueStep("airverify", expr.Col(qName), qExpose, 0)
				}

				merkleName := fmt.Sprintf("merk_lvl_l%d_q%d", li, qi)
				cn := merkle.BuildModule(&builder, merkleName, verifierMod.N)
				merkleMod := builder.Modules[merkleName]
				for i := 0; i < extfield.Limbs; i++ {
					pExpose := fmt.Sprintf("merk_lvl_l%d_q%d_P_%d", li, qi, i)
					qExpose := fmt.Sprintf("merk_lvl_l%d_q%d_Q_%d", li, qi, i)
					merkleMod.AssertEqualAt(expr.Col(cn.LeafP[i]), expr.Exposed(pExpose), 0)
					merkleMod.AssertEqualAt(expr.Col(cn.LeafQ[i]), expr.Exposed(qExpose), 0)
				}
				for i := 0; i < merkle.DigestWidth; i++ {
					merkleMod.AssertZeroAt(expr.Col(cn.Parent[i]).Sub(expr.Const(levelRoot[i])), depth-1)
				}

				pendingMerkleFills = append(pendingMerkleFills, pendingMerkleFill{
					cn:       cn,
					capacity: verifierMod.N,
					path: merkle.Path{
						LeafP:    lq.LeafPExt,
						LeafQ:    lq.LeafQExt,
						LeafIdx:  lq.Path.LeafIdx,
						Siblings: lq.Path.Siblings,
					},
				})
			}
		}
	}

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

	// Trace fill for the per-round merkle modules (Stage 10).
	for _, m := range pendingMerkleFills {
		for k, v := range merkle.GenerateTrace(m.cn, m.capacity, m.path) {
			tr.SetBase(k, v)
		}
	}

	// Trace fill for Stage 12: leafhash sponges (in airverify) and the
	// per-(tree, query) merkle modules.
	for _, p := range pendingLeafSponges {
		for b := 0; b < p.cn.NumBlocks; b++ {
			inputs := make([][24]koalabear.Element, verifierMod.N)
			for r := range inputs {
				inputs[r] = p.input[b]
			}
			cols, _ := poseidon2sponge.GenerateTrace(p.cn.Sponges[b], verifierMod.N, inputs)
			for k, v := range cols {
				tr.SetBase(k, v)
			}
		}
	}
	for _, m := range pendingMerkleFillsDigest {
		for k, v := range merkle.GenerateTraceWithDigest(m.cn, m.capacity, m.path) {
			tr.SetBase(k, v)
		}
	}

	// Trace fill for binexp running-product columns. binexp's per-row
	// constraint must hold at EVERY row: step_i = step_{i-1} * mult(b_i).
	// At off-rows the bit decomposition is all-zero, so every step
	// collapses to 1 = base^0. At rowIdx, the running product walks
	// base^(2^0 b_0 + 2^1 b_1 + ... + 2^i b_i).
	for _, p := range pendingBinexps {
		k := p.cn.NumBits
		powers := make([]koalabear.Element, k)
		powers[0].Set(&p.cn.BaseConst)
		for i := 1; i < k; i++ {
			powers[i].Square(&powers[i-1])
		}
		stepCols := make([][]koalabear.Element, k)
		for i := 0; i < k; i++ {
			col := make([]koalabear.Element, verifierMod.N)
			for r := range col {
				col[r].SetOne()
			}
			stepCols[i] = col
		}
		var running koalabear.Element
		running.SetOne()
		for i := 0; i < k; i++ {
			if i < len(p.bitsAtRow) && p.bitsAtRow[i] {
				running.Mul(&running, &powers[i])
			}
			stepCols[i][p.rowIdx].Set(&running)
		}
		for i := 0; i < k; i++ {
			tr.SetBase(p.cn.Steps[i], stepCols[i])
		}
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

// colEntry describes one column or AIR-chunk participating in a
// commitment tree's leaf for the per-column Merkle openings.
type colEntry struct {
	name    string
	polyIdx int
	field   field.Kind
	isChunk bool
}

// nativeLeafFor assembles a leafhash.FlexibleLeaf matching the
// (sorted) sample entries of a single commitment tree, reading raw
// values from a Loom PointSampling.
func nativeLeafFor(entries []colEntry, wp commitment.WMerkleProof) leafhash.FlexibleLeaf {
	var leaf leafhash.FlexibleLeaf
	for _, e := range entries {
		if e.field == field.Base {
			leaf.BasePairsP = append(leaf.BasePairsP, wp.RawLeafBase[e.polyIdx][0])
			leaf.BasePairsQ = append(leaf.BasePairsQ, wp.RawLeafBase[e.polyIdx][1])
		} else {
			leaf.ExtPairsP = append(leaf.ExtPairsP, extfield.FromE4(wp.RawLeafExt[e.polyIdx][0]))
			leaf.ExtPairsQ = append(leaf.ExtPairsQ, extfield.FromE4(wp.RawLeafExt[e.polyIdx][1]))
		}
	}
	return leaf
}

// nativeLeafDigestFor mirrors commitment.Poseidon2LeafHasher.HashLeaf
// for the entry layout.
func nativeLeafDigestFor(entries []colEntry, wp commitment.WMerkleProof) hash.Digest {
	var basePairs []commitment.PairBase
	var extPairs []commitment.PairExt
	for _, e := range entries {
		if e.field == field.Base {
			basePairs = append(basePairs, wp.RawLeafBase[e.polyIdx])
		} else {
			extPairs = append(extPairs, wp.RawLeafExt[e.polyIdx])
		}
	}
	return commitment.Poseidon2LeafHasher{}.HashLeaf(basePairs, extPairs)
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
