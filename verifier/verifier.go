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
	"sort"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
)

type PublicKey = []commitment.WMerkleTree

type verifierRunTime struct {
	proof        proof.Proof
	friParams    fri.Params
	publicInputs map[string]proof.PublicInput
	program      board.Program
	zeta         koalabear.Element
	setup        PublicKey
	fs           *fiatshamir.Transcript

	// layout is the canonical commitment layout, shared with the prover side
	// (built from program + len(setup) at the start of every Verify call).
	layout prover.Layout
	// roots is the flat sequence of Merkle roots in canonical order:
	//   setup roots (from PublicKey) ++ proof.Commitments
	// roots[i] aligns with proof.PointSamplings[q][i] for any query q.
	roots [][]byte
}

func newVerifierRuntime(program board.Program, setup PublicKey, publicInputs map[string]proof.PublicInput, prf proof.Proof) (verifierRunTime, error) {

	res := verifierRunTime{
		proof:        prf,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
	}

	// Build the layout shared with the prover.
	res.layout = prover.BuildLayout(program, len(setup))

	// Validate proof.Commitments matches layout (trace + AIR section).
	wantCommitments := res.layout.NumTrees - res.layout.SetupEnd
	if len(prf.Commitments) != wantCommitments {
		return res, fmt.Errorf("verifier: proof has %d commitments, layout expects %d", len(prf.Commitments), wantCommitments)
	}

	// Flatten setup roots ++ proof.Commitments into res.roots.
	res.roots = make([][]byte, res.layout.NumTrees)
	if len(setup) != res.layout.SetupEnd-res.layout.SetupBegin {
		return res, fmt.Errorf("verifier: setup has %d trees, layout expects %d", len(setup), res.layout.SetupEnd-res.layout.SetupBegin)
	}
	for i, tree := range setup {
		res.roots[res.layout.SetupBegin+i] = tree.Root()
	}
	for i, root := range prf.Commitments {
		res.roots[res.layout.SetupEnd+i] = root
	}

	res.fs = fiatshamir.NewTranscript(sha256.New())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	// Setup roots are bound to challenge_0 (alongside trace round 0 in deriveChallenges).
	for _, tree := range setup {
		res.fs.Bind(constants.CanonicalChallengeName(0), tree.Root())
	}

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

	return res, nil
}

func (vr *verifierRunTime) deriveChallenges() error {

	// For each FS round, bind every per-size trace root (decreasing N order,
	// matching the prover) before computing the round challenge. Setup roots
	// were already bound to challenge_0 in newVerifierRuntime.
	numRounds := len(vr.program.FScolumnsDependencies)
	for r := 0; r < numRounds; r++ {
		challengeName := constants.CanonicalChallengeName(r)
		for i := vr.layout.TraceBegin[r]; i < vr.layout.TraceEnd[r]; i++ {
			vr.fs.Bind(challengeName, vr.roots[i])
		}
		bChallenge, err := vr.fs.ComputeChallenge(challengeName)
		if err != nil {
			return err
		}
		var c koalabear.Element
		c.SetBytes(bChallenge)
		vr.proof.ValuesAtZeta[challengeName] = c
	}
	// Bind every per-size AIR-quotient root before computing zeta.
	for i := vr.layout.AIRBegin; i < vr.layout.AIREnd; i++ {
		vr.fs.Bind(constants.FINAL_EVALUATION_POINT, vr.roots[i])
	}
	bzeta, err := vr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	vr.zeta.SetBytes(bzeta)

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
		vr.proof.ValuesAtZeta[k] = lag
	}
	return nil
}

func (vr *verifierRunTime) computeLagrange() error {
	config := expr.OnlyLagranges
	for _, m := range vr.program.Modules {
		lags := m.VanishingRelation.Leaves(expr.NewConfig(config...))
		for _, lag := range lags {
			_, ok := vr.proof.ValuesAtZeta[lag]
			if ok {
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
			vr.proof.ValuesAtZeta[lag] = v
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

// checkAIRRelations checks the air relations per module
func (vr *verifierRunTime) checkAIRRelations() error {

	for moduleName, m := range vr.program.Modules {

		// Compute Q(zeta) = chunk_0(zeta) + zeta^N * chunk_1(zeta) + zeta^(2N) * chunk_2(zeta) + ...
		// The i-th chunk is stored in proof.ValuesAtZeta under the key "moduleName_i".
		var qZeta koalabear.Element
		var zetaPowIN koalabear.Element
		zetaPowIN.SetOne()
		var zetaN koalabear.Element
		zetaN.Exp(vr.zeta, big.NewInt(int64(m.N)))
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			chunkVal, ok := vr.proof.ValuesAtZeta[chunkName]
			if !ok {
				break
			}
			var term koalabear.Element
			term.Mul(&zetaPowIN, &chunkVal)
			qZeta.Add(&qZeta, &term)
			zetaPowIN.Mul(&zetaPowIN, &zetaN)
		}

		// Compute V(zeta): evaluate the vanishing relation DAG at zeta using ValuesAtZeta.
		vZeta := m.VanishingRelation.Eval(vr.proof.ValuesAtZeta)

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

func (vr *verifierRunTime) checkFRIProof() error {

	// Build levelDs from the program's distinct module sizes (decreasing N),
	// matching the prover's ComputeDeepQuotient grouping.
	sizesSet := map[int]bool{}
	for _, m := range vr.program.Modules {
		sizesSet[m.N] = true
	}
	levelDs := make([]int, 0, len(sizesSet))
	for n := range sizesSet {
		levelDs = append(levelDs, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(levelDs)))

	// One root per level (single polynomial per level in the current scheme).
	if len(vr.proof.DeepQuotientCommitment) != len(levelDs) {
		return fmt.Errorf("checkFRIProof: proof has %d level commitments, want %d", len(vr.proof.DeepQuotientCommitment), len(levelDs))
	}
	levelRoots := make([][][]byte, len(levelDs))
	for i := range levelDs {
		levelRoots[i] = [][]byte{vr.proof.DeepQuotientCommitment[i]}
	}

	return fri.Verify(vr.friParams, levelRoots, levelDs, vr.proof.DeepQuotientFriProof, vr.fs)
}

// verifyWMerkleProof checks wp opens to its leaf data under root, using the
// same paired-leaf serialisation as RSCommit.Commit (pair k contributes
// pair[0] || pair[1] to the leaf buffer at offset 2k).
func verifyWMerkleProof(root []byte, wp commitment.WMerkleProof) bool {
	buf := make([]byte, 2*len(wp.RawLeaf)*koalabear.Bytes)
	for k, pair := range wp.RawLeaf {
		copy(buf[2*k*koalabear.Bytes:], pair[0].Marshal())
		copy(buf[(2*k+1)*koalabear.Bytes:], pair[1].Marshal())
	}
	return merkle.Verify(root, wp.Proof, buf, commitment.LeafHash, commitment.NodeHash)
}

// checkMerkleProofsPointSampling verifies every WMerkleProof in
// proof.PointSamplings against the corresponding root in vr.roots
// (= setupRoots ++ proof.Commitments).
func (vr *verifierRunTime) checkMerkleProofsPointSampling() error {
	NQ := constants.NUM_QUERIES
	if len(vr.proof.PointSamplings) != NQ {
		return fmt.Errorf("checkMerkleProofs: PointSamplings has %d queries, want %d", len(vr.proof.PointSamplings), NQ)
	}
	for q, samplings := range vr.proof.PointSamplings {
		if len(samplings) != vr.layout.NumTrees {
			return fmt.Errorf("checkMerkleProofs: PointSamplings[%d] has %d entries, want %d", q, len(samplings), vr.layout.NumTrees)
		}
		for i, wp := range samplings {
			if !verifyWMerkleProof(vr.roots[i], wp) {
				return fmt.Errorf("checkMerkleProofs: query %d tree %d: invalid Merkle proof", q, i)
			}
		}
	}
	return nil
}

// checkFRIBridge verifies that the DEEP quotient (per size) evaluated at the
// FRI sample points (using the column / AIR-chunk samples from
// proof.PointSamplings) matches the FRI proof's level-0 layer values. It is
// the prover-side ComputeDeepQuotient computed pointwise at the FRI query
// positions instead of as a polynomial.
func (vr *verifierRunTime) checkFRIBridge() error {
	NQ := constants.NUM_QUERIES
	leafConfig := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())

	// Folding challenge — must match the prover's hard-coded value.
	// TODO derive from FS, same as prover.
	var alpha koalabear.Element
	alpha.SetUint64(10)

	// Group modules by size N (decreasing N). Within a size, names sorted
	// alphabetically — matches the prover's ComputeDeepQuotient ordering.
	modulesByN := map[int][]string{}
	for name := range vr.program.Modules {
		N := vr.program.Modules[name].N
		modulesByN[N] = append(modulesByN[N], name)
	}
	for _, names := range modulesByN {
		sort.Strings(names)
	}
	sizes := make([]int, 0, len(modulesByN))
	for n := range modulesByN {
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	// samplePair returns the (LeafP, LeafQ) pair for a given Slot at query q.
	samplePair := func(slot prover.Slot, q int) (koalabear.Element, koalabear.Element, error) {
		if slot.TreeIdx >= len(vr.proof.PointSamplings[q]) {
			return koalabear.Element{}, koalabear.Element{}, fmt.Errorf("checkFRIBridge: tree index %d out of range", slot.TreeIdx)
		}
		wp := vr.proof.PointSamplings[q][slot.TreeIdx]
		if slot.PolyIdx >= len(wp.RawLeaf) {
			return koalabear.Element{}, koalabear.Element{}, fmt.Errorf("checkFRIBridge: poly index %d out of range (have %d)", slot.PolyIdx, len(wp.RawLeaf))
		}
		return wp.RawLeaf[slot.PolyIdx][0], wp.RawLeaf[slot.PolyIdx][1], nil
	}

	for q := 0; q < NQ; q++ {
		// Full-domain FRI query position (the level-0 leaf index).
		s_full := vr.proof.DeepQuotientFriProof.FRIQueries[q].Layers[0].Path.LeafIdx

		for li, N := range sizes {
			domainSize := constants.RATE * N
			halfDomain := domainSize / 2
			s_l := s_full % halfDomain

			// Sample point for this level: omega_l^{s_l}, where omega_l is
			// the generator of the size-(RATE*N) FRI domain. fft.NewDomain
			// is deterministic so this matches what the prover used.
			domL := fft.NewDomain(uint64(domainSize))
			var X, negX koalabear.Element
			X.Exp(domL.Generator, big.NewInt(int64(s_l)))
			negX.Neg(&X)

			// Generator of the size-N domain (NOT RATE*N) — used for shift
			// evaluation z_s = zeta · ω_N^shift.
			domN := vr.program.Modules[modulesByN[N][0]].D

			var DQ_P, DQ_Q koalabear.Element
			var alphaAcc koalabear.Element
			alphaAcc.SetOne()

			// ── Phase 1: vanishing-relation columns (pool across modules of size N) ──
			type colEntry struct {
				name string // → trace ColSlot lookup
				key  string // → ValuesAtZeta lookup
			}
			byShift := map[int][]colEntry{}
			seenKey := map[string]bool{}
			for _, moduleName := range modulesByN[N] {
				module := vr.program.Modules[moduleName]
				for _, leaf := range module.VanishingRelation.LeavesFull(leafConfig) {
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
			for sh := range byShift {
				shifts = append(shifts, sh)
			}
			sort.Ints(shifts)
			for _, sh := range shifts {
				sort.Slice(byShift[sh], func(i, j int) bool { return byShift[sh][i].key < byShift[sh][j].key })
			}

			for _, shift := range shifts {
				// z_s = zeta · ω_N^shift
				var omegaShift, z_s koalabear.Element
				omegaShift.Exp(domN.Generator, big.NewInt(int64(shift)))
				z_s.Mul(&vr.zeta, &omegaShift)

				// Accumulate alphaAcc_i · column_i at zeta and at X / -X.
				var v_s, C_at_X, C_at_negX koalabear.Element
				for _, entry := range byShift[shift] {
					evalAtZ, ok := vr.proof.ValuesAtZeta[entry.key]
					if !ok {
						return fmt.Errorf("checkFRIBridge: %q not in ValuesAtZeta", entry.key)
					}
					slot, ok := vr.layout.ColSlot[entry.name]
					if !ok {
						return fmt.Errorf("checkFRIBridge: column %q not in layout.ColSlot", entry.name)
					}
					leafP, leafQ, err := samplePair(slot, q)
					if err != nil {
						return err
					}

					var term koalabear.Element
					term.Mul(&evalAtZ, &alphaAcc)
					v_s.Add(&v_s, &term)
					term.Mul(&leafP, &alphaAcc)
					C_at_X.Add(&C_at_X, &term)
					term.Mul(&leafQ, &alphaAcc)
					C_at_negX.Add(&C_at_negX, &term)

					alphaAcc.Mul(&alphaAcc, &alpha)
				}

				// DQ_shift(X) = (v_s - C_s(X)) / (z_s - X)
				var num, denom koalabear.Element
				num.Sub(&v_s, &C_at_X)
				denom.Sub(&z_s, &X)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_P.Add(&DQ_P, &num)

				num.Sub(&v_s, &C_at_negX)
				denom.Sub(&z_s, &negX)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_Q.Add(&DQ_Q, &num)
			}

			// ── Phase 2: AIR-quotient chunks (per module; eval point = zeta) ──
			for _, moduleName := range modulesByN[N] {
				var v_air, C_at_X, C_at_negX koalabear.Element
				for i := 0; ; i++ {
					chunkName := constants.QuotientChunkName(moduleName, i)
					evalAtZ, ok := vr.proof.ValuesAtZeta[chunkName]
					if !ok {
						break
					}
					slot, ok := vr.layout.AIRChunkSlot[chunkName]
					if !ok {
						return fmt.Errorf("checkFRIBridge: chunk %q not in layout.AIRChunkSlot", chunkName)
					}
					leafP, leafQ, err := samplePair(slot, q)
					if err != nil {
						return err
					}

					var term koalabear.Element
					term.Mul(&evalAtZ, &alphaAcc)
					v_air.Add(&v_air, &term)
					term.Mul(&leafP, &alphaAcc)
					C_at_X.Add(&C_at_X, &term)
					term.Mul(&leafQ, &alphaAcc)
					C_at_negX.Add(&C_at_negX, &term)

					alphaAcc.Mul(&alphaAcc, &alpha)
				}

				var num, denom koalabear.Element
				num.Sub(&v_air, &C_at_X)
				denom.Sub(&vr.zeta, &X)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_P.Add(&DQ_P, &num)

				num.Sub(&v_air, &C_at_negX)
				denom.Sub(&vr.zeta, &negX)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_Q.Add(&DQ_Q, &num)
			}

			// Compare DQ_N at (X, -X) with the FRI level-l layer-0 leaves.
			var actualP, actualQ koalabear.Element
			if li == 0 {
				actualP = vr.proof.DeepQuotientFriProof.FRIQueries[q].Layers[0].LeafP
				actualQ = vr.proof.DeepQuotientFriProof.FRIQueries[q].Layers[0].LeafQ
			} else {
				lq := vr.proof.DeepQuotientFriProof.LevelQueries[li-1][q][0]
				actualP = lq.LeafP
				actualQ = lq.LeafQ
			}
			if !DQ_P.Equal(&actualP) {
				return fmt.Errorf("checkFRIBridge: query %d level %d (N=%d): DQ(ω_l^s) mismatch: got %s, want %s", q, li, N, DQ_P.String(), actualP.String())
			}
			if !DQ_Q.Equal(&actualQ) {
				return fmt.Errorf("checkFRIBridge: query %d level %d (N=%d): DQ(-ω_l^s) mismatch: got %s, want %s", q, li, N, DQ_Q.String(), actualQ.String())
			}
		}
	}

	return nil
}

func Verify(publicInputs map[string]proof.PublicInput, setup PublicKey, program board.Program, proof proof.Proof) error {

	vr, err := newVerifierRuntime(program, setup, publicInputs, proof)
	if err != nil {
		return err
	}

	// 1 - derive the challenges, and populate proof.ValuesAtZeta with those challenges
	err = vr.deriveChallenges()
	if err != nil {
		return err
	}

	// 2 - populate proof.ValuesAtZeta with the public columns and lagrange columns
	err = vr.computePublicColumns()
	if err != nil {
		return err
	}
	err = vr.computeLagrange()
	if err != nil {
		return err
	}

	// 3 - check bus values
	err = vr.checkLogupBus()
	if err != nil {
		return err
	}

	// 4 - check the AIR relations
	err = vr.checkAIRRelations()
	if err != nil {
		return err
	}

	// ------ PCS related verification ------

	// 5a - check FRI proof
	err = vr.checkFRIProof()
	if err != nil {
		return err
	}

	// 5b - check merkle proofs of proof.PointSamplings
	err = vr.checkMerkleProofsPointSampling()
	if err != nil {
		return err
	}

	// 5c - check FRI <-> PointSamplings bridge
	err = vr.checkFRIBridge()
	if err != nil {
		return err
	}

	return nil
}
