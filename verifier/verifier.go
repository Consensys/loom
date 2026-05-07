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
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
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
}

func newVerifierRuntime(program board.Program, setup PublicKey, publicInputs map[string]proof.PublicInput, proof proof.Proof) (verifierRunTime, error) {

	res := verifierRunTime{
		proof:        proof,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
	}

	res.fs = fiatshamir.NewTranscript(sha256.New())
	numRounds := len(program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		res.fs.NewChallenge(constants.CanonicalChallengeName(i))
	}
	res.fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	for _, tree := range setup {
		res.fs.Bind(constants.CanonicalChallengeName(0), tree.Root())
	}

	// find the largest module size N in program and populate the Committer
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
	// matching the prover) before computing the round challenge.
	for i, roundRoots := range vr.proof.TraceCommitments {
		challengeName := constants.CanonicalChallengeName(i)
		for _, root := range roundRoots {
			vr.fs.Bind(challengeName, root)
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
	for _, root := range vr.proof.AIRQuotientsCommitment {
		vr.fs.Bind(constants.FINAL_EVALUATION_POINT, root)
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
// PointSamplingsSetup / PointSamplingsTrace / PointSamplingsAIRQuotients
// against the corresponding committed root, ensuring the bridge inputs to
// FRI are bound to data the prover committed to earlier in the protocol.
func (vr *verifierRunTime) checkMerkleProofsPointSampling() error {
	NQ := constants.NUM_QUERIES

	// 1 - PointSamplingsSetup[q][i] against vr.setup[i].Root().
	if len(vr.setup) > 0 {
		if len(vr.proof.PointSamplingsSetup) != NQ {
			return fmt.Errorf("checkMerkleProofs: PointSamplingsSetup has %d queries, want %d", len(vr.proof.PointSamplingsSetup), NQ)
		}
		for q, samplings := range vr.proof.PointSamplingsSetup {
			if len(samplings) != len(vr.setup) {
				return fmt.Errorf("checkMerkleProofs: PointSamplingsSetup[%d] has %d size groups, want %d", q, len(samplings), len(vr.setup))
			}
			for i, wp := range samplings {
				if !verifyWMerkleProof(vr.setup[i].Root(), wp) {
					return fmt.Errorf("checkMerkleProofs: setup query %d size %d: invalid Merkle proof", q, i)
				}
			}
		}
	}

	// 2 - PointSamplingsTrace[q][round][i] against vr.proof.TraceCommitments[round][i].
	if len(vr.proof.PointSamplingsTrace) != NQ {
		return fmt.Errorf("checkMerkleProofs: PointSamplingsTrace has %d queries, want %d", len(vr.proof.PointSamplingsTrace), NQ)
	}
	for q, rounds := range vr.proof.PointSamplingsTrace {
		if len(rounds) != len(vr.proof.TraceCommitments) {
			return fmt.Errorf("checkMerkleProofs: PointSamplingsTrace[%d] has %d rounds, want %d", q, len(rounds), len(vr.proof.TraceCommitments))
		}
		for r, samplings := range rounds {
			if len(samplings) != len(vr.proof.TraceCommitments[r]) {
				return fmt.Errorf("checkMerkleProofs: PointSamplingsTrace[%d][%d] has %d size groups, want %d", q, r, len(samplings), len(vr.proof.TraceCommitments[r]))
			}
			for i, wp := range samplings {
				if !verifyWMerkleProof(vr.proof.TraceCommitments[r][i], wp) {
					return fmt.Errorf("checkMerkleProofs: trace query %d round %d size %d: invalid Merkle proof", q, r, i)
				}
			}
		}
	}

	// 3 - PointSamplingsAIRQuotients[q][i] against vr.proof.AIRQuotientsCommitment[i].
	if len(vr.proof.PointSamplingsAIRQuotients) != NQ {
		return fmt.Errorf("checkMerkleProofs: PointSamplingsAIRQuotients has %d queries, want %d", len(vr.proof.PointSamplingsAIRQuotients), NQ)
	}
	for q, samplings := range vr.proof.PointSamplingsAIRQuotients {
		if len(samplings) != len(vr.proof.AIRQuotientsCommitment) {
			return fmt.Errorf("checkMerkleProofs: PointSamplingsAIRQuotients[%d] has %d size groups, want %d", q, len(samplings), len(vr.proof.AIRQuotientsCommitment))
		}
		for i, wp := range samplings {
			if !verifyWMerkleProof(vr.proof.AIRQuotientsCommitment[i], wp) {
				return fmt.Errorf("checkMerkleProofs: AIR query %d size %d: invalid Merkle proof", q, i)
			}
		}
	}

	return nil
}

// checkFRIBridge is part of the FRI ↔ polynomial-commitment bridge and is
// disabled until the bridge is rewired for the multi-degree commitment scheme.
// It is not called by Verify.
//
// func (vr *verifierRunTime) checkFRIBridge() error {
//	// Sort modules by decreasing N — must match ComputeDeepQuotient in the prover.
//	sortedModule := make([]string, 0, len(vr.program.Modules))
//	for name := range vr.program.Modules {
//		sortedModule = append(sortedModule, name)
//	}
//	sort.Slice(sortedModule, func(i, j int) bool {
//		ni := vr.program.Modules[sortedModule[i]].N
//		nj := vr.program.Modules[sortedModule[j]].N
//		if ni != nj {
//			return ni > nj
//		}
//		return sortedModule[i] < sortedModule[j]
//	})
//
//	// colToSlot maps a bare column name to its position in PointSamplings[k]:
//	// samplingIdx is the WMerkleProof index, leafIdx is the index within RawLeaf.
//	// Order must match SampleEvaluations: [setup?] + tTrees[0..r-1] + airTree.
//	type colSlot struct {
//		samplingIdx int
//		leafIdx     int
//	}
//	colToSlot := make(map[string]colSlot)
//	offset := 0
//	if vr.setup.Tree != nil {
//		offset = 1
//	}
//	for roundIdx, deps := range vr.program.FScolumnsDependencies {
//		for leafIdx, name := range deps {
//			colToSlot[name] = colSlot{samplingIdx: offset + roundIdx, leafIdx: leafIdx}
//		}
//	}

// (rest of checkFRIBridge body elided — see git history)

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
	// err = vr.checkFRIBridge()
	// if err != nil {
	// 	return err
	// }

	return nil
}
