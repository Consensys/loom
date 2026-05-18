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
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	p2crypto "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/trace"
)

const (
	poseidon2Width     = 16
	poseidon2HalfWidth = poseidon2Width / 2
)

type poseidon2MerkleTarget struct {
	Namespace string
	Input     RecursionInput
}

type poseidon2Op struct {
	Label      string
	Input      []koalabear.Element
	WantOutput []koalabear.Element
}

type poseidon2TranscriptChallenge struct {
	name       string
	bindings   [][]byte
	value      []byte
	isComputed bool
}

type poseidon2TranscriptRecorder struct {
	challenges         []poseidon2TranscriptChallenge
	nameToChallengePos map[string]int
}

type poseidon2ModuleBuilder struct {
	module    *board.Module
	lagranges map[int]expr.Expr
}

func buildPoseidon2VerifierModule(moduleName string, targets []poseidon2MerkleTarget) (board.Module, trace.Trace, error) {
	ops := make([]poseidon2Op, 0)
	for _, target := range targets {
		targetOps, err := collectPoseidon2VerifierOps(target.Namespace, target.Input)
		if err != nil {
			return board.Module{}, trace.Trace{}, err
		}
		ops = append(ops, targetOps...)
	}
	if len(ops) == 0 {
		return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: no Poseidon2 Merkle operations to arithmetize")
	}

	params := p2crypto.GetDefaultParameters()
	numRounds := params.NbFullRounds + params.NbPartialRounds
	rowsPerOp := numRounds + 1
	n := nextPowerOfTwo(maxInt(2, len(ops)*rowsPerOp))

	module := board.NewModule(moduleName)
	module.N = n
	builder := poseidon2ModuleBuilder{
		module:    &module,
		lagranges: make(map[int]expr.Expr),
	}

	tr := trace.New()
	stateNames := make([]string, poseidon2Width)
	stateCols := make([][]koalabear.Element, poseidon2Width)
	for i := range stateNames {
		stateNames[i] = fmt.Sprintf("%s.state.%d", moduleName, i)
		stateCols[i] = make([]koalabear.Element, n)
	}

	for opIdx, op := range ops {
		if len(op.Input) != poseidon2Width {
			return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: Poseidon2 op %s has input width %d, want %d", op.Label, len(op.Input), poseidon2Width)
		}
		if len(op.WantOutput) != poseidon2HalfWidth {
			return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: Poseidon2 op %s has output width %d, want %d", op.Label, len(op.WantOutput), poseidon2HalfWidth)
		}

		startRow := opIdx * rowsPerOp
		state := poseidon2MatMulExternalValues(op.Input)
		for i := range state {
			stateCols[i][startRow].Set(&state[i])
			builder.assertZeroAt(expr.Col(stateNames[i]).Sub(expr.Const(state[i])), startRow)
		}

		for round := 0; round < numRounds; round++ {
			partial := poseidon2IsPartialRound(params, round)
			state = poseidon2RoundValues(state, params.RoundKeys[round], partial)
			row := startRow + round + 1
			for i := range state {
				stateCols[i][row].Set(&state[i])
			}
		}

		finalRow := startRow + numRounds
		for i := 0; i < poseidon2HalfWidth; i++ {
			relation := expr.Col(stateNames[poseidon2HalfWidth+i]).
				Add(expr.Const(op.Input[poseidon2HalfWidth+i])).
				Sub(expr.Const(op.WantOutput[i]))
			builder.assertZeroAt(relation, finalRow)
		}
	}

	for i := range stateNames {
		tr.SetBase(stateNames[i], stateCols[i])
	}

	stateExprs := make([]expr.Expr, poseidon2Width)
	for i := range stateExprs {
		stateExprs[i] = expr.Col(stateNames[i])
	}
	transitionSelector := zeroExpr()
	expectedNext := make([]expr.Expr, poseidon2Width)
	for i := range expectedNext {
		expectedNext[i] = zeroExpr()
	}
	for round := 0; round < numRounds; round++ {
		roundSelector := zeroExpr()
		for opIdx := range ops {
			roundSelector = roundSelector.Add(builder.lagrange(opIdx*rowsPerOp + round))
		}
		transitionSelector = transitionSelector.Add(roundSelector)

		partial := poseidon2IsPartialRound(params, round)
		next := poseidon2RoundExprs(stateExprs, params.RoundKeys[round], partial)
		for i := range expectedNext {
			expectedNext[i] = expectedNext[i].Add(roundSelector.Mul(next[i]))
		}
	}
	for i := range stateNames {
		nextState := expr.Rot(stateNames[i], 1).Mul(transitionSelector)
		builder.module.AssertZero(nextState.Sub(expectedNext[i]))
	}

	return *builder.module, tr, nil
}

func collectPoseidon2VerifierOps(namespace string, input RecursionInput) ([]poseidon2Op, error) {
	transcriptOps, err := collectPoseidon2TranscriptOps(namespace, input)
	if err != nil {
		return nil, err
	}
	pointSamplingOps, err := collectPoseidon2PointSamplingMerkleOps(namespace, input)
	if err != nil {
		return nil, err
	}
	friOps, err := collectPoseidon2FRIMerkleOps(namespace, input)
	if err != nil {
		return nil, err
	}
	ops := append(transcriptOps, pointSamplingOps...)
	return append(ops, friOps...), nil
}

func collectPoseidon2TranscriptOps(namespace string, input RecursionInput) ([]poseidon2Op, error) {
	recorder, err := recordPoseidon2Transcript(input)
	if err != nil {
		return nil, err
	}

	ops := make([]poseidon2Op, 0)
	for pos, challenge := range recorder.challenges {
		if !challenge.isComputed {
			return nil, fmt.Errorf("recursion: transcript challenge %q was registered but not computed", challenge.name)
		}
		writes := make([][]byte, 0, 2+len(challenge.bindings))
		writes = append(writes, []byte(challenge.name))
		if pos != 0 {
			writes = append(writes, recorder.challenges[pos-1].value)
		}
		writes = append(writes, challenge.bindings...)

		expected, err := poseidon2DigestBytesToElements(challenge.value)
		if err != nil {
			return nil, fmt.Errorf("recursion: transcript challenge %q digest: %w", challenge.name, err)
		}
		_, challengeOps, err := poseidon2DigestWriteOps(fmt.Sprintf("%s.transcript.%d.%s", namespace, pos, challenge.name), writes)
		if err != nil {
			return nil, err
		}
		if len(challengeOps) == 0 {
			return nil, fmt.Errorf("recursion: transcript challenge %q produced no Poseidon2 operations", challenge.name)
		}
		challengeOps[len(challengeOps)-1].WantOutput = expected
		ops = append(ops, challengeOps...)
	}
	return ops, nil
}

func recordPoseidon2Transcript(input RecursionInput) (*poseidon2TranscriptRecorder, error) {
	layout := prover.BuildLayout(input.Program, len(input.Setup))
	wantCommitments := layout.NumTrees - layout.SetupEnd
	if len(input.Proof.Commitments) != wantCommitments {
		return nil, fmt.Errorf("recursion: transcript proof has %d commitments, layout expects %d", len(input.Proof.Commitments), wantCommitments)
	}
	if len(input.Setup) != layout.SetupEnd-layout.SetupBegin {
		return nil, fmt.Errorf("recursion: transcript setup has %d trees, layout expects %d", len(input.Setup), layout.SetupEnd-layout.SetupBegin)
	}

	roots := make([][]byte, layout.NumTrees)
	for i, root := range input.Setup {
		roots[layout.SetupBegin+i] = root
	}
	for i, root := range input.Proof.Commitments {
		roots[layout.SetupEnd+i] = root
	}

	recorder := newPoseidon2TranscriptRecorder()
	numRounds := len(input.Program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		if err := recorder.NewChallenge(constants.CanonicalChallengeName(i)); err != nil {
			return nil, err
		}
	}
	if err := recorder.NewChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
		return nil, err
	}
	if err := recorder.NewChallenge(constants.DEEP_ALPHA); err != nil {
		return nil, err
	}

	if numRounds > 0 {
		for _, root := range input.Setup {
			if err := recorder.Bind(constants.CanonicalChallengeName(0), root); err != nil {
				return nil, err
			}
		}
	}
	for round := 0; round < numRounds; round++ {
		challengeName := constants.CanonicalChallengeName(round)
		for i := layout.TraceBegin[round]; i < layout.TraceEnd[round]; i++ {
			if err := recorder.Bind(challengeName, roots[i]); err != nil {
				return nil, err
			}
		}
		if _, err := recorder.ComputeChallenge(challengeName); err != nil {
			return nil, err
		}
	}

	for i := layout.AIRBegin; i < layout.AIREnd; i++ {
		if err := recorder.Bind(constants.FINAL_EVALUATION_POINT, roots[i]); err != nil {
			return nil, err
		}
	}
	if _, err := recorder.ComputeChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
		return nil, err
	}

	dqLayout := prover.BuildDeepQuotientLayout(input.Program)
	if err := recorderBindDeepEvaluationClaims(recorder, input.Proof, dqLayout); err != nil {
		return nil, err
	}
	if _, err := recorder.ComputeChallenge(constants.DEEP_ALPHA); err != nil {
		return nil, err
	}

	maxN, err := maxModuleSize(input.Program)
	if err != nil {
		return nil, err
	}
	if maxN <= 1 {
		return recorder, nil
	}
	numFRIRounds, err := log2Exact(maxN)
	if err != nil {
		return nil, err
	}
	levelAtRound, err := poseidon2FRILevelAtRound(maxN, dqLayout.Sizes)
	if err != nil {
		return nil, err
	}
	if err := recorderRegisterFRIChallenges(recorder, numFRIRounds, levelAtRound); err != nil {
		return nil, err
	}
	if len(input.Proof.DeepQuotientCommitment) != len(dqLayout.Sizes) {
		return nil, fmt.Errorf("recursion: transcript FRI has %d DEEP quotient commitments, want %d", len(input.Proof.DeepQuotientCommitment), len(dqLayout.Sizes))
	}
	wantFRIRoots := numFRIRounds - 1
	if numFRIRounds <= 1 {
		wantFRIRoots = 0
	}
	if len(input.Proof.DeepQuotientFriProof.FRIRoots) != wantFRIRoots {
		return nil, fmt.Errorf("recursion: transcript FRI has %d running roots, want %d", len(input.Proof.DeepQuotientFriProof.FRIRoots), wantFRIRoots)
	}
	runningRoots := make([][]byte, numFRIRounds)
	runningRoots[0] = input.Proof.DeepQuotientCommitment[0]
	for round := 1; round < numFRIRounds; round++ {
		runningRoots[round] = input.Proof.DeepQuotientFriProof.FRIRoots[round-1]
	}

	for round := 0; round < numFRIRounds; round++ {
		if round > 0 {
			if level, ok := levelAtRound[round]; ok {
				gammaName := friLevelGammaName(level)
				if err := recorder.Bind(gammaName, input.Proof.DeepQuotientCommitment[level]); err != nil {
					return nil, err
				}
				if _, err := recorder.ComputeChallenge(gammaName); err != nil {
					return nil, err
				}
			}
		}
		foldName := friFoldName(round)
		if err := recorder.Bind(foldName, runningRoots[round]); err != nil {
			return nil, err
		}
		if _, err := recorder.ComputeChallenge(foldName); err != nil {
			return nil, err
		}
	}

	if input.Proof.DeepQuotientFriProof.FinalField != field.Ext {
		return nil, fmt.Errorf("recursion: transcript FRI final field is %s, want %s", input.Proof.DeepQuotientFriProof.FinalField, field.Ext)
	}
	if err := recorder.Bind(friQueryName(0), friSerialiseExt(input.Proof.DeepQuotientFriProof.FinalPolyExt)); err != nil {
		return nil, err
	}
	for query := 0; query < constants.NUM_QUERIES; query++ {
		b, err := recorder.ComputeChallenge(friQueryName(query))
		if err != nil {
			return nil, err
		}
		if query < constants.NUM_QUERIES-1 {
			if err := recorder.Bind(friQueryName(query+1), b); err != nil {
				return nil, err
			}
		}
	}
	return recorder, nil
}

func newPoseidon2TranscriptRecorder() *poseidon2TranscriptRecorder {
	return &poseidon2TranscriptRecorder{
		nameToChallengePos: make(map[string]int),
	}
}

func (r *poseidon2TranscriptRecorder) NewChallenge(challengeID string) error {
	if _, ok := r.nameToChallengePos[challengeID]; ok {
		return fmt.Errorf("recursion: transcript challenge %q already exists", challengeID)
	}
	r.nameToChallengePos[challengeID] = len(r.challenges)
	r.challenges = append(r.challenges, poseidon2TranscriptChallenge{name: challengeID})
	return nil
}

func (r *poseidon2TranscriptRecorder) Bind(challengeID string, bValue []byte) error {
	pos, ok := r.nameToChallengePos[challengeID]
	if !ok {
		return fmt.Errorf("recursion: transcript challenge %q not found", challengeID)
	}
	if r.challenges[pos].isComputed {
		return fmt.Errorf("recursion: transcript challenge %q already computed", challengeID)
	}
	bCopy := make([]byte, len(bValue))
	copy(bCopy, bValue)
	r.challenges[pos].bindings = append(r.challenges[pos].bindings, bCopy)
	return nil
}

func (r *poseidon2TranscriptRecorder) ComputeChallenge(challengeID string) ([]byte, error) {
	pos, ok := r.nameToChallengePos[challengeID]
	if !ok {
		return nil, fmt.Errorf("recursion: transcript challenge %q not found", challengeID)
	}
	challenge := &r.challenges[pos]
	if challenge.isComputed {
		return challenge.value, nil
	}
	writes := make([][]byte, 0, 2+len(challenge.bindings))
	writes = append(writes, []byte(challengeID))
	if pos != 0 {
		prev := r.challenges[pos-1]
		if !prev.isComputed {
			return nil, fmt.Errorf("recursion: transcript previous challenge %q not computed", prev.name)
		}
		writes = append(writes, prev.value)
	}
	writes = append(writes, challenge.bindings...)
	value := poseidon2DigestWritesNative(writes)
	challenge.value = value
	challenge.isComputed = true
	return value, nil
}

func recorderBindDeepEvaluationClaims(recorder *poseidon2TranscriptRecorder, prf proof.Proof, layout prover.DEEPquotientLayout) error {
	for i := range layout.Sizes {
		for _, keysAtShift := range layout.Keys[i] {
			for _, key := range keysAtShift {
				if err := recorderBindValueAtZeta(recorder, prf, key); err != nil {
					return err
				}
			}
		}
		for _, chunkName := range layout.AIRChunks[i] {
			if err := recorderBindValueAtZeta(recorder, prf, chunkName); err != nil {
				return err
			}
		}
	}
	return nil
}

func recorderBindValueAtZeta(recorder *poseidon2TranscriptRecorder, prf proof.Proof, key string) error {
	v, ok := prf.ValueAtZetaExt(key)
	if !ok {
		return fmt.Errorf("recursion: transcript ValuesAtZeta %q not found", key)
	}
	return recorder.Bind(constants.DEEP_ALPHA, poseidon2SerializeE4(v))
}

func recorderRegisterFRIChallenges(recorder *poseidon2TranscriptRecorder, numRounds int, levelAtRound map[int]int) error {
	if err := recorder.NewChallenge(friFoldName(0)); err != nil {
		return err
	}
	for round := 1; round < numRounds; round++ {
		if level, ok := levelAtRound[round]; ok {
			if err := recorder.NewChallenge(friLevelGammaName(level)); err != nil {
				return err
			}
		}
		if err := recorder.NewChallenge(friFoldName(round)); err != nil {
			return err
		}
	}
	for query := 0; query < constants.NUM_QUERIES; query++ {
		if err := recorder.NewChallenge(friQueryName(query)); err != nil {
			return err
		}
	}
	return nil
}

func poseidon2FRILevelAtRound(maxN int, levelDs []int) (map[int]int, error) {
	if len(levelDs) == 0 {
		return nil, fmt.Errorf("recursion: transcript FRI has no DEEP quotient levels")
	}
	if levelDs[0] != maxN {
		return nil, fmt.Errorf("recursion: transcript FRI first level D=%d, want max module size %d", levelDs[0], maxN)
	}
	numRounds, err := log2Exact(maxN)
	if err != nil {
		return nil, err
	}
	levelAtRound := make(map[int]int, len(levelDs)-1)
	for level := 1; level < len(levelDs); level++ {
		levelD := levelDs[level]
		if levelD <= 0 || levelD&(levelD-1) != 0 {
			return nil, fmt.Errorf("recursion: transcript FRI level %d D=%d is not a positive power of two", level, levelD)
		}
		ratio := maxN / levelD
		if ratio <= 0 || ratio*levelD != maxN || ratio&(ratio-1) != 0 {
			return nil, fmt.Errorf("recursion: transcript FRI level %d D=%d does not divide max D=%d by a power-of-two ratio", level, levelD, maxN)
		}
		round, err := log2Exact(ratio)
		if err != nil {
			return nil, err
		}
		if round < 1 || round >= numRounds {
			return nil, fmt.Errorf("recursion: transcript FRI level %d introduction round %d outside 1..%d", level, round, numRounds-1)
		}
		if _, ok := levelAtRound[round]; ok {
			return nil, fmt.Errorf("recursion: transcript FRI duplicate level introduction round %d", round)
		}
		levelAtRound[round] = level
	}
	return levelAtRound, nil
}

func collectPoseidon2PointSamplingMerkleOps(namespace string, input RecursionInput) ([]poseidon2Op, error) {
	layout := prover.BuildLayout(input.Program, len(input.Setup))
	if len(input.Proof.PointSamplings) != constants.NUM_QUERIES {
		return nil, fmt.Errorf("recursion: point-sampling Merkle has %d queries, want %d", len(input.Proof.PointSamplings), constants.NUM_QUERIES)
	}

	roots := make([][]byte, layout.NumTrees)
	for i, root := range input.Setup {
		roots[layout.SetupBegin+i] = root
	}
	for i, root := range input.Proof.Commitments {
		roots[layout.SetupEnd+i] = root
	}

	ops := make([]poseidon2Op, 0)
	for q, samplings := range input.Proof.PointSamplings {
		if len(samplings) != layout.NumTrees {
			return nil, fmt.Errorf("recursion: point-sampling query %d has %d trees, want %d", q, len(samplings), layout.NumTrees)
		}
		for treeIdx, wp := range samplings {
			root, err := poseidon2DigestBytesToElements(roots[treeIdx])
			if err != nil {
				return nil, fmt.Errorf("recursion: point-sampling query %d tree %d root: %w", q, treeIdx, err)
			}
			proofOps, err := collectPoseidon2MerkleProofOps(fmt.Sprintf("%s.ps.q%d.t%d", namespace, q, treeIdx), poseidon2RawLeafElements(wp), wp.Proof, root)
			if err != nil {
				return nil, err
			}
			ops = append(ops, proofOps...)
		}
	}
	return ops, nil
}

func collectPoseidon2FRIMerkleOps(namespace string, input RecursionInput) ([]poseidon2Op, error) {
	maxN, err := maxModuleSize(input.Program)
	if err != nil {
		return nil, err
	}
	if maxN <= 1 {
		return nil, nil
	}
	numRounds, err := log2Exact(maxN)
	if err != nil {
		return nil, err
	}

	dqLayout := prover.BuildDeepQuotientLayout(input.Program)
	levelDs := dqLayout.Sizes
	if len(levelDs) == 0 {
		return nil, fmt.Errorf("recursion: FRI Merkle has no DEEP quotient levels")
	}
	if levelDs[0] != maxN {
		return nil, fmt.Errorf("recursion: FRI Merkle first level D=%d, want max module size %d", levelDs[0], maxN)
	}
	if len(input.Proof.DeepQuotientCommitment) != len(levelDs) {
		return nil, fmt.Errorf("recursion: FRI Merkle has %d DEEP quotient commitments, want %d", len(input.Proof.DeepQuotientCommitment), len(levelDs))
	}

	friProof := input.Proof.DeepQuotientFriProof
	wantFRIRoots := numRounds - 1
	if numRounds <= 1 {
		wantFRIRoots = 0
	}
	if len(friProof.FRIRoots) != wantFRIRoots {
		return nil, fmt.Errorf("recursion: FRI Merkle has %d running roots, want %d", len(friProof.FRIRoots), wantFRIRoots)
	}
	if len(friProof.FRIQueries) != constants.NUM_QUERIES {
		return nil, fmt.Errorf("recursion: FRI Merkle has %d queries, want %d", len(friProof.FRIQueries), constants.NUM_QUERIES)
	}
	if len(friProof.LevelQueries) != len(levelDs)-1 {
		return nil, fmt.Errorf("recursion: FRI Merkle has %d level query sets, want %d", len(friProof.LevelQueries), len(levelDs)-1)
	}

	runningRoots := make([][]byte, numRounds)
	runningRoots[0] = input.Proof.DeepQuotientCommitment[0]
	for round := 1; round < numRounds; round++ {
		runningRoots[round] = friProof.FRIRoots[round-1]
	}

	ops := make([]poseidon2Op, 0)
	for q, query := range friProof.FRIQueries {
		if len(query.Layers) != numRounds {
			return nil, fmt.Errorf("recursion: FRI Merkle query %d has %d layers, want %d", q, len(query.Layers), numRounds)
		}
		for round, layer := range query.Layers {
			root, err := poseidon2DigestBytesToElements(runningRoots[round])
			if err != nil {
				return nil, fmt.Errorf("recursion: FRI Merkle query %d round %d root: %w", q, round, err)
			}
			leafElements, err := poseidon2QueryLayerElements(layer)
			if err != nil {
				return nil, fmt.Errorf("recursion: FRI Merkle query %d round %d leaf: %w", q, round, err)
			}
			proofOps, err := collectPoseidon2MerkleProofOps(fmt.Sprintf("%s.fri.q%d.r%d", namespace, q, round), leafElements, layer.Path, root)
			if err != nil {
				return nil, err
			}
			ops = append(ops, proofOps...)
		}

		for level := 1; level < len(levelDs); level++ {
			if len(friProof.LevelQueries[level-1]) != constants.NUM_QUERIES {
				return nil, fmt.Errorf("recursion: FRI Merkle level %d has %d queries, want %d", level, len(friProof.LevelQueries[level-1]), constants.NUM_QUERIES)
			}
			layer := friProof.LevelQueries[level-1][q]
			root, err := poseidon2DigestBytesToElements(input.Proof.DeepQuotientCommitment[level])
			if err != nil {
				return nil, fmt.Errorf("recursion: FRI Merkle query %d level %d root: %w", q, level, err)
			}
			leafElements, err := poseidon2QueryLayerElements(layer)
			if err != nil {
				return nil, fmt.Errorf("recursion: FRI Merkle query %d level %d leaf: %w", q, level, err)
			}
			proofOps, err := collectPoseidon2MerkleProofOps(fmt.Sprintf("%s.fri.q%d.l%d", namespace, q, level), leafElements, layer.Path, root)
			if err != nil {
				return nil, err
			}
			ops = append(ops, proofOps...)
		}
	}
	return ops, nil
}

func collectPoseidon2MerkleProofOps(label string, leafElements []koalabear.Element, path merkle.Proof, root []koalabear.Element) ([]poseidon2Op, error) {
	current, ops := poseidon2DigestElementOps(label+".leaf", 0, [][]koalabear.Element{leafElements})

	idx := path.LeafIdx
	for depth, siblingBytes := range path.Siblings {
		siblingVals, err := poseidon2DigestBytesToElements(siblingBytes)
		if err != nil {
			return nil, fmt.Errorf("recursion: %s sibling %d: %w", label, depth, err)
		}
		left, right := current, siblingVals
		if idx&1 == 1 {
			left, right = siblingVals, current
		}
		var nodeOps []poseidon2Op
		current, nodeOps = poseidon2NodeDigestOps(fmt.Sprintf("%s.node.%d", label, depth), left, right)
		ops = append(ops, nodeOps...)
		idx >>= 1
	}

	if len(root) != poseidon2HalfWidth {
		return nil, fmt.Errorf("recursion: %s root has %d elements, want %d", label, len(root), poseidon2HalfWidth)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("recursion: %s produced no Poseidon2 operations", label)
	}
	ops[len(ops)-1].WantOutput = cloneBaseElements(root)
	return ops, nil
}

func poseidon2QueryLayerElements(layer fri.QueryLayer) ([]koalabear.Element, error) {
	switch layer.Field {
	case field.Base:
		return []koalabear.Element{layer.LeafPBase, layer.LeafQBase}, nil
	case field.Ext:
		return []koalabear.Element{
			layer.LeafPExt.B0.A0, layer.LeafPExt.B0.A1, layer.LeafPExt.B1.A0, layer.LeafPExt.B1.A1,
			layer.LeafQExt.B0.A0, layer.LeafQExt.B0.A1, layer.LeafQExt.B1.A0, layer.LeafQExt.B1.A1,
		}, nil
	default:
		return nil, fmt.Errorf("field is %s, want base or ext", layer.Field)
	}
}

func poseidon2NodeDigestOps(label string, left, right []koalabear.Element) ([]koalabear.Element, []poseidon2Op) {
	lenBlock := poseidon2LengthBlock(poseidon2HalfWidth * koalabear.Bytes)
	return poseidon2DigestBlockOps(label, 1, [][]koalabear.Element{lenBlock, left, lenBlock, right})
}

func poseidon2DigestElementOps(label string, tag byte, parts [][]koalabear.Element) ([]koalabear.Element, []poseidon2Op) {
	blocks := make([][]koalabear.Element, 0, 1+2*len(parts))
	for _, part := range parts {
		blocks = append(blocks, poseidon2LengthBlock(len(part)*koalabear.Bytes))
		blocks = append(blocks, poseidon2ElementBlocks(part)...)
	}
	return poseidon2DigestBlockOps(label, tag, blocks)
}

func poseidon2DigestBlockOps(label string, tag byte, blocks [][]koalabear.Element) ([]koalabear.Element, []poseidon2Op) {
	tagBlock := make([]koalabear.Element, poseidon2HalfWidth)
	tagBlock[poseidon2HalfWidth-1].SetUint64(uint64(tag))

	state := make([]koalabear.Element, poseidon2HalfWidth)
	allBlocks := append([][]koalabear.Element{tagBlock}, blocks...)
	ops := make([]poseidon2Op, 0, len(allBlocks))
	for i, block := range allBlocks {
		output := poseidon2CompressValues(state, block)
		input := make([]koalabear.Element, poseidon2Width)
		copy(input[:poseidon2HalfWidth], state)
		copy(input[poseidon2HalfWidth:], block)
		ops = append(ops, poseidon2Op{
			Label:      fmt.Sprintf("%s.block.%d", label, i),
			Input:      input,
			WantOutput: cloneBaseElements(output),
		})
		state = output
	}
	return state, ops
}

func poseidon2DigestWriteOps(label string, writes [][]byte) ([]koalabear.Element, []poseidon2Op, error) {
	state := make([]koalabear.Element, poseidon2HalfWidth)
	ops := make([]poseidon2Op, 0)
	for writeIdx, write := range writes {
		blocks, err := poseidon2ByteBlocks(write)
		if err != nil {
			return nil, nil, fmt.Errorf("recursion: Poseidon2 transcript write %s.%d: %w", label, writeIdx, err)
		}
		for blockIdx, block := range blocks {
			output := poseidon2CompressValues(state, block)
			input := make([]koalabear.Element, poseidon2Width)
			copy(input[:poseidon2HalfWidth], state)
			copy(input[poseidon2HalfWidth:], block)
			ops = append(ops, poseidon2Op{
				Label:      fmt.Sprintf("%s.write.%d.block.%d", label, writeIdx, blockIdx),
				Input:      input,
				WantOutput: cloneBaseElements(output),
			})
			state = output
		}
	}
	return state, ops, nil
}

func poseidon2DigestWritesNative(writes [][]byte) []byte {
	h := commitment.NewPoseidon2TranscriptHash()
	for _, write := range writes {
		_, _ = h.Write(write)
	}
	return h.Sum(nil)
}

func poseidon2CompressValues(state, block []koalabear.Element) []koalabear.Element {
	input := make([]koalabear.Element, poseidon2Width)
	copy(input[:poseidon2HalfWidth], state)
	copy(input[poseidon2HalfWidth:], block)
	perm := poseidon2PermutationValues(input)
	output := make([]koalabear.Element, poseidon2HalfWidth)
	for i := range output {
		output[i].Add(&perm[poseidon2HalfWidth+i], &block[i])
	}
	return output
}

func poseidon2PermutationValues(input []koalabear.Element) []koalabear.Element {
	params := p2crypto.GetDefaultParameters()
	state := poseidon2MatMulExternalValues(input)
	totalRounds := params.NbFullRounds + params.NbPartialRounds
	for round := 0; round < totalRounds; round++ {
		state = poseidon2RoundValues(state, params.RoundKeys[round], poseidon2IsPartialRound(params, round))
	}
	return state
}

func poseidon2IsPartialRound(params *p2crypto.Parameters, round int) bool {
	rf := params.NbFullRounds / 2
	return round >= rf && round < rf+params.NbPartialRounds
}

func (pb *poseidon2ModuleBuilder) lagrange(row int) expr.Expr {
	if lagrange, ok := pb.lagranges[row]; ok {
		return lagrange
	}
	lagrange := pb.module.LagrangeCol(row)
	pb.lagranges[row] = lagrange
	return lagrange
}

func (pb *poseidon2ModuleBuilder) assertZeroAt(relation expr.Expr, row int) {
	pb.module.AssertZero(relation.Mul(pb.lagrange(row)))
}

func mergeTrace(dst trace.Trace, src trace.Trace) error {
	for name, col := range src.Base {
		if _, ok := dst.Base[name]; ok {
			return fmt.Errorf("recursion: duplicate base trace column %q", name)
		}
		dst.SetBase(name, col)
	}
	for name, col := range src.Ext {
		if _, ok := dst.Ext[name]; ok {
			return fmt.Errorf("recursion: duplicate extension trace column %q", name)
		}
		dst.SetExt(name, col)
	}
	return nil
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func poseidon2RawLeafElements(wp commitment.WMerkleProof) []koalabear.Element {
	total := 2*len(wp.RawLeafBase) + 8*len(wp.RawLeafExt)
	res := make([]koalabear.Element, 0, total)
	for _, pair := range wp.RawLeafBase {
		res = append(res, pair[0], pair[1])
	}
	for _, pair := range wp.RawLeafExt {
		res = append(res,
			pair[0].B0.A0, pair[0].B0.A1, pair[0].B1.A0, pair[0].B1.A1,
			pair[1].B0.A0, pair[1].B0.A1, pair[1].B1.A0, pair[1].B1.A1,
		)
	}
	return res
}

func poseidon2DigestBytesToElements(b []byte) ([]koalabear.Element, error) {
	if len(b) != poseidon2HalfWidth*koalabear.Bytes {
		return nil, fmt.Errorf("digest has %d bytes, want %d", len(b), poseidon2HalfWidth*koalabear.Bytes)
	}
	res := make([]koalabear.Element, poseidon2HalfWidth)
	for i := range res {
		if err := res[i].SetBytesCanonical(b[i*koalabear.Bytes : (i+1)*koalabear.Bytes]); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func poseidon2ByteBlocks(data []byte) ([][]koalabear.Element, error) {
	if len(data) == 0 {
		return nil, nil
	}
	numBlocks := (len(data) + poseidon2HalfWidth*koalabear.Bytes - 1) / (poseidon2HalfWidth * koalabear.Bytes)
	blocks := make([][]koalabear.Element, 0, numBlocks)
	for len(data) > 0 {
		take := len(data)
		if take > poseidon2HalfWidth*koalabear.Bytes {
			take = poseidon2HalfWidth * koalabear.Bytes
		}
		blockBytes := make([]byte, poseidon2HalfWidth*koalabear.Bytes)
		copy(blockBytes[len(blockBytes)-take:], data[:take])
		block := make([]koalabear.Element, poseidon2HalfWidth)
		for i := range block {
			if err := block[i].SetBytesCanonical(blockBytes[i*koalabear.Bytes : (i+1)*koalabear.Bytes]); err != nil {
				return nil, err
			}
		}
		blocks = append(blocks, block)
		data = data[take:]
	}
	return blocks, nil
}

func poseidon2ElementBlocks(elements []koalabear.Element) [][]koalabear.Element {
	if len(elements) == 0 {
		return nil
	}
	numBlocks := (len(elements) + poseidon2HalfWidth - 1) / poseidon2HalfWidth
	blocks := make([][]koalabear.Element, 0, numBlocks)
	for len(elements) > 0 {
		block := make([]koalabear.Element, poseidon2HalfWidth)
		take := len(elements)
		if take > poseidon2HalfWidth {
			take = poseidon2HalfWidth
		}
		copy(block[poseidon2HalfWidth-take:], elements[:take])
		blocks = append(blocks, block)
		elements = elements[take:]
	}
	return blocks
}

func poseidon2LengthBlock(length int) []koalabear.Element {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(length))
	block := make([]koalabear.Element, poseidon2HalfWidth)
	block[poseidon2HalfWidth-2].SetBytes(lenBuf[:4])
	block[poseidon2HalfWidth-1].SetBytes(lenBuf[4:])
	return block
}

func poseidon2SerializeE4(v ext.E4) []byte {
	res := make([]byte, 0, 4*koalabear.Bytes)
	res = append(res, v.B0.A0.Marshal()...)
	res = append(res, v.B0.A1.Marshal()...)
	res = append(res, v.B1.A0.Marshal()...)
	res = append(res, v.B1.A1.Marshal()...)
	return res
}

func poseidon2RoundValues(input []koalabear.Element, roundKey []koalabear.Element, partial bool) []koalabear.Element {
	state := cloneBaseElements(input)
	for i := range roundKey {
		state[i].Add(&state[i], &roundKey[i])
	}
	if partial {
		state[0] = poseidon2SBoxValue(state[0])
		return poseidon2MatMulInternalValues(state)
	}
	for i := range state {
		state[i] = poseidon2SBoxValue(state[i])
	}
	return poseidon2MatMulExternalValues(state)
}

func poseidon2RoundExprs(input []expr.Expr, roundKey []koalabear.Element, partial bool) []expr.Expr {
	state := cloneExprs(input)
	for i := range roundKey {
		state[i] = state[i].Add(expr.Const(roundKey[i]))
	}
	if partial {
		state[0] = poseidon2SBoxExpr(state[0])
		return poseidon2MatMulInternalExprs(state)
	}
	for i := range state {
		state[i] = poseidon2SBoxExpr(state[i])
	}
	return poseidon2MatMulExternalExprs(state)
}

func poseidon2SBoxValue(value koalabear.Element) koalabear.Element {
	var square, cube koalabear.Element
	square.Square(&value)
	cube.Mul(&square, &value)
	return cube
}

func poseidon2SBoxExpr(value expr.Expr) expr.Expr {
	return value.Mul(value).Mul(value)
}

func poseidon2MatMulExternalValues(input []koalabear.Element) []koalabear.Element {
	state := poseidon2MatMulM4Values(input)
	tmp := make([]koalabear.Element, 4)
	for i := 0; i < poseidon2Width/4; i++ {
		for j := 0; j < 4; j++ {
			tmp[j].Add(&tmp[j], &state[4*i+j])
		}
	}
	for i := 0; i < poseidon2Width/4; i++ {
		for j := 0; j < 4; j++ {
			state[4*i+j].Add(&state[4*i+j], &tmp[j])
		}
	}
	return state
}

func poseidon2MatMulExternalExprs(input []expr.Expr) []expr.Expr {
	state := poseidon2MatMulM4Exprs(input)
	tmp := make([]expr.Expr, 4)
	for i := range tmp {
		tmp[i] = zeroExpr()
	}
	for i := 0; i < poseidon2Width/4; i++ {
		for j := 0; j < 4; j++ {
			tmp[j] = tmp[j].Add(state[4*i+j])
		}
	}
	for i := 0; i < poseidon2Width/4; i++ {
		for j := 0; j < 4; j++ {
			state[4*i+j] = state[4*i+j].Add(tmp[j])
		}
	}
	return state
}

func poseidon2MatMulM4Values(input []koalabear.Element) []koalabear.Element {
	res := cloneBaseElements(input)
	for i := 0; i < poseidon2Width/4; i++ {
		x0, x1, x2, x3 := res[4*i], res[4*i+1], res[4*i+2], res[4*i+3]
		var t01, t23, t0123, t01123, t01233 koalabear.Element
		t01.Add(&x0, &x1)
		t23.Add(&x2, &x3)
		t0123.Add(&t01, &t23)
		t01123.Add(&t0123, &x1)
		t01233.Add(&t0123, &x3)
		res[4*i+3].Double(&x0).Add(&res[4*i+3], &t01233)
		res[4*i+1].Double(&x2).Add(&res[4*i+1], &t01123)
		res[4*i].Add(&t01, &t01123)
		res[4*i+2].Add(&t23, &t01233)
	}
	return res
}

func poseidon2MatMulM4Exprs(input []expr.Expr) []expr.Expr {
	res := cloneExprs(input)
	for i := 0; i < poseidon2Width/4; i++ {
		x0, x1, x2, x3 := res[4*i], res[4*i+1], res[4*i+2], res[4*i+3]
		t01 := x0.Add(x1)
		t23 := x2.Add(x3)
		t0123 := t01.Add(t23)
		t01123 := t0123.Add(x1)
		t01233 := t0123.Add(x3)
		res[4*i+3] = x0.Add(x0).Add(t01233)
		res[4*i+1] = x2.Add(x2).Add(t01123)
		res[4*i] = t01.Add(t01123)
		res[4*i+2] = t23.Add(t01233)
	}
	return res
}

func poseidon2MatMulInternalValues(input []koalabear.Element) []koalabear.Element {
	diag := poseidon2InternalDiag16()
	var sum koalabear.Element
	for i := range input {
		sum.Add(&sum, &input[i])
	}
	res := make([]koalabear.Element, poseidon2Width)
	for i := range res {
		var term koalabear.Element
		term.Mul(&input[i], &diag[i])
		res[i].Add(&sum, &term)
	}
	return res
}

func poseidon2MatMulInternalExprs(input []expr.Expr) []expr.Expr {
	diag := poseidon2InternalDiag16()
	sum := zeroExpr()
	for i := range input {
		sum = sum.Add(input[i])
	}
	res := make([]expr.Expr, poseidon2Width)
	for i := range res {
		res[i] = sum.Add(input[i].Mul(expr.Const(diag[i])))
	}
	return res
}

func poseidon2InternalDiag16() []koalabear.Element {
	vals := []uint64{
		2130706431, 1, 2, 1065353217,
		3, 4, 1065353216, 2130706430,
		2130706429, 2122383361, 1864368129, 2130706306,
		8323072, 266338304, 133169152, 127,
	}
	res := make([]koalabear.Element, len(vals))
	for i, v := range vals {
		res[i].SetUint64(v)
	}
	return res
}

func cloneBaseElements(input []koalabear.Element) []koalabear.Element {
	res := make([]koalabear.Element, len(input))
	copy(res, input)
	return res
}

func cloneExprs(input []expr.Expr) []expr.Expr {
	res := make([]expr.Expr, len(input))
	copy(res, input)
	return res
}
