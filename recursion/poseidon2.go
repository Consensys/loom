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

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	p2crypto "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/trace"
)

const (
	poseidon2DigestWidth   = 8
	poseidon2MDWidth       = 16
	poseidon2SpongeWidth   = 24
	poseidon2MDHalfWidth   = poseidon2MDWidth / 2
	poseidon2SpongeRate    = 16
	poseidon2FullRounds    = 6
	poseidon2PartialRounds = 21
	poseidon2LeafDomainTag = 0x4c454146 // "LEAF"
	poseidon2NodeDomainTag = 0x4e4f4445 // "NODE"
	poseidon2FSIDDomainTag = 0x46534944 // "FSID"
)

type poseidon2OutputMode uint8

const (
	poseidon2OutputMD poseidon2OutputMode = iota
	poseidon2OutputSponge
)

type poseidon2MerkleTarget struct {
	Namespace string
	Input     RecursionInput
}

type poseidon2Op struct {
	Label      string
	Width      int
	OutputMode poseidon2OutputMode
	Input      []koalabear.Element
	WantOutput []koalabear.Element
}

type poseidon2TranscriptChallenge struct {
	name       string
	bindings   [][]koalabear.Element
	value      hash.Digest
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

var (
	poseidon2Params16 = p2crypto.NewParameters(poseidon2MDWidth, poseidon2FullRounds, poseidon2PartialRounds)
	poseidon2Params24 = p2crypto.NewParameters(poseidon2SpongeWidth, poseidon2FullRounds, poseidon2PartialRounds)
)

func poseidon2Params(width int) (*p2crypto.Parameters, error) {
	switch width {
	case poseidon2MDWidth:
		return poseidon2Params16, nil
	case poseidon2SpongeWidth:
		return poseidon2Params24, nil
	default:
		return nil, fmt.Errorf("recursion: unsupported Poseidon2 width %d", width)
	}
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

	params, err := poseidon2Params(poseidon2MDWidth)
	if err != nil {
		return board.Module{}, trace.Trace{}, err
	}
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
	stateNames := make([]string, poseidon2SpongeWidth)
	stateCols := make([][]koalabear.Element, poseidon2SpongeWidth)
	for i := range stateNames {
		stateNames[i] = fmt.Sprintf("%s.state.%d", moduleName, i)
		stateCols[i] = make([]koalabear.Element, n)
	}

	for opIdx, op := range ops {
		if op.Width != poseidon2MDWidth && op.Width != poseidon2SpongeWidth {
			return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: Poseidon2 op %s has unsupported width %d", op.Label, op.Width)
		}
		if len(op.Input) != op.Width {
			return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: Poseidon2 op %s has input width %d, want %d", op.Label, len(op.Input), op.Width)
		}
		if len(op.WantOutput) != poseidon2DigestWidth {
			return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: Poseidon2 op %s has output width %d, want %d", op.Label, len(op.WantOutput), poseidon2DigestWidth)
		}

		params, err := poseidon2Params(op.Width)
		if err != nil {
			return board.Module{}, trace.Trace{}, err
		}
		startRow := opIdx * rowsPerOp
		state := poseidon2MatMulExternalValues(op.Input)
		for i := 0; i < poseidon2SpongeWidth; i++ {
			if i < op.Width {
				stateCols[i][startRow].Set(&state[i])
				builder.assertZeroAt(expr.Col(stateNames[i]).Sub(expr.Const(state[i])), startRow)
				continue
			}
			builder.assertZeroAt(expr.Col(stateNames[i]), startRow)
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
		for i := 0; i < poseidon2DigestWidth; i++ {
			var relation expr.Expr
			switch op.OutputMode {
			case poseidon2OutputMD:
				relation = expr.Col(stateNames[poseidon2MDHalfWidth+i]).
					Add(expr.Const(op.Input[poseidon2MDHalfWidth+i])).
					Sub(expr.Const(op.WantOutput[i]))
			case poseidon2OutputSponge:
				relation = expr.Col(stateNames[i]).Sub(expr.Const(op.WantOutput[i]))
			default:
				return board.Module{}, trace.Trace{}, fmt.Errorf("recursion: Poseidon2 op %s has unsupported output mode %d", op.Label, op.OutputMode)
			}
			builder.assertZeroAt(relation, finalRow)
		}
	}

	for i := range stateNames {
		tr.SetBase(stateNames[i], stateCols[i])
	}

	stateExprs := make([]expr.Expr, poseidon2SpongeWidth)
	for i := range stateExprs {
		stateExprs[i] = expr.Col(stateNames[i])
	}
	for round := 0; round < numRounds; round++ {
		transitionSelector := zeroExpr()
		roundSelectors := map[int]expr.Expr{
			poseidon2MDWidth:     zeroExpr(),
			poseidon2SpongeWidth: zeroExpr(),
		}
		for opIdx, op := range ops {
			selector := builder.lagrange(opIdx*rowsPerOp + round)
			transitionSelector = transitionSelector.Add(selector)
			roundSelectors[op.Width] = roundSelectors[op.Width].Add(selector)
		}

		expectedNext := make([]expr.Expr, poseidon2SpongeWidth)
		for i := range expectedNext {
			expectedNext[i] = zeroExpr()
		}
		for _, width := range []int{poseidon2MDWidth, poseidon2SpongeWidth} {
			selector := roundSelectors[width]
			params, err := poseidon2Params(width)
			if err != nil {
				return board.Module{}, trace.Trace{}, err
			}
			next := poseidon2RoundExprs(stateExprs[:width], params.RoundKeys[round], poseidon2IsPartialRound(params, round))
			for i := range next {
				expectedNext[i] = expectedNext[i].Add(selector.Mul(next[i]))
			}
		}
		for i := range stateNames {
			nextState := expr.Rot(stateNames[i], 1).Mul(transitionSelector)
			builder.module.AssertZero(nextState.Sub(expectedNext[i]))
		}
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
		writes := make([][]koalabear.Element, 0, 2+len(challenge.bindings))
		writes = append(writes, hash.StringToElements(poseidon2FSIDDomainTag, challenge.name))
		if pos != 0 {
			writes = append(writes, recorder.challenges[pos-1].value[:])
		}
		writes = append(writes, challenge.bindings...)

		expected := cloneBaseElements(challenge.value[:])
		_, challengeOps := poseidon2SpongeWriteOps(fmt.Sprintf("%s.transcript.%d.%s", namespace, pos, challenge.name), writes)
		if len(challengeOps) == 0 {
			return nil, fmt.Errorf("recursion: transcript challenge %q produced no Poseidon2 operations", challenge.name)
		}
		challengeOps[len(challengeOps)-1].WantOutput = expected
		ops = append(ops, challengeOps...)
	}
	return ops, nil
}

func recordPoseidon2Transcript(input RecursionInput) (*poseidon2TranscriptRecorder, error) {
	hashBackend, err := resolveRecursionHashBackend(input, Config{hashBackend: commitment.Poseidon2HashBackend()})
	if err != nil {
		return nil, err
	}
	if hashBackend.ID != commitment.HashBackendPoseidon2 {
		return nil, fmt.Errorf("recursion: Poseidon2 arithmetization requires poseidon2 hash backend, got %q", hashBackend.ID)
	}

	layout := prover.BuildLayout(input.Program, len(input.Setup.Roots))
	wantCommitments := layout.NumTrees - layout.SetupEnd
	if len(input.Proof.Commitments) != wantCommitments {
		return nil, fmt.Errorf("recursion: transcript proof has %d commitments, layout expects %d", len(input.Proof.Commitments), wantCommitments)
	}
	if len(input.Setup.Roots) != layout.SetupEnd-layout.SetupBegin {
		return nil, fmt.Errorf("recursion: transcript setup has %d trees, layout expects %d", len(input.Setup.Roots), layout.SetupEnd-layout.SetupBegin)
	}

	roots := make([]hash.Digest, layout.NumTrees)
	for i, root := range input.Setup.Roots {
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

	initialChallenge := constants.InitialChallengeName(numRounds)
	if err := recorder.Bind(initialChallenge, hash.StringToElements(constants.HASH_BACKEND_DOMAIN_TAG, hashBackend.ID)); err != nil {
		return nil, err
	}
	for _, root := range input.Setup.Roots {
		if err := recorder.Bind(initialChallenge, root[:]); err != nil {
			return nil, err
		}
	}
	if len(input.PublicInputs) > 0 {
		if err := recorder.Bind(initialChallenge, input.PublicInputs.TranscriptElements()); err != nil {
			return nil, err
		}
	}

	for round := 0; round < numRounds; round++ {
		challengeName := constants.CanonicalChallengeName(round)
		for i := layout.TraceBegin[round]; i < layout.TraceEnd[round]; i++ {
			if err := recorder.Bind(challengeName, roots[i][:]); err != nil {
				return nil, err
			}
		}
		if _, err := recorder.ComputeChallenge(challengeName); err != nil {
			return nil, err
		}
	}

	for i := layout.AIRBegin; i < layout.AIREnd; i++ {
		if err := recorder.Bind(constants.FINAL_EVALUATION_POINT, roots[i][:]); err != nil {
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
	runningRoots := make([]hash.Digest, numFRIRounds)
	runningRoots[0] = input.Proof.DeepQuotientCommitment[0]
	for round := 1; round < numFRIRounds; round++ {
		runningRoots[round] = input.Proof.DeepQuotientFriProof.FRIRoots[round-1]
	}

	for round := 0; round < numFRIRounds; round++ {
		if round > 0 {
			if level, ok := levelAtRound[round]; ok {
				gammaName := friLevelGammaName(level)
				if err := recorder.Bind(gammaName, input.Proof.DeepQuotientCommitment[level][:]); err != nil {
					return nil, err
				}
				if _, err := recorder.ComputeChallenge(gammaName); err != nil {
					return nil, err
				}
			}
		}
		foldName := friFoldName(round)
		if err := recorder.Bind(foldName, runningRoots[round][:]); err != nil {
			return nil, err
		}
		if _, err := recorder.ComputeChallenge(foldName); err != nil {
			return nil, err
		}
	}

	if input.Proof.DeepQuotientFriProof.FinalField != field.Ext {
		return nil, fmt.Errorf("recursion: transcript FRI final field is %s, want %s", input.Proof.DeepQuotientFriProof.FinalField, field.Ext)
	}
	if err := recorder.Bind(friQueryName(0), friTranscriptExtPoly(input.Proof.DeepQuotientFriProof.FinalPolyExt)); err != nil {
		return nil, err
	}
	for query := 0; query < constants.NUM_QUERIES; query++ {
		challenge, err := recorder.ComputeChallenge(friQueryName(query))
		if err != nil {
			return nil, err
		}
		if query < constants.NUM_QUERIES-1 {
			if err := recorder.Bind(friQueryName(query+1), challenge[:]); err != nil {
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

func (r *poseidon2TranscriptRecorder) Bind(challengeID string, bValue []koalabear.Element) error {
	pos, ok := r.nameToChallengePos[challengeID]
	if !ok {
		return fmt.Errorf("recursion: transcript challenge %q not found", challengeID)
	}
	if r.challenges[pos].isComputed {
		return fmt.Errorf("recursion: transcript challenge %q already computed", challengeID)
	}
	bCopy := cloneBaseElements(bValue)
	r.challenges[pos].bindings = append(r.challenges[pos].bindings, bCopy)
	return nil
}

func (r *poseidon2TranscriptRecorder) ComputeChallenge(challengeID string) (hash.Digest, error) {
	pos, ok := r.nameToChallengePos[challengeID]
	if !ok {
		return hash.Digest{}, fmt.Errorf("recursion: transcript challenge %q not found", challengeID)
	}
	challenge := &r.challenges[pos]
	if challenge.isComputed {
		return challenge.value, nil
	}
	writes := make([][]koalabear.Element, 0, 2+len(challenge.bindings))
	writes = append(writes, hash.StringToElements(poseidon2FSIDDomainTag, challengeID))
	if pos != 0 {
		prev := r.challenges[pos-1]
		if !prev.isComputed {
			return hash.Digest{}, fmt.Errorf("recursion: transcript previous challenge %q not computed", prev.name)
		}
		writes = append(writes, prev.value[:])
	}
	writes = append(writes, challenge.bindings...)
	value := poseidon2SpongeDigestNative(writes)
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
	return recorder.Bind(constants.DEEP_ALPHA, poseidon2E4Elements(v))
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
	layout := prover.BuildLayout(input.Program, len(input.Setup.Roots))
	if len(input.Proof.PointSamplings) != constants.NUM_QUERIES {
		return nil, fmt.Errorf("recursion: point-sampling Merkle has %d queries, want %d", len(input.Proof.PointSamplings), constants.NUM_QUERIES)
	}

	roots := make([]hash.Digest, layout.NumTrees)
	for i, root := range input.Setup.Roots {
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
			root := cloneBaseElements(roots[treeIdx][:])
			proofOps, err := collectPoseidon2MerkleProofOps(fmt.Sprintf("%s.ps.q%d.t%d", namespace, q, treeIdx), wp, wp.Proof, root)
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

	runningRoots := make([]hash.Digest, numRounds)
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
			root := cloneBaseElements(runningRoots[round][:])
			proofOps, err := collectPoseidon2MerkleProofOps(fmt.Sprintf("%s.fri.q%d.r%d", namespace, q, round), layer, layer.Path, root)
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
			root := cloneBaseElements(input.Proof.DeepQuotientCommitment[level][:])
			proofOps, err := collectPoseidon2MerkleProofOps(fmt.Sprintf("%s.fri.q%d.l%d", namespace, q, level), layer, layer.Path, root)
			if err != nil {
				return nil, err
			}
			ops = append(ops, proofOps...)
		}
	}
	return ops, nil
}

func collectPoseidon2MerkleProofOps(label string, leaf any, path merkle.Proof, root []koalabear.Element) ([]poseidon2Op, error) {
	current, ops, err := poseidon2MerkleLeafDigestOps(label+".leaf", leaf)
	if err != nil {
		return nil, err
	}

	idx := path.LeafIdx
	for depth, sibling := range path.Siblings {
		siblingVals := cloneBaseElements(sibling[:])
		left, right := current, siblingVals
		if idx&1 == 1 {
			left, right = siblingVals, current
		}
		var nodeOps []poseidon2Op
		current, nodeOps = poseidon2NodeDigestOps(fmt.Sprintf("%s.node.%d", label, depth), left, right)
		ops = append(ops, nodeOps...)
		idx >>= 1
	}

	if len(root) != poseidon2DigestWidth {
		return nil, fmt.Errorf("recursion: %s root has %d elements, want %d", label, len(root), poseidon2DigestWidth)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("recursion: %s produced no Poseidon2 operations", label)
	}
	ops[len(ops)-1].WantOutput = cloneBaseElements(root)
	return ops, nil
}

func poseidon2MerkleLeafDigestOps(label string, leaf any) ([]koalabear.Element, []poseidon2Op, error) {
	switch v := leaf.(type) {
	case commitment.WMerkleProof:
		return poseidon2CommitmentLeafDigestOps(label, v.RawLeafBase, v.RawLeafExt)
	case fri.QueryLayer:
		switch v.Field {
		case field.Base:
			return poseidon2CommitmentLeafDigestOps(label, []commitment.PairBase{{v.LeafPBase, v.LeafQBase}}, nil)
		case field.Ext:
			return poseidon2CommitmentLeafDigestOps(label, nil, []commitment.PairExt{{v.LeafPExt, v.LeafQExt}})
		default:
			return nil, nil, fmt.Errorf("field is %s, want base or ext", v.Field)
		}
	default:
		return nil, nil, fmt.Errorf("recursion: unsupported Poseidon2 Merkle leaf type %T", leaf)
	}
}

func poseidon2CommitmentLeafDigestOps(label string, base []commitment.PairBase, ext []commitment.PairExt) ([]koalabear.Element, []poseidon2Op, error) {
	leafElements := poseidon2LeafHashElements(base, ext)
	digest, ops := poseidon2SpongeWriteOps(label, [][]koalabear.Element{leafElements})
	return digest, ops, nil
}

func poseidon2LeafHashElements(base []commitment.PairBase, extPairs []commitment.PairExt) []koalabear.Element {
	total := 3 + 2*len(base) + 8*len(extPairs)
	res := make([]koalabear.Element, 0, total)
	res = append(res,
		hash.NewElement(poseidon2LeafDomainTag),
		hash.NewElement(uint64(len(base))),
		hash.NewElement(uint64(len(extPairs))),
	)
	for _, pair := range base {
		res = append(res, pair[0], pair[1])
	}
	for _, pair := range extPairs {
		res = append(res, poseidon2E4Elements(pair[0])...)
		res = append(res, poseidon2E4Elements(pair[1])...)
	}
	return res
}

func poseidon2NodeDigestOps(label string, left, right []koalabear.Element) ([]koalabear.Element, []poseidon2Op) {
	inputs := make([]koalabear.Element, 0, 1+len(left)+len(right))
	inputs = append(inputs, hash.NewElement(poseidon2NodeDomainTag))
	inputs = append(inputs, left...)
	inputs = append(inputs, right...)
	return poseidon2MDDigestOps(label, inputs)
}

func poseidon2MDDigestOps(label string, inputs []koalabear.Element) ([]koalabear.Element, []poseidon2Op) {
	var state [poseidon2MDWidth]koalabear.Element
	ops := make([]poseidon2Op, 0, (len(inputs)+poseidon2MDWidth-1)/poseidon2MDWidth+1)
	pos := 0
	wrote := false
	compressed := false
	for _, input := range inputs {
		state[pos].Set(&input)
		pos++
		wrote = true
		if pos == poseidon2MDWidth {
			_, op := poseidon2MDCompressOp(fmt.Sprintf("%s.block.%d", label, len(ops)), &state)
			ops = append(ops, op)
			pos = poseidon2MDHalfWidth
			compressed = true
		}
	}
	if !wrote {
		return make([]koalabear.Element, poseidon2DigestWidth), ops
	}
	if !compressed || pos > poseidon2MDHalfWidth {
		for i := pos; i < poseidon2MDWidth; i++ {
			state[i].SetZero()
		}
		_, op := poseidon2MDCompressOp(fmt.Sprintf("%s.block.%d", label, len(ops)), &state)
		ops = append(ops, op)
	}
	return cloneBaseElements(state[:poseidon2DigestWidth]), ops
}

func poseidon2MDCompressOp(label string, state *[poseidon2MDWidth]koalabear.Element) ([]koalabear.Element, poseidon2Op) {
	input := cloneBaseElements(state[:])
	perm := poseidon2PermutationValues(input)
	output := make([]koalabear.Element, poseidon2DigestWidth)
	for i := range output {
		output[i].Add(&perm[poseidon2MDHalfWidth+i], &input[poseidon2MDHalfWidth+i])
	}
	for i := 0; i < poseidon2DigestWidth; i++ {
		state[i].Set(&output[i])
	}
	for i := poseidon2DigestWidth; i < poseidon2MDWidth; i++ {
		state[i].SetZero()
	}
	return output, poseidon2Op{
		Label:      label,
		Width:      poseidon2MDWidth,
		OutputMode: poseidon2OutputMD,
		Input:      input,
		WantOutput: cloneBaseElements(output),
	}
}

func poseidon2SpongeWriteOps(label string, writes [][]koalabear.Element) ([]koalabear.Element, []poseidon2Op) {
	var state [poseidon2SpongeWidth]koalabear.Element
	var block [poseidon2SpongeRate]koalabear.Element
	blockLen := 0
	wrote := false
	ops := make([]poseidon2Op, 0)
	for _, write := range writes {
		for _, input := range write {
			block[blockLen].Set(&input)
			blockLen++
			if blockLen == poseidon2SpongeRate {
				copy(state[:poseidon2SpongeRate], block[:])
				_, op := poseidon2SpongePermuteOp(fmt.Sprintf("%s.block.%d", label, len(ops)), &state)
				ops = append(ops, op)
				for i := range block {
					block[i].SetZero()
				}
				blockLen = 0
				wrote = true
			}
		}
	}
	if !wrote && blockLen == 0 {
		return make([]koalabear.Element, poseidon2DigestWidth), ops
	}
	if blockLen > 0 {
		for i := 0; i < blockLen; i++ {
			state[i].Set(&block[i])
		}
		_, op := poseidon2SpongePermuteOp(fmt.Sprintf("%s.block.%d", label, len(ops)), &state)
		ops = append(ops, op)
	}
	return cloneBaseElements(state[:poseidon2DigestWidth]), ops
}

func poseidon2SpongePermuteOp(label string, state *[poseidon2SpongeWidth]koalabear.Element) ([]koalabear.Element, poseidon2Op) {
	input := cloneBaseElements(state[:])
	perm := poseidon2PermutationValues(input)
	copy(state[:], perm)
	output := cloneBaseElements(state[:poseidon2DigestWidth])
	return output, poseidon2Op{
		Label:      label,
		Width:      poseidon2SpongeWidth,
		OutputMode: poseidon2OutputSponge,
		Input:      input,
		WantOutput: cloneBaseElements(output),
	}
}

func poseidon2SpongeDigestNative(writes [][]koalabear.Element) hash.Digest {
	h := hash.NewPoseidon2SpongeHasher()
	for _, write := range writes {
		h.WriteElements(write...)
	}
	return h.Sum()
}

func poseidon2E4Elements(v ext.E4) []koalabear.Element {
	return []koalabear.Element{v.B0.A0, v.B0.A1, v.B1.A0, v.B1.A1}
}

func poseidon2PermutationValues(input []koalabear.Element) []koalabear.Element {
	params, err := poseidon2Params(len(input))
	if err != nil {
		panic(err)
	}
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
	for i := 0; i < len(state)/4; i++ {
		for j := 0; j < 4; j++ {
			tmp[j].Add(&tmp[j], &state[4*i+j])
		}
	}
	for i := 0; i < len(state)/4; i++ {
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
	for i := 0; i < len(state)/4; i++ {
		for j := 0; j < 4; j++ {
			tmp[j] = tmp[j].Add(state[4*i+j])
		}
	}
	for i := 0; i < len(state)/4; i++ {
		for j := 0; j < 4; j++ {
			state[4*i+j] = state[4*i+j].Add(tmp[j])
		}
	}
	return state
}

func poseidon2MatMulM4Values(input []koalabear.Element) []koalabear.Element {
	res := cloneBaseElements(input)
	for i := 0; i < len(res)/4; i++ {
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
	for i := 0; i < len(res)/4; i++ {
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
	diag := poseidon2InternalDiag(len(input))
	var sum koalabear.Element
	for i := range input {
		sum.Add(&sum, &input[i])
	}
	res := make([]koalabear.Element, len(input))
	for i := range res {
		var term koalabear.Element
		term.Mul(&input[i], &diag[i])
		res[i].Add(&sum, &term)
	}
	return res
}

func poseidon2MatMulInternalExprs(input []expr.Expr) []expr.Expr {
	diag := poseidon2InternalDiag(len(input))
	sum := zeroExpr()
	for i := range input {
		sum = sum.Add(input[i])
	}
	res := make([]expr.Expr, len(input))
	for i := range res {
		res[i] = sum.Add(input[i].Mul(expr.Const(diag[i])))
	}
	return res
}

func poseidon2InternalDiag(width int) []koalabear.Element {
	var vals []uint64
	switch width {
	case poseidon2MDWidth:
		vals = []uint64{
			2130706431, 1, 2, 1065353217,
			3, 4, 1065353216, 2130706430,
			2130706429, 2122383361, 1864368129, 2130706306,
			8323072, 266338304, 133169152, 127,
		}
	case poseidon2SpongeWidth:
		vals = []uint64{
			2130706431, 1, 2, 1065353217,
			3, 4, 1065353216, 2130706430,
			2130706429, 2122383361, 1598029825, 1864368129,
			1997537281, 2064121857, 2097414145, 2130706306,
			8323072, 266338304, 133169152, 66584576,
			33292288, 16646144, 4161536, 127,
		}
	default:
		panic(fmt.Errorf("recursion: unsupported Poseidon2 width %d", width))
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
