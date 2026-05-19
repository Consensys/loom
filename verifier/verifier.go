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
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/public"

	"github.com/consensys/loom/setup"
)

type Config struct {
	SkipFRI bool
}

type Option func(c *Config) error

func SkipFRI() Option {
	return func(c *Config) error {
		c.SkipFRI = true
		return nil
	}
}

type PublicKey = []commitment.WMerkleTree

type verifierRunTime struct {
	config       Config
	proof        proof.Proof
	friParams    fri.Params
	publicInputs public.Inputs
	program      board.Program
	zeta         ext.E4 // point of evaluation to check the AIR relation with SZ
	alpha        ext.E4 // folding challenge for N-grouped polynomials, used to build the DEEP quotient
	setup        setup.PublicKeyRoots
	fs           *fiatshamir.Transcript
	dqLayout     prover.DEEPquotientLayout

	// layout is the canonical commitment layout, shared with the prover side
	// (built from program + len(setup) at the start of every Verify call).
	layout prover.Layout
	// roots is the flat sequence of Merkle roots in canonical order:
	//   setup roots (from PublicKey) ++ proof.Commitments
	// roots[i] aligns with proof.PointSamplings[q][i] for any query q.
	roots [][]byte
}

func newVerifierRuntime(program board.Program, setup setup.PublicKeyRoots, publicInputs public.Inputs, prf proof.Proof, config Config) (verifierRunTime, error) {
	res := verifierRunTime{
		config:       config,
		proof:        prf,
		publicInputs: publicInputs,
		program:      program,
		setup:        setup,
	}

	// Build the layout shared with the prover.
	res.layout = prover.BuildLayout(program, len(setup))
	res.dqLayout = prover.BuildDeepQuotientLayout(program)

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
	for i, pkr := range setup {
		res.roots[res.layout.SetupBegin+i] = pkr
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
	res.fs.NewChallenge(constants.DEEP_ALPHA)

	// Setup roots are bound to challenge_0 (alongside trace round 0 in deriveChallenges).
	for _, pkr := range setup {
		res.fs.Bind(constants.CanonicalChallengeName(0), pkr)
	}

	// find the largest module size N in program (used to size FRI's outer domain)
	maxN := 0
	for _, m := range program.Modules {
		if m.N > maxN {
			maxN = m.N
		}
	}

	var err error
	res.friParams, err = fri.NewParams(int(constants.RATE)*maxN, maxN, constants.NUM_QUERIES, commitment.LeafHash, commitment.NodeHash, fri.LightMode())
	if err != nil {
		return res, err
	}

	return res, nil
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
		var c ext.E4
		if err := setExtFromBytes(&c, bChallenge); err != nil {
			return err
		}
		vr.proof.SetValueAtZetaExt(challengeName, c)
	}
	// Bind every per-size AIR-quotient root before computing zeta.
	for i := vr.layout.AIRBegin; i < vr.layout.AIREnd; i++ {
		vr.fs.Bind(constants.FINAL_EVALUATION_POINT, vr.roots[i])
	}
	bzeta, err := vr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	if err := setExtFromBytes(&vr.zeta, bzeta); err != nil {
		return err
	}

	return nil
}

func (vr *verifierRunTime) deriveDeepAlpha() error {
	if err := prover.BindDeepEvaluationClaims(vr.fs, vr.proof, vr.dqLayout); err != nil {
		return err
	}
	alphaBytes, err := vr.fs.ComputeChallenge(constants.DEEP_ALPHA)
	if err != nil {
		return err
	}
	return setExtFromBytes(&vr.alpha, alphaBytes)
}

// TODO the verifier should fetch the public values from the vanishing expressions, and look them up
// in proof.PublicColumns, but not just trust proof.PublicColumns
func (vr *verifierRunTime) computeExposedColumns() error {
	for _, m := range vr.program.Modules {
		leafs := m.VanishingRelation.Leaves(expr.NewConfig(expr.OnlyExposedColumns...))
		for _, leaf := range leafs {
			pi, ok := vr.proof.ExposedValues[leaf]
			if !ok {
				return fmt.Errorf("computeExposedColumns: %s not found in proof.ExposedValues", leaf)
			}
			var lag ext.E4
			for _, pe := range pi.Entries {
				tmp := poly.LagrangeAtZetaExt(vr.zeta, m.N, pe.Idx)
				value := pe.ExtValue()
				tmp.Mul(&tmp, &value)
				lag.Add(&lag, &tmp)
			}
			vr.proof.SetValueAtZetaExt(leaf, lag)
		}
	}
	// for k, pi := range vr.proof.ExposedValues {
	// 	var lag ext.E4
	// 	for _, pe := range pi.Entries {
	// 		tmp := poly.LagrangeAtZetaExt(vr.zeta, pi.N, pe.Idx)
	// 		value := pe.ExtValue()
	// 		tmp.Mul(&tmp, &value)
	// 		lag.Add(&lag, &tmp)
	// 	}
	// 	vr.proof.SetValueAtZetaExt(k, lag)
	// }
	return nil
}

func (vr *verifierRunTime) computeLagrange() error {
	config := expr.OnlyLagranges
	for _, m := range vr.program.Modules {
		lags := m.VanishingRelation.Leaves(expr.NewConfig(config...))
		for _, lag := range lags {
			if _, ok := vr.proof.ValueAtZetaExt(lag); ok {
				continue
			}
			i := constants.ParseLagrangeName(lag)
			if i < 0 {
				i = m.N + i
			}
			v := poly.LagrangeAtZetaExt(vr.zeta, m.N, i)
			vr.proof.SetValueAtZetaExt(lag, v)
		}
	}
	return nil
}

func (vr *verifierRunTime) checkLogupBus() error {
	for _, bus := range vr.program.LogupBus {
		var cumNegative, cumPositive ext.E4
		for _, pos := range bus.Positive {
			if len(vr.proof.ExposedValues[pos].Entries) > 1 {
				return fmt.Errorf("an extracted value from a logup column should have exactly one entry")
			}
			pe := vr.proof.ExposedValues[pos].Entries[0]
			value := pe.ExtValue()
			cumPositive.Add(&cumPositive, &value)
		}
		for _, neg := range bus.Negative {
			if len(vr.proof.ExposedValues[neg].Entries) > 1 {
				return fmt.Errorf("an extracted value from a logup column should have exactly one entry")
			}
			pe := vr.proof.ExposedValues[neg].Entries[0]
			value := pe.ExtValue()
			cumNegative.Add(&cumNegative, &value)
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
	valuesAtZeta := vr.proof.ExtValuesAtZeta()

	for moduleName, m := range vr.program.Modules {
		var qZeta ext.E4
		var zetaPowIN ext.E4
		zetaPowIN.SetOne()
		var zetaN ext.E4
		zetaN.Exp(vr.zeta, big.NewInt(int64(m.N)))
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			chunkVal, ok := vr.proof.ValueAtZetaExt(chunkName)
			if !ok {
				break
			}
			var term ext.E4
			term.Mul(&zetaPowIN, &chunkVal)
			qZeta.Add(&qZeta, &term)
			zetaPowIN.Mul(&zetaPowIN, &zetaN)
		}

		vZeta := m.VanishingRelation.EvalExt(valuesAtZeta)

		var one, zetaNMinusOne, rhs ext.E4
		one.SetOne()
		zetaNMinusOne.Sub(&zetaN, &one)
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
	levelRoots := make([][]byte, len(levelDs))
	for i := range levelDs {
		levelRoots[i] = vr.proof.DeepQuotientCommitment[i]
	}

	return fri.Verify(vr.friParams, levelRoots, levelDs, vr.proof.DeepQuotientFriProof, vr.fs)
}

// verifyWMerkleProof checks wp opens to its leaf data under root, using the
// same base-then-ext paired-leaf serialisation as RSCommit.Commit.
func verifyWMerkleProof(root []byte, wp commitment.WMerkleProof) bool {
	buf := commitment.SerializeRawLeaf(wp.RawLeafBase, wp.RawLeafExt)
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

	dqLayout := vr.dqLayout
	sizes := dqLayout.Sizes

	domainBySize := make(map[int]*fft.Domain, len(sizes))
	for _, m := range vr.program.Modules {
		if _, ok := domainBySize[m.N]; !ok {
			domainBySize[m.N] = m.D
		}
	}

	samplePair := func(slot prover.Slot, q int) (ext.E4, ext.E4, error) {
		if slot.TreeIdx >= len(vr.proof.PointSamplings[q]) {
			return ext.E4{}, ext.E4{}, fmt.Errorf("checkFRIBridge: tree index %d out of range", slot.TreeIdx)
		}
		wp := vr.proof.PointSamplings[q][slot.TreeIdx]
		if slot.Field == field.Ext {
			rawIdx := slot.PolyIdx
			if rawIdx >= len(wp.RawLeafExt) {
				return ext.E4{}, ext.E4{}, fmt.Errorf("checkFRIBridge: ext raw leaf index %d out of range for slot %+v (have %d)", rawIdx, slot, len(wp.RawLeafExt))
			}
			return wp.RawLeafExt[rawIdx][0], wp.RawLeafExt[rawIdx][1], nil
		}

		rawIdx := slot.PolyIdx
		if rawIdx >= len(wp.RawLeafBase) {
			return ext.E4{}, ext.E4{}, fmt.Errorf("checkFRIBridge: base raw leaf index %d out of range for slot %+v (have %d)", rawIdx, slot, len(wp.RawLeafBase))
		}
		return liftBaseToExt(wp.RawLeafBase[rawIdx][0]), liftBaseToExt(wp.RawLeafBase[rawIdx][1]), nil
	}

	for q := 0; q < NQ; q++ {
		sFull := vr.proof.DeepQuotientFriProof.FRIQueries[q].Layers[0].Path.LeafIdx

		for i, N := range sizes {
			domainSize := constants.RATE * N
			halfDomain := domainSize / 2
			sL := sFull % halfDomain

			generator, err := koalabear.Generator(uint64(domainSize))
			if err != nil {
				return err
			}
			var XBase, negXBase koalabear.Element
			XBase.Exp(generator, big.NewInt(int64(sL)))
			negXBase.Neg(&XBase)
			X := liftBaseToExt(XBase)
			negX := liftBaseToExt(negXBase)

			domN := domainBySize[N]

			var DQ_P, DQ_Q ext.E4
			var alphaAcc ext.E4
			alphaAcc.SetOne()

			for j, shift := range dqLayout.Shifts[i] {
				var omegaShift koalabear.Element
				omegaShift.Exp(domN.Generator, big.NewInt(int64(shift)))
				z_s := vr.zeta
				z_s.MulByElement(&z_s, &omegaShift)

				var v_s, C_at_X, C_at_negX ext.E4
				names := dqLayout.Names[i][j]
				keys := dqLayout.Keys[i][j]
				for k := range names {
					evalAtZ, ok := vr.proof.ValueAtZetaExt(keys[k])
					if !ok {
						return fmt.Errorf("checkFRIBridge: %q not in ValuesAtZeta", keys[k])
					}
					slot, ok := vr.layout.ColSlot[names[k]]
					if !ok {
						return fmt.Errorf("checkFRIBridge: column %q not in layout.ColSlot", names[k])
					}
					leafP, leafQ, err := samplePair(slot, q)
					if err != nil {
						return err
					}

					var term ext.E4
					term.Mul(&evalAtZ, &alphaAcc)
					v_s.Add(&v_s, &term)
					term.Mul(&leafP, &alphaAcc)
					C_at_X.Add(&C_at_X, &term)
					term.Mul(&leafQ, &alphaAcc)
					C_at_negX.Add(&C_at_negX, &term)

					alphaAcc.Mul(&alphaAcc, &vr.alpha)
				}

				var num, denom ext.E4
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

			if len(dqLayout.AIRChunks[i]) > 0 {
				var v_air, C_at_X, C_at_negX ext.E4
				for _, chunkName := range dqLayout.AIRChunks[i] {
					evalAtZ, ok := vr.proof.ValueAtZetaExt(chunkName)
					if !ok {
						return fmt.Errorf("checkFRIBridge: %q not in ValuesAtZeta", chunkName)
					}
					slot, ok := vr.layout.AIRChunkSlot[chunkName]
					if !ok {
						return fmt.Errorf("checkFRIBridge: chunk %q not in layout.AIRChunkSlot", chunkName)
					}
					leafP, leafQ, err := samplePair(slot, q)
					if err != nil {
						return err
					}

					var term ext.E4
					term.Mul(&evalAtZ, &alphaAcc)
					v_air.Add(&v_air, &term)
					term.Mul(&leafP, &alphaAcc)
					C_at_X.Add(&C_at_X, &term)
					term.Mul(&leafQ, &alphaAcc)
					C_at_negX.Add(&C_at_negX, &term)

					alphaAcc.Mul(&alphaAcc, &vr.alpha)
				}

				var num, denom ext.E4
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

			var actualP, actualQ ext.E4
			if i == 0 {
				layer := vr.proof.DeepQuotientFriProof.FRIQueries[q].Layers[0]
				if layer.Field != field.Ext {
					return fmt.Errorf("checkFRIBridge: expected ext FRI query layer, got %s", layer.Field)
				}
				actualP = layer.LeafPExt
				actualQ = layer.LeafQExt
			} else {
				lq := vr.proof.DeepQuotientFriProof.LevelQueries[i-1][q]
				if lq.Field != field.Ext {
					return fmt.Errorf("checkFRIBridge: expected ext FRI level query, got %s", lq.Field)
				}
				actualP = lq.LeafPExt
				actualQ = lq.LeafQExt
			}
			if !DQ_P.Equal(&actualP) {
				return fmt.Errorf("checkFRIBridge: query %d level %d (N=%d): DQ(ω_l^s) mismatch: got %s, want %s", q, i, N, DQ_P.String(), actualP.String())
			}
			if !DQ_Q.Equal(&actualQ) {
				return fmt.Errorf("checkFRIBridge: query %d level %d (N=%d): DQ(-ω_l^s) mismatch: got %s, want %s", q, i, N, DQ_Q.String(), actualQ.String())
			}
		}
	}

	return nil
}

func Verify(publicInputs public.Inputs, setup setup.PublicKeyRoots, program board.Program, proof proof.Proof, opts ...Option) error {

	var config Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	vr, err := newVerifierRuntime(program, setup, publicInputs, proof, config)
	if err != nil {
		return err
	}

	// 1 - derive the challenges, and populate proof.ValuesAtZeta with those challenges
	err = vr.deriveChallenges()
	if err != nil {
		return err
	}

	// 2 - populate proof.ValuesAtZeta with the public columns and lagrange columns
	err = vr.computeExposedColumns()
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

	if !config.SkipFRI {

		// 5a - derive the DEEP batching challenge before FRI appends its own
		// challenges to the shared transcript.
		err = vr.deriveDeepAlpha()
		if err != nil {
			return err
		}

		// 5b - check FRI proof
		err = vr.checkFRIProof()
		if err != nil {
			return err
		}

		// 5c - check merkle proofs of proof.PointSamplings
		err = vr.checkMerkleProofsPointSampling()
		if err != nil {
			return err
		}

		// 5d - check FRI <-> PointSamplings bridge
		err = vr.checkFRIBridge()
		if err != nil {
			return err
		}

	}

	return nil
}
