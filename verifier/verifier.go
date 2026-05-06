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

type PublicKey = commitment.WMerkleTree

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

	if setup.Tree != nil {
		res.fs.Bind(constants.CanonicalChallengeName(0), res.setup.Root())
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

	// populate proof.ValuesAtZeta with the challenges
	for i, tc := range vr.proof.TraceCommitments {
		challengeName := constants.CanonicalChallengeName(i)
		vr.fs.Bind(challengeName, tc)
		bChallenge, err := vr.fs.ComputeChallenge((challengeName))
		if err != nil {
			return err
		}
		var c koalabear.Element
		c.SetBytes(bChallenge)
		vr.proof.ValuesAtZeta[challengeName] = c
	}
	vr.fs.Bind(constants.FINAL_EVALUATION_POINT, vr.proof.AIRQuotientsCommitment)
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

	// // ------- check FRI <-> trace commitments bridge -------

	// sortedModule := make([]string, 0, len(vr.program.Modules))
	// for name := range vr.program.Modules {
	// 	sortedModule = append(sortedModule, name)
	// }
	// sort.Slice(sortedModule, func(i, j int) bool {
	// 	return vr.program.Modules[sortedModule[i]].N > vr.program.Modules[sortedModule[j]].N
	// })

	// var alpha koalabear.Element
	// // TODO follow FS schedule to derive it as in the prover
	// alpha.SetUint64(10)

	// // recomputed pairs of points: \sum_i alpha^i (C(w^j) - f(shift*z_s))/(w^j - shift*z_s)) for some j corresponding to the query positions of FRI
	// recomputedPairs := make([]commitment.Pair, constants.NUM_QUERIES)

	// // loop through sortedModule, get the corresponding module
	// for _, moduleName := range sortedModule {
	// 	module := vr.program.Modules[moduleName]
	// 	N := module.N

	// 	// 1 - get the RotatedColumn and CommittedColumn from the module's vanishing relation
	// 	config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
	// 	leaves := module.VanishingRelation.LeavesFull(config)

	// 	// 2 - group columns by normalized shift; deduplicate by leaf.String()
	// 	// Each entry carries the bare column name (for trace lookup) and the original
	// 	// leaf.String() key (for ValuesAtZeta lookup, which preserves the raw shift).
	// 	type colEntry struct {
	// 		name string // bare column name → key in pr.t
	// 		key  string // leaf.String() → key in ValuesAtZeta
	// 	}
	// 	byShift := map[int][]colEntry{} // normalized shift → entries
	// 	seenKey := map[string]bool{}    // deduplicate by leaf.String()
	// 	for _, leaf := range leaves {
	// 		k := leaf.String()
	// 		if seenKey[k] {
	// 			continue
	// 		}
	// 		seenKey[k] = true
	// 		normalizedShift := 0
	// 		if leaf.Type == expr.RotatedColumn {
	// 			normalizedShift = ((leaf.Shift % N) + N) % N
	// 		}
	// 		byShift[normalizedShift] = append(byShift[normalizedShift], colEntry{name: leaf.Name, key: k})
	// 	}
	// 	// store shifts sorted in increasing order
	// 	shifts := make([]int, 0, len(byShift))
	// 	for s := range byShift {
	// 		shifts = append(shifts, s)
	// 	}
	// 	sort.Ints(shifts)

	// 	// 3 - for each shift in 'sorted' (looped through in increasing order), fold the corresponding columns in the trace
	// 	// using alpha to build C_shift := \sum_i \alpha^i C
	// 	// compute C_shift_deep := (C_shift(\omega^shift * zeta)-C_shift)/(omega^shift*zeta - X) using synthetic division
	// 	for _, shift := range shifts {

	// 		// evaluation point z_s = omega^shift * zeta
	// 		var omegaShift koalabear.Element
	// 		omegaShift.SetOne()
	// 		for k := 0; k < shift; k++ {
	// 			omegaShift.Mul(&omegaShift, &module.D.Generator)
	// 		}
	// 		var z_s koalabear.Element
	// 		z_s.Mul(&vr.zeta, &omegaShift)

	// 		// compute : v_s = C_s(z_s) = sum_i alphaAcc_i * C_i(z_s)
	// 		// and samples of C_s(X) = sum_i alphaAcc_i * C_i(X) for X = w^i for i in proof.DeepQuotientFriProof.Queries[0].Path.LeafIdx
	// 		C_s := make(poly.Polynomial, N)
	// 		var v_s koalabear.Element
	// 		for _, entry := range byShift[shift] {
	// 			col := pr.t[entry.name]
	// 			evalAtZ, ok := pr.Proof.ValuesAtZeta[entry.key]
	// 			if !ok {
	// 				return fmt.Errorf("ComputeDeepQuotient: %q not found in ValuesAtZeta", entry.key)
	// 			}
	// 			for j := 0; j < constants.NUM_QUERIES; j++ {
	// 				var term koalabear.Element
	// 				if len(col) == 1 {
	// 					term = col[0] // constant polynomial
	// 				} else {
	// 					term = col[j]
	// 				}
	// 				term.Mul(&term, &alphaAcc)
	// 				C_s[j].Add(&C_s[j], &term)
	// 			}
	// 			var term koalabear.Element
	// 			term.Mul(&evalAtZ, &alphaAcc)
	// 			v_s.Add(&v_s, &term)
	// 			alphaAcc.Mul(&alphaAcc, &alpha)
	// 		}

	// 		// compute DQ_s = (v_s - C_s(X)) / (z_s - X) via synthetic division
	// 		DQ_s := poly.DeepQuotient(C_s, v_s, z_s, module.D)

	// 		// accumulate into deepQuotient; extend to maxN domain if this module is smaller
	// 		if N == maxN {
	// 			for j := 0; j < N; j++ {
	// 				deepQuotient[j].Add(&deepQuotient[j], &DQ_s[j])
	// 			}
	// 		} else {
	// 			// IFFT DQ_s to canonical (natural order), zero-pad to maxN, FFT to largest domain
	// 			module.D.FFTInverse(DQ_s, fft.DIF)
	// 			utils.BitReverse(DQ_s)
	// 			extended := make(poly.Polynomial, maxN)
	// 			copy(extended, DQ_s)
	// 			// largestD := fft.NewDomain(uint64(maxN))
	// 			largestD.FFT(extended, fft.DIF)
	// 			utils.BitReverse(extended)
	// 			for j := 0; j < maxN; j++ {
	// 				deepQuotient[j].Add(&deepQuotient[j], &extended[j])
	// 			}
	// 		}
	// 	}
	// }

	// // Compute the AIR quotient shares of the DEEP ComputeDeepQuotient
	// // 1- loop through the modules in the program (in the order given by sortedModule)
	// // 2- add the contribution of each quotient shares for the given module (ordered by share 0, then share 1, etc...) to the deep quotient
	// for _, moduleName := range sortedModule {
	// 	module := pr.program.Modules[moduleName]
	// 	N := module.N

	// 	C_s := make(poly.Polynomial, N)
	// 	var v_s koalabear.Element
	// 	for i := 0; ; i++ {
	// 		chunkName := constants.QuotientChunkName(moduleName, i)
	// 		chunk, ok := pr.airTrace[chunkName]
	// 		if !ok {
	// 			break
	// 		}
	// 		evalAtZ := pr.Proof.ValuesAtZeta[chunkName]
	// 		for j := 0; j < N; j++ {
	// 			var term koalabear.Element
	// 			term.Mul(&chunk[j], &alphaAcc)
	// 			C_s[j].Add(&C_s[j], &term)
	// 		}
	// 		var term koalabear.Element
	// 		term.Mul(&evalAtZ, &alphaAcc)
	// 		v_s.Add(&v_s, &term)
	// 		alphaAcc.Mul(&alphaAcc, &alpha)
	// 	}

	// 	DQ_air := poly.DeepQuotient(C_s, v_s, pr.zeta, module.D)

	// 	if N == maxN {
	// 		for j := 0; j < N; j++ {
	// 			deepQuotient[j].Add(&deepQuotient[j], &DQ_air[j])
	// 		}
	// 	} else {
	// 		module.D.FFTInverse(DQ_air, fft.DIF)
	// 		utils.BitReverse(DQ_air)
	// 		extended := make(poly.Polynomial, maxN)
	// 		copy(extended, DQ_air)
	// 		largestD.FFT(extended, fft.DIF)
	// 		utils.BitReverse(extended)
	// 		for j := 0; j < maxN; j++ {
	// 			deepQuotient[j].Add(&deepQuotient[j], &extended[j])
	// 		}
	// 	}
	// }

	// -------- check FRI proof -------
	err := fri.Verify(vr.friParams, vr.proof.DeepQuotientCommitment, vr.proof.DeepQuotientFriProof, vr.fs)
	if err != nil {
		return err
	}

	return nil
}

func (vr *verifierRunTime) checkMerkleProofsPointSampling() error {

	for i := 0; i < constants.NUM_QUERIES; i++ {
		offset := 0
		// share of the setup
		if vr.setup.Tree != nil {
			wp := vr.proof.PointSamplings[i][0]
			buf := make([]byte, 2*len(wp.RawLeaf)*koalabear.Bytes)
			for k := 0; k < len(wp.RawLeaf); k++ {
				copy(buf[2*k*koalabear.Bytes:], wp.RawLeaf[k][0].Marshal())
				copy(buf[(2*k+1)*koalabear.Bytes:], wp.RawLeaf[k][1].Marshal())
			}
			merkle.Verify(vr.setup.Root(), wp.Proof, buf, commitment.LeafHash, commitment.NodeHash)
			offset++
		}
		// share of rounds (covering the whole trace)
		for j, trc := range vr.proof.TraceCommitments {
			wp := vr.proof.PointSamplings[i][offset+j]
			buf := make([]byte, 2*len(wp.RawLeaf)*koalabear.Bytes)
			for k := 0; k < len(wp.RawLeaf); k++ {
				copy(buf[2*k*koalabear.Bytes:], wp.RawLeaf[k][0].Marshal())
				copy(buf[(2*k+1)*koalabear.Bytes:], wp.RawLeaf[k][1].Marshal())
			}
			merkle.Verify(trc, wp.Proof, buf, commitment.LeafHash, commitment.NodeHash)
		}
		offset += len(vr.proof.TraceCommitments)
		// share of the AIR quotients
		wp := vr.proof.PointSamplings[i][offset]
		buf := make([]byte, 2*len(wp.RawLeaf)*koalabear.Bytes)
		for k := 0; k < len(wp.RawLeaf); k++ {
			copy(buf[2*k*koalabear.Bytes:], wp.RawLeaf[k][0].Marshal())
			copy(buf[(2*k+1)*koalabear.Bytes:], wp.RawLeaf[k][1].Marshal())
		}
		merkle.Verify(vr.proof.AIRQuotientsCommitment, wp.Proof, buf, commitment.LeafHash, commitment.NodeHash)
		offset++
	}

	return nil
}

func (vr *verifierRunTime) checkFRIBridge() error {
	// Sort modules by decreasing N — must match ComputeDeepQuotient in the prover.
	sortedModule := make([]string, 0, len(vr.program.Modules))
	for name := range vr.program.Modules {
		sortedModule = append(sortedModule, name)
	}
	sort.Slice(sortedModule, func(i, j int) bool {
		ni := vr.program.Modules[sortedModule[i]].N
		nj := vr.program.Modules[sortedModule[j]].N
		if ni != nj {
			return ni > nj
		}
		return sortedModule[i] < sortedModule[j]
	})

	// colToSlot maps a bare column name to its position in PointSamplings[k]:
	// samplingIdx is the WMerkleProof index, leafIdx is the index within RawLeaf.
	// Order must match SampleEvaluations: [setup?] + tTrees[0..r-1] + airTree.
	type colSlot struct {
		samplingIdx int
		leafIdx     int
	}
	colToSlot := make(map[string]colSlot)
	offset := 0
	if vr.setup.Tree != nil {
		offset = 1
	}
	for roundIdx, deps := range vr.program.FScolumnsDependencies {
		for leafIdx, name := range deps {
			colToSlot[name] = colSlot{samplingIdx: offset + roundIdx, leafIdx: leafIdx}
		}
	}

	// airChunkToLeafIdx maps a chunk name to its RawLeaf index within the air tree opening.
	// Order must match the fixed ComputeAIRQuotients: sortedModule × chunkIdx.
	airChunkToLeafIdx := make(map[string]int)
	airLeafIdx := 0
	for _, moduleName := range sortedModule {
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			if _, ok := vr.proof.ValuesAtZeta[chunkName]; !ok {
				break
			}
			airChunkToLeafIdx[chunkName] = airLeafIdx
			airLeafIdx++
		}
	}
	airSamplingIdx := offset + len(vr.program.FScolumnsDependencies)

	var alpha koalabear.Element
	alpha.SetUint64(10) // TODO: derive via FS, same as prover

	leafConfig := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())
	friDomainGen := vr.friParams.FullDomainGenerator()

	for k := 0; k < constants.NUM_QUERIES; k++ {
		s := vr.proof.DeepQuotientFriProof.Queries[k].Layers[0].Path.LeafIdx

		var omega_s koalabear.Element
		omega_s.Exp(friDomainGen, big.NewInt(int64(s)))
		var neg_omega_s koalabear.Element
		neg_omega_s.Neg(&omega_s)

		var DQ_s, DQ_neg_s koalabear.Element
		var alphaAcc koalabear.Element
		alphaAcc.SetOne()

		// Trace columns — mirrors ComputeDeepQuotient's first loop.
		for _, moduleName := range sortedModule {
			module := vr.program.Modules[moduleName]
			N := module.N

			type colEntry struct {
				name string
				key  string
			}
			byShift := map[int][]colEntry{}
			seenKey := map[string]bool{}
			for _, leaf := range module.VanishingRelation.LeavesFull(leafConfig) {
				lk := leaf.String()
				if seenKey[lk] {
					continue
				}
				seenKey[lk] = true
				normalizedShift := 0
				if leaf.Type == expr.RotatedColumn {
					normalizedShift = ((leaf.Shift % N) + N) % N
				}
				byShift[normalizedShift] = append(byShift[normalizedShift], colEntry{name: leaf.Name, key: lk})
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
				var omegaShift koalabear.Element
				omegaShift.SetOne()
				for j := 0; j < shift; j++ {
					omegaShift.Mul(&omegaShift, &module.D.Generator)
				}
				var z_s koalabear.Element
				z_s.Mul(&vr.zeta, &omegaShift)

				var v_s, C_s_at_point, C_s_at_neg koalabear.Element
				for _, entry := range byShift[shift] {
					evalAtZ := vr.proof.ValuesAtZeta[entry.key]
					slot, ok := colToSlot[entry.name]
					if !ok {
						return fmt.Errorf("checkFRIBridge: column %q not found in colToSlot", entry.name)
					}
					pair := vr.proof.PointSamplings[k][slot.samplingIdx].RawLeaf[slot.leafIdx]

					var term koalabear.Element
					term.Mul(&evalAtZ, &alphaAcc)
					v_s.Add(&v_s, &term)

					term.Set(&pair[0])
					term.Mul(&term, &alphaAcc)
					C_s_at_point.Add(&C_s_at_point, &term)

					term.Set(&pair[1])
					term.Mul(&term, &alphaAcc)
					C_s_at_neg.Add(&C_s_at_neg, &term)

					alphaAcc.Mul(&alphaAcc, &alpha)
				}

				var num, denom koalabear.Element
				num.Sub(&v_s, &C_s_at_point)
				denom.Sub(&z_s, &omega_s)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_s.Add(&DQ_s, &num)

				num.Sub(&v_s, &C_s_at_neg)
				denom.Sub(&z_s, &neg_omega_s)
				denom.Inverse(&denom)
				num.Mul(&num, &denom)
				DQ_neg_s.Add(&DQ_neg_s, &num)
			}
		}

		// Air quotient chunks — mirrors ComputeDeepQuotient's second loop.
		for _, moduleName := range sortedModule {
			var v_s, C_s_at_point, C_s_at_neg koalabear.Element
			for i := 0; ; i++ {
				chunkName := constants.QuotientChunkName(moduleName, i)
				evalAtZ, ok := vr.proof.ValuesAtZeta[chunkName]
				if !ok {
					break
				}
				lIdx := airChunkToLeafIdx[chunkName]
				pair := vr.proof.PointSamplings[k][airSamplingIdx].RawLeaf[lIdx]

				var term koalabear.Element
				term.Mul(&evalAtZ, &alphaAcc)
				v_s.Add(&v_s, &term)

				term.Set(&pair[0])
				term.Mul(&term, &alphaAcc)
				C_s_at_point.Add(&C_s_at_point, &term)

				term.Set(&pair[1])
				term.Mul(&term, &alphaAcc)
				C_s_at_neg.Add(&C_s_at_neg, &term)

				alphaAcc.Mul(&alphaAcc, &alpha)
			}

			var num, denom koalabear.Element
			num.Sub(&v_s, &C_s_at_point)
			denom.Sub(&vr.zeta, &omega_s)
			denom.Inverse(&denom)
			num.Mul(&num, &denom)
			DQ_s.Add(&DQ_s, &num)

			num.Sub(&v_s, &C_s_at_neg)
			denom.Sub(&vr.zeta, &neg_omega_s)
			denom.Inverse(&denom)
			num.Mul(&num, &denom)
			DQ_neg_s.Add(&DQ_neg_s, &num)
		}

		expectedP := vr.proof.DeepQuotientFriProof.Queries[k].Layers[0].LeafP
		expectedQ := vr.proof.DeepQuotientFriProof.Queries[k].Layers[0].LeafQ

		if !DQ_s.Equal(&expectedP) {
			return fmt.Errorf("checkFRIBridge: query %d: DQ(ω^s) mismatch: got %s, want %s", k, DQ_s.String(), expectedP.String())
		}
		if !DQ_neg_s.Equal(&expectedQ) {
			return fmt.Errorf("checkFRIBridge: query %d: DQ(-ω^s) mismatch: got %s, want %s", k, DQ_neg_s.String(), expectedQ.String())
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
