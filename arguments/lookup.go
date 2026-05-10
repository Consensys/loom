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

package arguments

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
)

func Range(builder *board.Builder, S board.Column, bound uint64) error {

	// 1 - check if the range module for bound exists, if not, create it
	bound = ecc.NextPowerOfTwo(bound)
	rangeModuleName := constants.RangeModuleName(bound)
	_, ok := builder.Modules[rangeModuleName]
	if !ok {
		rangeModule := board.NewModule(constants.RangeModuleName(bound))
		rangeModule.N = int(bound)
		rangeModule.GenCol = append(rangeModule.GenCol, board.RangeColumnGen{Bound: bound})
		builder.AddModule(constants.RangeModuleName(bound), rangeModule)
	}
	T := board.Column{Module: rangeModuleName, In: expr.Col(constants.RangeColName(bound))}

	// 2 - add the lookup
	return Lookup(builder, S, T)
}

// LookupUnion argument that {S[0], S[1], ..} ⊂ {T[0], T[1], ..}
// len(S) and len(T) need not be equal.
func LookupUnion(builder *board.Builder, S, T []board.Column) error {

	// 1 - compute union multiplicity
	unionMultiplicity, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	sIn := make([]expr.Expr, len(S))
	tIn := make([]expr.Expr, len(T))
	for i, sin := range S {
		sIn[i] = sin.In
	}
	for i, tin := range T {
		tIn[i] = tin.In
	}
	builder.AddCountMultiplicityStep(sIn, tIn, unionMultiplicity)

	// 2 - sample the challenge
	fsInputs := make([]expr.Expr, len(S)+len(T)+len(T))
	copy(fsInputs, sIn)
	copy(fsInputs[len(S):], tIn)
	for i := 0; i < len(T); i++ {
		fsInputs[len(S)+len(T)+i] = expr.Col(constants.MultiplicityChunkName(unionMultiplicity, i))
	}
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 3 - compute |S| logups for S, |T| logups for T
	gamma := expr.Challenge(_gamma)
	_logupS, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupT, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	logupT := make([]board.Column, len(T))
	logupS := make([]board.Column, len(S))
	for i, t := range T {
		_logupT = fmt.Sprintf("%s.%s_%s", t.Module, constants.LOGUP, _logupT)
		sMinusGamma := t.In.Sub(gamma)
		logupName := constants.LogupChunkName(_logupT, i)
		builder.AddLogupStep(
			t.Module,
			sMinusGamma,
			expr.Col(constants.MultiplicityChunkName(unionMultiplicity, i)),
			logupName)
		logupT[i] = board.Column{Module: t.Module, In: expr.Col(logupName)}
	}
	for i, s := range S {
		_logupS = fmt.Sprintf("%s.%s_%s", s.Module, constants.LOGUP, _logupS)
		sMinusGamma := s.In.Sub(gamma)
		logupName := constants.LogupChunkName(_logupS, i)
		builder.AddLogupStep(
			s.Module,
			sMinusGamma,
			expr.Const(koalabear.One()),
			logupName)
		logupS[i] = board.Column{Module: s.Module, In: expr.Col(logupName)}
	}

	// 4. Add logup equality check
	AddLogupEqualityCheck(builder, logupS, logupT)

	return nil
}

// LookupUnionTuple
// argument that {S[0], S[1], ..} ⊂ {T[0], T[1], ..}, where S[i], T[i] are tuples of columns
//
// for each i, len(S[i]) must be equal to len(T[i])
func LookupUnionTuple(builder *board.Builder, S, T []board.Table) error {

	refWidth := len(S[0].In)
	for _, s := range S {
		if len(s.In) != refWidth {
			return fmt.Errorf("inconsistent width, expected %d, got %d", refWidth, len(s.In))
		}
	}
	for _, t := range T {
		if len(t.In) != refWidth {
			return fmt.Errorf("inconsistent width, expected %d, got %d", refWidth, len(t.In))
		}
	}

	// 1. fold each S[i], each T[i] to reduce the case to LookupUnion
	fsInputs := make([]expr.Expr, 0, (len(S)+len(T))*len(S[0].In))
	for _, s := range S {
		fsInputs = append(fsInputs, s.In...)

	}
	for _, t := range T {
		fsInputs = append(fsInputs, t.In...)

	}
	_alpha, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _alpha)

	// 2. call LookupUnion on foldedS, foldedT
	foldedS := make([]board.Column, len(S))
	foldedT := make([]board.Column, len(T))
	alpha := expr.Challenge(_alpha)
	for i, s := range S {
		foldedS[i].In = expr.Fold(alpha, s.In)
		foldedS[i].Module = s.Module
	}
	for i, t := range T {
		foldedT[i].In = expr.Fold(alpha, t.In)
		foldedT[i].Module = t.Module
	}

	return LookupUnion(builder, foldedS, foldedT)
}

func CLookupUnion(builder *board.Builder, selS, selT []expr.Expr, S, T []board.Column) error {

	if len(selS) != len(S) {
		return fmt.Errorf("selS has %d chunks, but S has %d chunks", len(selS), len(S))
	}
	if len(selT) != len(T) {
		return fmt.Errorf("selS has %d chunks, but S has %d chunks", len(selS), len(S))
	}

	// 1 - build the weigthed multiplicity
	wmultiplicity, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	wmultiplicity = fmt.Sprintf("Mult_%s", wmultiplicity)
	sIn := make([]expr.Expr, len(S))
	tIn := make([]expr.Expr, len(T))
	for i, s := range S {
		sIn[i] = s.In
	}
	for i, t := range T {
		tIn[i] = t.In
	}
	builder.AddCountWeightedMultiplicityStep(selS, sIn, tIn, wmultiplicity)

	// 2 - samplea challenge
	wmultiplicities := make([]expr.Expr, len(T))
	for i := 0; i < len(T); i++ {
		wmultiplicities[i] = expr.Col(constants.MultiplicityChunkName(wmultiplicity, i))
	}
	fsInputs := make([]expr.Expr, 3*len(T)+2*len(S))
	offset := 0
	copy(fsInputs, sIn)
	offset += len(S)
	copy(fsInputs[offset:], tIn)
	offset += len(T)
	copy(fsInputs[offset:], selS)
	offset += len(selS)
	copy(fsInputs[offset:], selT)
	offset += len(T)
	copy(fsInputs[offset:], wmultiplicities)
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 3. register logup for both parties
	gamma := expr.Challenge(_gamma)
	_logupT, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupS, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	logupT := make([]board.Column, len(T))
	logupS := make([]board.Column, len(S))
	for i, t := range T {
		_logupT = fmt.Sprintf("%s.%s_%s", t.Module, constants.LOGUP, _logupT)
		sMinusGamma := t.In.Sub(gamma)
		logupName := constants.LogupChunkName(_logupT, i)
		M := wmultiplicities[i].Mul(selT[i])
		builder.AddLogupStep(
			t.Module,
			sMinusGamma,
			M,
			logupName)
		logupT[i] = board.Column{Module: t.Module, In: expr.Col(logupName)}
	}
	for i, s := range S {
		_logupS = fmt.Sprintf("%s.%s_%s", s.Module, constants.LOGUP, _logupT)
		sMinusGamma := s.In.Sub(gamma)
		logupName := constants.LogupChunkName(_logupS, i)
		builder.AddLogupStep(
			s.Module,
			sMinusGamma,
			selS[i],
			logupName)
		logupS[i] = board.Column{Module: s.Module, In: expr.Col(logupName)}
	}

	// 4. Add logup equality check
	AddLogupEqualityCheck(builder, logupS, logupT)

	return nil
}

func CLookupUnionTuple(builder *board.Builder, selS, selT []expr.Expr, S, T []board.Table) error {

	refWidth := len(S[0].In)
	for _, s := range S {
		if len(s.In) != refWidth {
			return fmt.Errorf("inconsistent width, expected %d, got %d", refWidth, len(s.In))
		}
	}
	for _, t := range T {
		if len(t.In) != refWidth {
			return fmt.Errorf("inconsistent width, expected %d, got %d", refWidth, len(t.In))
		}
	}

	// 1. fold each S[i], each T[i] to reduce the case to LookupUnion
	fsInputs := make([]expr.Expr, 0, (len(S)+len(T))*len(S[0].In))
	for _, s := range S {
		fsInputs = append(fsInputs, s.In...)

	}
	for _, t := range T {
		fsInputs = append(fsInputs, t.In...)

	}
	fsInputs = append(fsInputs, selS...)
	fsInputs = append(fsInputs, selT...)
	_alpha, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _alpha)

	// 2. call LookupUnion on foldedS, foldedT
	foldedS := make([]board.Column, len(S))
	foldedT := make([]board.Column, len(T))
	alpha := expr.Challenge(_alpha)
	for i, s := range S {
		foldedS[i].In = expr.Fold(alpha, s.In)
		foldedS[i].Module = s.Module
	}
	for i, t := range T {
		foldedT[i].In = expr.Fold(alpha, t.In)
		foldedT[i].Module = t.Module
	}

	return CLookupUnion(builder, selS, selT, foldedS, foldedT)
}

// Lookup arguments that S ⊂ T
func Lookup(builder *board.Builder, S, T board.Column) error {
	return LookupUnion(builder, []board.Column{S}, []board.Column{T})
}

// LookupTuple lookup on table of width len(S)=len(T)
func LookupTuple(builder *board.Builder, S, T board.Table) error {
	if len(S.In) != len(T.In) {
		return fmt.Errorf("[LookupTuple] S and T must have equal size, got %d and %d", len(S.In), len(T.In))
	}
	return LookupUnionTuple(builder, []board.Table{S}, []board.Table{T})
}

func CLookup(builder *board.Builder, S, T board.Column, SelS, SelT expr.Expr) error {
	return CLookupUnion(builder, []expr.Expr{SelS}, []expr.Expr{SelT}, []board.Column{S}, []board.Column{T})
}

// Lookup arguments that S ⊂ T where S and T are tables
// CLookupTuple argues that { row(S) | SelS != 0 } is a subset of { row(T) | SelT != 0 }
// where row(.) denotes the tuple of all columns in a row. It folds the columns
// with a random challenge and delegates to CLookup.
func CLookupTuple(builder *board.Builder, S, T board.Table, selS, selT expr.Expr) error {
	return CLookupUnionTuple(builder, []expr.Expr{selS}, []expr.Expr{selT}, []board.Table{S}, []board.Table{T})
}
