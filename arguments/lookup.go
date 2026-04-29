package arguments

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
)

func CLookup(builder *board.Builder, S, T board.Input, SelS, SelT expr.Expr) error {

	// 1. compute multiplicity
	wmultiplicity, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	wmultiplicity = fmt.Sprintf("%s.Mult_%s", T.Module, wmultiplicity)
	builder.AddCountWeightedMultiplicityStep(S.In, T.In, SelS, wmultiplicity)

	// 2. sample challenge
	fsInputs := []expr.Expr{S.In, T.In, SelS, SelT}
	fsInputs = append(fsInputs, expr.Col(wmultiplicity))
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 3. register lookup for both parties
	gamma := expr.Challenge(_gamma)
	_logupT, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupS, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupT = fmt.Sprintf("%s.%s_%s", T.Module, constants.LOGUP, _logupT)
	_logupS = fmt.Sprintf("%s.%s_%s", S.Module, constants.LOGUP, _logupS)
	{
		tMinusGamma := T.In.Sub(gamma)
		builder.AddLogupStep(T.Module, tMinusGamma, expr.Col(wmultiplicity).Mul(SelT), _logupT)
	}
	{
		sMinusGamma := S.In.Sub(gamma)
		builder.AddLogupStep(S.Module, sMinusGamma, SelS, _logupS)
	}

	// 4. if the inputs come from the same module, build the vanishing relation, else build a logup bus
	logupS := expr.Col(_logupS)
	logupT := expr.Col(_logupT)
	AddLogupEqualityCheck(builder, S.Module, T.Module, []expr.Expr{logupS}, []expr.Expr{logupT})

	return nil
}

func Range(builder *board.Builder, S board.Input, bound uint64) error {

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
	T := board.Input{Module: rangeModuleName, In: expr.Col(constants.RangeColName(bound))}

	// 2 - add the lookup
	return Lookup(builder, S, T)
}

// Lookup arguments that S ⊂ T
func Lookup(builder *board.Builder, S, T board.Input) error {

	// 1. compute multiplicity
	multiplicity, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	multiplicity = fmt.Sprintf("%s.Mult_%s", T.Module, multiplicity)
	builder.AddCountMultiplicityStep(S.In, T.In, multiplicity)

	// 2. sample challenge
	fsInputs := []expr.Expr{S.In, T.In}
	fsInputs = append(fsInputs, expr.Col(multiplicity))
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 3. register lookup for both parties
	gamma := expr.Challenge(_gamma)
	_logupT, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupS, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupT = fmt.Sprintf("%s.%s_%s", T.Module, constants.LOGUP, _logupT)
	_logupS = fmt.Sprintf("%s.%s_%s", S.Module, constants.LOGUP, _logupS)
	{
		tMinusGamma := T.In.Sub(gamma)
		builder.AddLogupStep(T.Module, tMinusGamma, expr.Col(multiplicity), _logupT)
	}
	{
		sMinusGamma := S.In.Sub(gamma)
		builder.AddLogupStep(S.Module, sMinusGamma, expr.Const(koalabear.One()), _logupS)
	}

	// 4. if the inputs come from the same module, build the vanishing relation, else build a logup bus
	logupS := expr.Col(_logupS)
	logupT := expr.Col(_logupT)
	AddLogupEqualityCheck(builder, S.Module, T.Module, []expr.Expr{logupS}, []expr.Expr{logupT})

	return nil
}

// Lookup arguments that S ⊂ T where S and T are tables
// CLookupTuple argues that { row(S) | SelS != 0 } is a subset of { row(T) | SelT != 0 }
// where row(.) denotes the tuple of all columns in a row. It folds the columns
// with a random challenge and delegates to CLookup.
func CLookupTuple(builder *board.Builder, S, T []board.Input, selS, selT expr.Expr) error {
	if len(S) != len(T) {
		return fmt.Errorf("[CLookupTuple] S and T must have equal size, got %d and %d", len(S), len(T))
	}

	// 1. sample a folding challenge
	_alpha, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	fsInputs := make([]expr.Expr, 0, len(S)+len(T))
	for _, s := range S {
		fsInputs = append(fsInputs, s.In)
	}
	for _, t := range T {
		fsInputs = append(fsInputs, t.In)
	}
	builder.AddFiatShamirStep(fsInputs, _alpha)

	// 2. fold columns — selectors apply to rows so they pass through unchanged
	exprS := make([]expr.Expr, len(S))
	exprT := make([]expr.Expr, len(T))
	for i := range S {
		exprS[i] = S[i].In
		exprT[i] = T[i].In
	}
	alpha := expr.Challenge(_alpha)
	inputS := board.Input{Module: S[0].Module, In: expr.Fold(alpha, exprS)}
	inputT := board.Input{Module: T[0].Module, In: expr.Fold(alpha, exprT)}

	return CLookup(builder, inputS, inputT, selS, selT)
}

func LookupTuple(builder *board.Builder, S, T []board.Input) error {

	if len(S) != len(T) {
		return fmt.Errorf("[LookupTuple] S and T must have equal size, got %d and %d", len(S), len(T))
	}

	// 1. sample a challenge
	_alpha, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	fsInputs := []expr.Expr{}
	for _, s := range S {
		fsInputs = append(fsInputs, s.In)
	}
	for _, t := range T {
		fsInputs = append(fsInputs, t.In)
	}
	builder.AddFiatShamirStep(fsInputs, _alpha)

	// 2. fold the inputs
	exprS := make([]expr.Expr, len(S))
	exprT := make([]expr.Expr, len(T))
	for i := 0; i < len(S); i++ {
		exprS[i] = S[i].In
		exprT[i] = T[i].In
	}
	alpha := expr.Challenge(_alpha)
	foldedS := expr.Fold(alpha, exprS)
	foldedT := expr.Fold(alpha, exprT)

	// 3. call 1 single column lookup
	moduleS := S[0].Module
	moduleT := T[0].Module
	inputS := board.Input{Module: moduleS, In: foldedS}
	inputT := board.Input{Module: moduleT, In: foldedT}
	Lookup(builder, inputS, inputT)

	return nil
}
