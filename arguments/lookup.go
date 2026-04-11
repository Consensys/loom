package arguments

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
)

type LookupConfig struct {
	Selector board.Input
}

type LookupOption func(lc *LookupConfig) error

func WithSelector(input board.Input) LookupOption {
	return func(lc *LookupConfig) error {
		lc.Selector = input
		return nil
	}
}

type RawLogupCtx struct{}

func RawLogup(builder *board.Builder, S board.Input) error {

	fsInputs := []expr.Expr{S.In}
	_gamma, err := RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	gamma := expr.Challenge(_gamma)
	_logupS, err := RandomString(10)
	if err != nil {
		return err
	}
	_logupS = fmt.Sprintf("%s_%s", constants.LOGUP, _logupS)
	sMinusGamma := S.In.Sub(gamma)
	builder.AddLogupStep(S.Module, sMinusGamma, expr.Const(koalabear.One()), _logupS)

	return nil
}

// Lookup arguments that S ⊂ T
func Lookup(builder *board.Builder, S, T board.Input) error {

	// 1. compute multiplicity
	multiplicity, err := RandomString(10)
	if err != nil {
		return err
	}
	multiplicity = fmt.Sprintf("Mult_%s", multiplicity)
	builder.AddCountMultiplicityStep(S.In, T.In, multiplicity)

	// 2. sample challenge
	fsInputs := []expr.Expr{S.In, T.In}
	fsInputs = append(fsInputs, expr.Col(multiplicity))
	_gamma, err := RandomString(10)
	if err != nil {
		return err
	}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 3. register lookup for both parties
	gamma := expr.Challenge(_gamma)
	_logupT, err := RandomString(10)
	if err != nil {
		return err
	}
	_logupS, err := RandomString(10)
	if err != nil {
		return err
	}
	_logupT = fmt.Sprintf("%s_%s", constants.LOGUP, _logupT)
	_logupS = fmt.Sprintf("%s_%s", constants.LOGUP, _logupS)
	{
		tMinusGamma := T.In.Sub(gamma)
		builder.AddLogupStep(T.Module, tMinusGamma, expr.Col(multiplicity), _logupT)
	}
	{
		sMinusGamma := S.In.Sub(gamma)
		builder.AddLogupStep(S.Module, sMinusGamma, expr.Const(koalabear.One()), _logupS)
	}

	// 4. if the inputs come from the same module, build the vanishing relation, else build a logup bus
	AddLogupEqualityCheck(builder, S.Module, T.Module, []string{_logupS}, []string{_logupT})

	return nil
}

// Lookup arguments that S ⊂ T where S and T are tables
func LookupTuple(builder *board.Builder, S, T []board.Input) error {

	if len(S) != len(T) {
		return fmt.Errorf("[LookupTuple] S and T must have equal size, got %d and %d", len(S), len(T))
	}

	// 1. sample a challenge
	_alpha, err := RandomString(10)
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
