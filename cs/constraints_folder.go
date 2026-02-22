package cs

import (
	"fmt"

	"github.com/consensys/iop/pas/sym"
)

// foldConstraints folds all the constraints in S.CachedConstraints with challenge. Record the folded
// constraint (i.e. store it in S.Constraint)
func foldConstraints(S *System, challenge Challenge, inCache bool) error {

	// get the constraints Ci
	if inCache {
		if len(S.CachedConstraints) == 0 {
			return fmt.Errorf("no cached constraints to fold")
		}
	} else {
		if len(S.Constraints) == 0 {
			return fmt.Errorf("no cached constraints to fold")
		}
	}

	// create a constraint C := \Sum_i challenge.Name^i * Ci
	var C Constraint
	if inCache {
		C = S.CachedConstraints[0]
		for i := 1; i < len(S.CachedConstraints); i++ {
			C = C.Add(sym.NewPlaceholder(challenge.Name).Pow(uint32(i)).Mul(S.CachedConstraints[i]))
		}
		S.CachedConstraints = nil
	} else {
		C = S.Constraints[0]
		for i := 1; i < len(S.Constraints); i++ {
			C = C.Add(sym.NewPlaceholder(challenge.Name).Pow(uint32(i)).Mul(S.Constraints[i]))
		}
		S.Constraints = nil
	}

	// store C in S.Constraints
	S.Constraints = append(S.Constraints, C)

	return nil
}

func FoldCachedConstraints(S *System, challenge Challenge) error {
	if err := ensureChallengeInTrace(S, challenge); err != nil {
		return err
	}
	return foldConstraints(S, challenge, true)
}

// Fold folds all the constraints in S.CachedConstraints with challenge. Record the folded
// constraint (i.e. store it in S.Constraint)
func FoldConstraints(S *System, challenge Challenge) error {
	return foldConstraints(S, challenge, false)
}
