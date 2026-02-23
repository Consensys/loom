// syntactic sugar to generate common useful constraints

package system

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
)

type Constraint = sym.Expr

// AddConstraint populates the constraints with C
func AddConstraint(S *System, C Constraint, opts ...IOPOption) error {

	// build the config file
	var config IOPConfig
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C)
	} else {
		S.Constraints = append(S.Constraints, C)
	}
	return nil
}

// NewVirtualColumn registers a new virtual column, that is a column that can be referenced, and whose content is not computed
// yet, but expressed as a function of other columns.
func NewVirtualColumn(S *System, ID string, E sym.Expr) error {
	if _, ok := S.VirtualColumns[ID]; ok {
		return fmt.Errorf("virtual column %s already referenced", ID)
	}
	S.VirtualColumns[ID] = E
	return nil
}

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

	// create a constraint C := \Sum_i challenge.Nameⁱ * Ci
	var C Constraint
	if inCache {
		C = S.CachedConstraints[0]
		for i := 1; i < len(S.CachedConstraints); i++ {
			C = C.Add(sym.NewPlaceholder(challenge.Name).Pow(uint32(i)).Mul(S.CachedConstraints[i]))
		}
		S.CachedConstraints = []Constraint{}
	} else {
		C = S.Constraints[0]
		for i := 1; i < len(S.Constraints); i++ {
			C = C.Add(sym.NewPlaceholder(challenge.Name).Pow(uint32(i)).Mul(S.Constraints[i]))
		}
		S.Constraints = []Constraint{}
	}

	// store C in S.Constraints
	S.Constraints = append(S.Constraints, C)

	return nil
}

// FlushCache put the cached constraints in the active constraints registery and empty the cache
func FlushCache(S *System) {
	S.Constraints = append(S.Constraints, S.CachedConstraints...)
	S.CachedConstraints = []Constraint{}
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

func GetLagrangeConstraint(ColumnToCheck string, entry int, value koalabear.Element) Constraint {
	lagrangeID := GetLagrangeID(entry)
	C := sym.NewVar(ColumnToCheck).Sub(sym.NewConst(value)).Mul(sym.NewVar(lagrangeID))
	return C
}

// GetGrandProductConstraint returns the constraint:
// RS*C2 - R*C1
func GetGrandProductConstraint(E1, E2 Constraint, R, RS string) Constraint {
	C := E2.Mul(sym.NewVar(RS)).Sub(E1.Mul(sym.NewVar(R)))
	return C
}

// GetProductExpression returns the expression Π_i (E[i] - challenge).
// The first occurrence of challenge uses NewVar (degree 1); subsequent ones use
// NewPlaceholder (degree 0), keeping the symbolic degree equal to len(ID).
func GetProductExpression(E []sym.Expr, challenge string) Constraint {
	C := E[0].Sub(sym.NewPlaceholder(challenge))
	for i := 1; i < len(E); i++ {
		C = C.Mul(E[i].Sub(sym.NewPlaceholder(challenge)))
	}
	return C
}

// GetFoldingExpression returns the expression Σ_i αⁱ Pi
// where challenge is registered as a placeholder
func GetFoldingExpression(IDs []string, challenge, R string) Constraint {
	var one koalabear.Element
	one.SetOne()
	C := sym.NewVar(IDs[0]).Mul(sym.NewConst(one))
	for i := 1; i < len(IDs); i++ {
		C = C.Add(sym.NewVar(IDs[i]).Mul(sym.NewPlaceholder(challenge).Pow(uint32(i))))
	}
	return C
}
