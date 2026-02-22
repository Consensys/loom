// syntactic sugar to generate common useful constraints

package cs

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
)

type Constraint = sym.Expr

func GetLagrangeConstraint(ColumnToCheck string, entry int, value koalabear.Element) Constraint {
	lagrangeID := GetLagrangeID(entry)
	C := sym.NewVar(ColumnToCheck).Sub(sym.NewConst(value)).Mul(sym.NewVar(lagrangeID))
	return C
}

// GetGrandProductConstraint returns the constraint:
// RS*C2 - R*C1
func GetGrandProductConstraint(C1, C2 Constraint, R, RS string) Constraint {
	C := C2.Mul(sym.NewVar(RS)).Sub(C1.Mul(sym.NewVar(R)))
	return C
}

// GetProductConstraint returns the expression Π_i (ID[i] - challenge).
// The first occurrence of challenge uses NewVar (degree 1); subsequent ones use
// NewPlaceholder (degree 0), keeping the symbolic degree equal to len(ID).
func GetProductConstraint(ID []string, challenge string) Constraint {
	C := sym.NewVar(ID[0]).Sub(sym.NewVar(challenge))
	for i := 1; i < len(ID); i++ {
		C = C.Mul(sym.NewVar(ID[i]).Sub(sym.NewPlaceholder(challenge)))
	}
	return C
}

// GetFoldingRelation returns the constraint \Sigma_i \alpha^i Pi - R = 0
func GetFoldingRelation(IDs []string, challenge, R string) Constraint {
	var one koalabear.Element
	one.SetOne()
	C := sym.NewVar(IDs[0]).Mul(sym.NewConst(one))
	for i := 1; i < len(IDs); i++ {
		C = C.Add(sym.NewVar(IDs[i]).Mul(sym.NewPlaceholder(challenge).Pow(uint32(i))))
	}
	C = C.Sub(sym.NewVar(R))
	return C
}
