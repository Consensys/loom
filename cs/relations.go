package cs

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
)

func GetFoldingRelation(IDs []string, challenge, R string) Constraint {
	var one koalabear.Element
	one.SetOne()
	C := sym.NewVar(IDs[0]).Mul(sym.NewConst(one))
	for i := 1; i < len(IDs); i++ {
		C = C.Add(sym.NewVar(IDs[i]).Mul(sym.NewPlaceholder(challenge).Pow(uint32(i)))) // <- sym.NewPlaceholder(alpha) guarantees that powers of alpha are of degree 0
	}
	C = C.Sub(sym.NewVar(R))
	return C
}

// GetGrandProductRelation returns the relation:
// RS*C2 - R*C1
func GetGrandProductRelation(C1, C2 Constraint, R, RS string) Constraint {
	C := C2.Mul(sym.NewVar(RS)).Sub(C1.Mul(sym.NewVar(R)))
	return C
}

// GetProductRelation returns the relation \Pi (ID-challenge)
func GetProductRelation(ID []string, challenge string) Constraint {
	C := sym.NewVar(ID[0]).Sub(sym.NewVar(challenge))
	for i := 1; i < len(ID); i++ {
		C = C.Mul(sym.NewVar(ID[i]).Sub(sym.NewPlaceholder(challenge))) // <- sym.NewPlaceholder(alpha) guarantees that powers of alpha are of degree 0
	}
	return C
}
