package expr

import "github.com/consensys/gnark-crypto/field/koalabear"

// Fold returns \Sigma_{i} v^iC[i].
// v can be any Expr (Var, Placeholder, etc.).
// Returns the zero constant when C is empty.
func Fold(v Expr, C []Expr) Expr {
	if len(C) == 0 {
		return Const(koalabear.Element{})
	}
	res := C[0]
	for i := 1; i < len(C); i++ {
		res = res.Add(C[i].Mul(v.Pow(uint32(i))))
	}
	return res
}
