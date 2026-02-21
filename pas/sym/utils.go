package sym

// Fold returns \Sigma_{i} v^iC[i].
// v can be any Expr (Var, Placeholder, etc.).
func Fold(v Expr, C []Expr) Expr {
	res := C[0]
	for i := 1; i < len(C); i++ {
		res = res.Add(C[i].Mul(v.Pow(uint32(i))))
	}
	return res
}
