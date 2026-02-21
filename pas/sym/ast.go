package sym

import (
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

const NegInf = math.MinInt

type Expr interface {
	Degree() int
	NumVars() int
	String() string
	Add(Expr) Expr
	Sub(Expr) Expr
	Mul(Expr) Expr
	Pow(uint32) Expr

	// return a slice containing the names of the leaves of Expr
	// /!\ contains duplicates, use RemoveDuplicates to clean the slice
	Leaves() []string

	// recurse through expr, until an Expr (call it E) of degree <= deg is found.
	// When E is found, remove E from expr and replace this subexpression with NewVar(E.String())
	// Return E.
	Prune(deg int) Expr
}

type Placeholder struct {
	Name string
}

// Acts as a constant, but with an identifier, so it can be plugged in an expression. Its degree is zero.
func NewPlaceholder(name string) *Placeholder {
	return &Placeholder{Name: name}
}

func (v Placeholder) Degree() int    { return 0 } // Placeholder acts as a constant
func (v Placeholder) String() string { return v.Name }

func (v Placeholder) NumVars() int {
	// A single variable contributes 1 to the count
	// The actual index assignment happens during Convert()
	vars := make(map[string]bool)
	v.collectVars(vars)
	return len(vars)
}

func (v Placeholder) collectVars(vars map[string]bool) {
	vars[v.Name] = true
}

type Var struct {
	Name string
}

func NewVar(name string) *Var {
	return &Var{Name: name}
}

func (v Var) Degree() int    { return 1 }
func (v Var) String() string { return v.Name }

func (v Var) NumVars() int {
	// A single variable contributes 1 to the count
	// The actual index assignment happens during Convert()
	vars := make(map[string]bool)
	v.collectVars(vars)
	return len(vars)
}

func (v Var) collectVars(vars map[string]bool) {
	vars[v.Name] = true
}

type Const struct {
	Value koalabear.Element
}

func NewConst(value koalabear.Element) *Const {
	return &Const{Value: value}
}

func (c Const) Degree() int {
	if c.Value.IsZero() {
		return math.MinInt // negative infinity
	}
	return 0
}

func (c Const) String() string { return c.Value.String() }

func (c Const) NumVars() int {
	return 0 // Constants don't use any variables
}

func (c Const) collectVars(vars map[string]bool) {
	// Constants don't contribute any variables
}

type Add struct {
	Left, Right Expr
}

func (a Add) Degree() int {
	leftDegree := a.Left.Degree()
	rightDegree := a.Right.Degree()
	return max(leftDegree, rightDegree)
}

func (a Add) String() string {
	return "(" + a.Left.String() + " + " + a.Right.String() + ")"
}

func (a Add) NumVars() int {
	vars := make(map[string]bool)
	a.collectVars(vars)
	return len(vars)
}

func (a Add) collectVars(vars map[string]bool) {
	if collector, ok := a.Left.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
	if collector, ok := a.Right.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
}

type Sub struct {
	Left, Right Expr
}

func (s Sub) Degree() int {
	leftDegree := s.Left.Degree()
	rightDegree := s.Right.Degree()
	return max(leftDegree, rightDegree)
}

func (s Sub) String() string {
	return "(" + s.Left.String() + " - " + s.Right.String() + ")"
}

func (s Sub) NumVars() int {
	vars := make(map[string]bool)
	s.collectVars(vars)
	return len(vars)
}

func (s Sub) collectVars(vars map[string]bool) {
	if collector, ok := s.Left.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
	if collector, ok := s.Right.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
}

type Mul struct {
	Left, Right Expr
}

func (m Mul) Degree() int {
	leftDegree := m.Left.Degree()
	rightDegree := m.Right.Degree()
	return leftDegree + rightDegree
}

func (m Mul) String() string {
	return "(" + m.Left.String() + " * " + m.Right.String() + ")"
}

func (m Mul) NumVars() int {
	vars := make(map[string]bool)
	m.collectVars(vars)
	return len(vars)
}

func (m Mul) collectVars(vars map[string]bool) {
	if collector, ok := m.Left.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
	if collector, ok := m.Right.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
}

type Pow struct {
	Base Expr
	Exp  uint32
}

func (p Pow) Degree() int {
	return p.Base.Degree() * int(p.Exp)
}

func (p Pow) String() string {
	return "(" + p.Base.String() + " ^ " + fmt.Sprintf("%d", p.Exp) + ")"
}

func (p Pow) NumVars() int {
	vars := make(map[string]bool)
	p.collectVars(vars)
	return len(vars)
}

func (p Pow) collectVars(vars map[string]bool) {
	if collector, ok := p.Base.(interface{ collectVars(map[string]bool) }); ok {
		collector.collectVars(vars)
	}
}

func (v *Var) Add(e Expr) Expr { return &Add{v, e} }
func (v *Var) Sub(e Expr) Expr { return &Sub{v, e} }
func (v *Var) Mul(e Expr) Expr { return &Mul{v, e} }
func (v *Var) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(v, n)
	}
	return &Pow{v, n}
}

func (c *Placeholder) Add(e Expr) Expr { return &Add{c, e} }
func (c *Placeholder) Sub(e Expr) Expr { return &Sub{c, e} }
func (c *Placeholder) Mul(e Expr) Expr { return &Mul{c, e} }
func (c *Placeholder) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(c, n)
	}
	return &Pow{c, n}
}

func (c *Const) Add(e Expr) Expr { return &Add{c, e} }
func (c *Const) Sub(e Expr) Expr { return &Sub{c, e} }
func (c *Const) Mul(e Expr) Expr { return &Mul{c, e} }
func (c *Const) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(c, n)
	}
	return &Pow{c, n}
}

func (a *Add) Add(e Expr) Expr { return &Add{a, e} }
func (a *Add) Sub(e Expr) Expr { return &Sub{a, e} }
func (a *Add) Mul(e Expr) Expr { return &Mul{a, e} }
func (a *Add) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(a, n)
	}
	return &Pow{a, n}
}

func (s *Sub) Add(e Expr) Expr { return &Add{s, e} }
func (s *Sub) Sub(e Expr) Expr { return &Sub{s, e} }
func (s *Sub) Mul(e Expr) Expr { return &Mul{s, e} }
func (s *Sub) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(s, n)
	}
	return &Pow{s, n}
}

func (m *Mul) Add(e Expr) Expr { return &Add{m, e} }
func (m *Mul) Sub(e Expr) Expr { return &Sub{m, e} }
func (m *Mul) Mul(e Expr) Expr { return &Mul{m, e} }
func (m *Mul) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(m, n)
	}
	return &Pow{m, n}
}

func (p *Pow) Add(e Expr) Expr { return &Add{p, e} }
func (p *Pow) Sub(e Expr) Expr { return &Sub{p, e} }
func (p *Pow) Mul(e Expr) Expr { return &Mul{p, e} }
func (p *Pow) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(p, n)
	}
	return &Pow{p, n}
}

func Sum(exprs ...Expr) Expr {
	if len(exprs) == 0 {
		panic("empty sum")
	}
	result := exprs[0]
	for i := 1; i < len(exprs); i++ {
		result = &Add{result, exprs[i]}
	}
	return result
}

func Prod(exprs ...Expr) Expr {
	if len(exprs) == 0 {
		panic("empty product")
	}
	result := exprs[0]
	for i := 1; i < len(exprs); i++ {
		result = &Mul{result, exprs[i]}
	}
	return result
}

// isPrunable returns true if e is a composite sub-expression (not a bare Var, Placeholder, or Const)
// that is eligible to be extracted into a new intermediate polynomial.
func isPrunable(e Expr) bool {
	switch e.(type) {
	case *Var, *Const, *Placeholder:
		return false
	}
	return true
}

// pruneSearch recurses through expr looking for a composite child node E with degree <= deg.
// When found, E is replaced in-place with NewVar(E.String()) and E is returned.
// Var and Const children are skipped (they are already leaves; replacing them is a no-op).
// Returns nil if no such sub-expression is found.
func pruneSearch(expr Expr, deg int) Expr {
	switch e := expr.(type) {
	case *Var, *Const:
		return nil
	case *Add:
		if isPrunable(e.Left) && e.Left.Degree() <= deg {
			found := e.Left
			e.Left = NewVar(found.String())
			return found
		}
		if isPrunable(e.Right) && e.Right.Degree() <= deg {
			found := e.Right
			e.Right = NewVar(found.String())
			return found
		}
		if r := pruneSearch(e.Left, deg); r != nil {
			return r
		}
		return pruneSearch(e.Right, deg)
	case *Sub:
		if isPrunable(e.Left) && e.Left.Degree() <= deg {
			found := e.Left
			e.Left = NewVar(found.String())
			return found
		}
		if isPrunable(e.Right) && e.Right.Degree() <= deg {
			found := e.Right
			e.Right = NewVar(found.String())
			return found
		}
		if r := pruneSearch(e.Left, deg); r != nil {
			return r
		}
		return pruneSearch(e.Right, deg)
	case *Mul:
		if isPrunable(e.Left) && e.Left.Degree() <= deg {
			found := e.Left
			e.Left = NewVar(found.String())
			return found
		}
		if isPrunable(e.Right) && e.Right.Degree() <= deg {
			found := e.Right
			e.Right = NewVar(found.String())
			return found
		}
		if r := pruneSearch(e.Left, deg); r != nil {
			return r
		}
		return pruneSearch(e.Right, deg)
	case *Pow:
		if isPrunable(e.Base) && e.Base.Degree() <= deg {
			found := e.Base
			e.Base = NewVar(found.String())
			return found
		}
		return pruneSearch(e.Base, deg)
	}
	return nil
}

func (c *Placeholder) Prune(deg int) Expr { return pruneSearch(c, deg) }
func (v *Var) Prune(deg int) Expr         { return pruneSearch(v, deg) }
func (c *Const) Prune(deg int) Expr       { return pruneSearch(c, deg) }
func (a *Add) Prune(deg int) Expr         { return pruneSearch(a, deg) }
func (s *Sub) Prune(deg int) Expr         { return pruneSearch(s, deg) }
func (m *Mul) Prune(deg int) Expr         { return pruneSearch(m, deg) }
func (p *Pow) Prune(deg int) Expr         { return pruneSearch(p, deg) }

func (c *Placeholder) Leaves() []string { return []string{c.String()} }
func (v *Var) Leaves() []string         { return []string{v.Name} }
func (c *Const) Leaves() []string       { return []string{c.String()} }
func (a *Add) Leaves() []string         { return append(a.Left.Leaves(), a.Right.Leaves()...) }
func (s *Sub) Leaves() []string         { return append(s.Left.Leaves(), s.Right.Leaves()...) }
func (m *Mul) Leaves() []string         { return append(m.Left.Leaves(), m.Right.Leaves()...) }
func (p *Pow) Leaves() []string         { return p.Base.Leaves() }

// squareAndMultiply builds an Expr tree for base^exp using binary exponentiation.
// exp must be >= 3.
func squareAndMultiply(base Expr, exp uint32) Expr {
	// Collect the bits of exp from LSB to MSB, then reverse to get MSB-first.
	var binaryBits []bool
	for n := exp; n > 0; n >>= 1 {
		binaryBits = append(binaryBits, n&1 == 1)
	}
	for i, j := 0, len(binaryBits)-1; i < j; i, j = i+1, j-1 {
		binaryBits[i], binaryBits[j] = binaryBits[j], binaryBits[i]
	}

	// The MSB is always 1; start with result = base and process the remaining bits.
	result := base
	for i := 1; i < len(binaryBits); i++ {
		result = &Mul{result, result} // square
		if binaryBits[i] {
			result = &Mul{result, base} // multiply
		}
	}
	return result
}

// RemoveDuplicates removes duplicates in input
func RemoveDuplicates(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, value := range input {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}

	return result
}
