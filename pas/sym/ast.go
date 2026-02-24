package sym

import (
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

const NegInf = math.MinInt

// The type of the leaves:
// * Var
// * ComputableColumn
// * Challenge
// is used at the protocol/ level, because those types encode the status of a column -> is it a column that needs to be committed ?
// Should we use this column for Fiat Shamir ? Is it a Challenge sent by the verifier (so not a column we need to commit)?
// All this info is stored directly in the AST describing the constraint.
//
// It is not used as the system/ level, because at this level there is no verifier-prover interaction. We just have a trace,
// and mathematical formulas encoding the constraints that the trace must fulfil.

type Expr interface {
	Degree() int
	NumVars() int
	String() string
	Add(Expr) Expr
	Sub(Expr) Expr
	Mul(Expr) Expr
	Pow(uint32) Expr

	// return a slice containing the names of the leaves of Expr, except the constants
	// /!\ contains duplicates, use RemoveDuplicates to clean the slice
	Leaves() []string

	// return a slice containing the names of the leaves of Expr which are of type Var
	// /!\ contains duplicates, use RemoveDuplicates to clean the slice
	Vars() []string

	// return a slice containing the names of the leaves of Expr which are of type ComputableColumn
	// /!\ contains duplicates, use RemoveDuplicates to clean the slice
	ComputableColumns() []string

	// ReplaceLeafByExpression finds all occurence of leaf in the tree and replace it with e
	ReplaceLeafByExpression(leaf string, e Expr) Expr

	// recurse through expr, until an Expr (call it E) of degree <= deg is found.
	// When E is found, remove E from expr and replace this subexpression with NewVar(E.String())
	// Return E.
	Prune(deg int) Expr
}

// ComputableColumn leaf used to store columns which are not committed to, because they can be recomputed by the verifier
// because their values can be retrieved with a formula, for instance Lagrange columns. Its degree is one.
type ComputableColumn struct {
	Name string
}

func NewComputableColumn(name string) *ComputableColumn {
	return &ComputableColumn{Name: name}
}

func (v *ComputableColumn) Degree() int    { return 1 }
func (v *ComputableColumn) String() string { return v.Name }

func (v *ComputableColumn) NumVars() int {
	vars := make(map[string]bool)
	v.collectVars(vars)
	return len(vars)
}

func (v *ComputableColumn) collectVars(vars map[string]bool) {
	vars[v.Name] = true
}

func (v *ComputableColumn) Add(e Expr) Expr { return &Add{v, e} }
func (v *ComputableColumn) Sub(e Expr) Expr { return &Sub{v, e} }
func (v *ComputableColumn) Mul(e Expr) Expr { return &Mul{v, e} }
func (v *ComputableColumn) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(v, n)
	}
	return &Pow{v, n}
}

func (v *ComputableColumn) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	if v.Name == leaf {
		return e
	}
	return v
}

func (v *ComputableColumn) Prune(deg int) Expr { return pruneSearch(v, deg) }

// Leaf storing a challenge
type Challenge struct {
	Name string
}

// Acts as a constant, but with an identifier, so it can be plugged in an expression. Its degree is zero. It is used to stored the
// challenges in an algebraic expression
func NewChallenge(name string) *Challenge {
	return &Challenge{Name: name}
}

func (v Challenge) Degree() int    { return 0 } // Challenge acts as a constant
func (v Challenge) String() string { return v.Name }

func (v Challenge) NumVars() int {
	// A single variable contributes 1 to the count
	// The actual index assignment happens during Convert()
	vars := make(map[string]bool)
	v.collectVars(vars)
	return len(vars)
}

func (v Challenge) collectVars(vars map[string]bool) {
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

func (c *Challenge) Add(e Expr) Expr { return &Add{c, e} }
func (c *Challenge) Sub(e Expr) Expr { return &Sub{c, e} }
func (c *Challenge) Mul(e Expr) Expr { return &Mul{c, e} }
func (c *Challenge) Pow(n uint32) Expr {
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

// isPrunable returns true if e is a composite sub-expression (not a bare leaf or Const)
// that is eligible to be extracted into a new intermediate polynomial.
func isPrunable(e Expr) bool {
	switch e.(type) {
	case *Var, *Const, *Challenge, *ComputableColumn:
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
	case *Var, *Const, *ComputableColumn:
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

func (c *Challenge) Prune(deg int) Expr { return pruneSearch(c, deg) }
func (v *Var) Prune(deg int) Expr       { return pruneSearch(v, deg) }
func (c *Const) Prune(deg int) Expr     { return pruneSearch(c, deg) }
func (a *Add) Prune(deg int) Expr       { return pruneSearch(a, deg) }
func (s *Sub) Prune(deg int) Expr       { return pruneSearch(s, deg) }
func (m *Mul) Prune(deg int) Expr       { return pruneSearch(m, deg) }
func (p *Pow) Prune(deg int) Expr       { return pruneSearch(p, deg) }

func (v *ComputableColumn) Leaves() []string { return []string{v.Name} }
func (c *Challenge) Leaves() []string        { return []string{c.String()} }
func (v *Var) Leaves() []string              { return []string{v.Name} }
func (c *Const) Leaves() []string            { return []string{} }
func (a *Add) Leaves() []string              { return append(a.Left.Leaves(), a.Right.Leaves()...) }
func (s *Sub) Leaves() []string              { return append(s.Left.Leaves(), s.Right.Leaves()...) }
func (m *Mul) Leaves() []string              { return append(m.Left.Leaves(), m.Right.Leaves()...) }
func (p *Pow) Leaves() []string              { return p.Base.Leaves() }

func (c *Challenge) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	if c.Name == leaf {
		return e
	} else {
		return c
	}
}
func (v *Var) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	if v.Name == leaf {
		return e
	} else {
		return v
	}
}
func (c *Const) ReplaceLeafByExpression(leaf string, e Expr) Expr { return c }
func (a *Add) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	return &Add{a.Left.ReplaceLeafByExpression(leaf, e), a.Right.ReplaceLeafByExpression(leaf, e)}
}
func (s *Sub) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	return &Sub{s.Left.ReplaceLeafByExpression(leaf, e), s.Right.ReplaceLeafByExpression(leaf, e)}
}
func (m *Mul) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	return &Mul{m.Left.ReplaceLeafByExpression(leaf, e), m.Right.ReplaceLeafByExpression(leaf, e)}
}
func (p *Pow) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	return &Pow{p.Base.ReplaceLeafByExpression(leaf, e), p.Exp}
}

func (v *ComputableColumn) Vars() []string { return []string{v.Name} }
func (c *Challenge) Vars() []string        { return []string{} }
func (v *Var) Vars() []string              { return []string{v.String()} }
func (c *Const) Vars() []string            { return []string{} }
func (a *Add) Vars() []string {
	return append(a.Left.Vars(), a.Right.Vars()...)
}
func (s *Sub) Vars() []string {
	return append(s.Left.Vars(), s.Right.Vars()...)
}
func (m *Mul) Vars() []string {
	return append(m.Left.Vars(), m.Right.Vars()...)
}
func (p *Pow) Vars() []string { return p.Base.Vars() }

func (v *ComputableColumn) ComputableColumns() []string { return []string{v.Name} }
func (c *Challenge) ComputableColumns() []string        { return []string{} }
func (v *Var) ComputableColumns() []string              { return []string{} }
func (c *Const) ComputableColumns() []string            { return []string{} }
func (a *Add) ComputableColumns() []string {
	return append(a.Left.ComputableColumns(), a.Right.ComputableColumns()...)
}
func (s *Sub) ComputableColumns() []string {
	return append(s.Left.ComputableColumns(), s.Right.ComputableColumns()...)
}
func (m *Mul) ComputableColumns() []string {
	return append(m.Left.ComputableColumns(), m.Right.ComputableColumns()...)
}
func (p *Pow) ComputableColumns() []string { return p.Base.ComputableColumns() }

// Clone returns a deep copy of the expression tree with no shared nodes.
//
// fix from an error originally found in TestPrune. Without Clone some nodes share the same objects,
// resulting in a DAG and not a tree
//
// ================ claude log ================
// Root cause: squareAndMultiply built a DAG instead of a tree. The line
//   result = &Mul{result, result} made both Left and Right of the new Mul
//   point to the same object. For (x0+x1)^8:
// M3.Left === M3.Right === M2
//   M2.Left === M2.Right === M1   ← shared!
//   M1.Left === M1.Right === Add{x0,x1}

//   When Prune(2) found M1 (degree 2) inside M2.Left and replaced it in-place
//    with a Var, it also silently modified M2.Right (same pointer). So degree
//    dropped from 8 → 6 instead of 8 → 7.

// Fix: Added a Clone(Expr) Expr deep-copy function and changed
// squareAndMultiply to clone the right child on every square step (result =
//
//	&Mul{result, Clone(result)}) and clone base on every multiply step. This
//	ensures every node in the tree is a distinct object, so in-place
//
// mutations like Prune only affect the intended subtree
// ================================================
func Clone(e Expr) Expr {
	switch v := e.(type) {
	case *Var:
		return &Var{Name: v.Name}
	case *Const:
		c := *v
		return &c
	case *Challenge:
		return &Challenge{Name: v.Name}
	case *ComputableColumn:
		return &ComputableColumn{Name: v.Name}
	case *Add:
		return &Add{Left: Clone(v.Left), Right: Clone(v.Right)}
	case *Sub:
		return &Sub{Left: Clone(v.Left), Right: Clone(v.Right)}
	case *Mul:
		return &Mul{Left: Clone(v.Left), Right: Clone(v.Right)}
	case *Pow:
		return &Pow{Base: Clone(v.Base), Exp: v.Exp}
	}
	panic("Clone: unknown Expr type")
}

// squareAndMultiply builds an Expr tree for base^exp using binary exponentiation.
// exp must be >= 3.
// Each node in the tree is a distinct object (no shared pointers) so that
// in-place transformations such as Prune work correctly on the tree.
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
	// Clone the right child on every squaring step so that Left and Right are always
	// distinct objects — otherwise Prune (which rewrites nodes in-place) would
	// simultaneously modify both sides of a Mul when it modifies a shared subtree.
	result := base
	for i := 1; i < len(binaryBits); i++ {
		result = &Mul{result, Clone(result)} // square
		if binaryBits[i] {
			result = &Mul{result, Clone(base)} // multiply
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
