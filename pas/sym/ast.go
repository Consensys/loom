package sym

import (
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

const NegInf = math.MinInt

type LeafType int

const (
	CommittedColumn LeafType = iota
	ShiftedColumn
	ComputableColumn
	Challenge
	Const
)

type Leaf struct {
	Type  LeafType
	Idx   int // used for EvalPointWise, as a lookup to avoid maps
	Shift int
	Name  string
	Value koalabear.Element // only set for Const type
}

// Config useful for querying the leaves
type Config struct {
	WoCommittedColumns  bool
	WoComputableColumns bool
	WoShiftedColumns    bool
	WoChallenges        bool
}

type Option func(*Config)

// Leaves() doesnt return the ShiftedColumns
func WithoutShiftedColumns() Option {
	return func(c *Config) {
		c.WoShiftedColumns = true
	}
}

// Leaves() doesnt return the CommittedColumns
func WithoutCommittedColumns() Option {
	return func(c *Config) {
		c.WoCommittedColumns = true
	}
}

// Leaves() doesnt return the ComputableColumns
func WithoutComputableColumns() Option {
	return func(c *Config) {
		c.WoComputableColumns = true
	}
}

// Leaves() doesnt return the Challenge
func WithoutChallenges() Option {
	return func(c *Config) {
		c.WoChallenges = true
	}
}

func NewConfig(opts ...Option) Config {
	var res Config
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

var OnlyChallenges = []Option{WithoutComputableColumns(), WithoutCommittedColumns(), WithoutShiftedColumns()}
var OnlyCommittedColumns = []Option{WithoutComputableColumns(), WithoutChallenges(), WithoutShiftedColumns()}
var OnlyShiftedColumns = []Option{WithoutComputableColumns(), WithoutChallenges(), WithoutCommittedColumns()}

// The LeafType encodes the status of a column at the protocol level:
//   - CommittedColumn: the prover commits to this column
//   - ComputableColumn: recomputable by the verifier (e.g. Lagrange basis columns)
//   - Challenge: a Fiat-Shamir challenge (degree 0)
//   - ShiftedColumn: a column evaluated at a shifted point P(ω^shift·X)
//   - Const: a constant field element (degree 0)

type Expr interface {
	Degree() int
	String() string
	Add(Expr) Expr
	Sub(Expr) Expr
	Mul(Expr) Expr
	Pow(uint32) Expr

	Leaves(config Config) []string

	// LeavesFull returns every non-Const Leaf in the expression tree.
	LeavesFull(config Config) []*Leaf

	// ReplaceLeafByExpression finds all occurence of leaf in the tree and replace it with e
	ReplaceLeafByExpression(leaf string, e Expr) Expr

	// recurse through expr, until an Expr (call it E) of degree <= deg is found.
	// When E is found, remove E from expr and replace this subexpression with NewCommittedColumn(E.String())
	// Return E.
	Prune(deg int) Expr

	// EvaluateWEvaluateWithIdx substitues each leaf idx with vals[idx] and returns the result.
	// Panics if idx out of bound
	EvaluateWithIdx(vals []koalabear.Element) koalabear.Element

	// Evaluate substitutes each leaf name with the corresponding field element
	// from vals and returns the result. Panics if a required name is absent.
	Evaluate(vals map[string]koalabear.Element) koalabear.Element
}

func NewCommittedColumn(name string) *Leaf {
	return &Leaf{Type: CommittedColumn, Name: name}
}

func NewShiftedColumn(name string, shift int) *Leaf {
	return &Leaf{Type: ShiftedColumn, Shift: shift, Name: name}
}

func NewComputableColumn(name string) *Leaf {
	return &Leaf{Type: ComputableColumn, Name: name}
}

func NewChallenge(name string) *Leaf {
	return &Leaf{Type: Challenge, Name: name}
}

func NewConst(value koalabear.Element) *Leaf {
	return &Leaf{Type: Const, Value: value}
}

func (l *Leaf) String() string {
	switch l.Type {
	case ShiftedColumn:
		return fmt.Sprintf("%s_shift_%d", l.Name, l.Shift)
	case Const:
		return l.Value.String()
	default:
		return l.Name
	}
}

func (l *Leaf) Degree() int {
	switch l.Type {
	case Const:
		if l.Value.IsZero() {
			return NegInf
		}
		return 0
	case Challenge:
		return 0
	default: // CommittedColumn, ShiftedColumn, ComputableColumn
		return 1
	}
}

func (l *Leaf) Add(e Expr) Expr { return &Add{l, e} }
func (l *Leaf) Sub(e Expr) Expr { return &Sub{l, e} }
func (l *Leaf) Mul(e Expr) Expr { return &Mul{l, e} }
func (l *Leaf) Pow(n uint32) Expr {
	if n > 2 {
		return squareAndMultiply(l, n)
	}
	return &Pow{l, n}
}

func (l *Leaf) Leaves(config Config) []string {
	switch l.Type {
	case CommittedColumn:
		if config.WoCommittedColumns {
			return []string{}
		}
		return []string{l.Name}
	case ShiftedColumn:
		if config.WoShiftedColumns {
			return []string{}
		}
		return []string{l.String()}
	case ComputableColumn:
		if config.WoComputableColumns {
			return []string{}
		}
		return []string{l.Name}
	case Challenge:
		if config.WoChallenges {
			return []string{}
		}
		return []string{l.Name}
	case Const:
		return []string{}
	}
	return []string{}
}

func (l *Leaf) ReplaceLeafByExpression(leaf string, e Expr) Expr {
	if l.Type == Const {
		return l
	}
	if l.String() == leaf {
		return e
	}
	return l
}

func (l *Leaf) Prune(deg int) Expr { return pruneSearch(l, deg) }

func (l *Leaf) Evaluate(vals map[string]koalabear.Element) koalabear.Element {
	if l.Type == Const {
		return l.Value
	}
	key := l.String()
	v, ok := vals[key]
	if !ok {
		panic("Evaluate: missing value for " + key)
	}
	return v
}

func (l *Leaf) EvaluateWithIdx(vals []koalabear.Element) koalabear.Element {
	if l.Type == Const {
		return l.Value
	}
	return vals[l.Idx]
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

// isPrunable returns true if e is a composite sub-expression (not a bare leaf)
// that is eligible to be extracted into a new intermediate polynomial.
func isPrunable(e Expr) bool {
	switch e.(type) {
	case *Leaf:
		return false
	}
	return true
}

// pruneSearch recurses through expr looking for a composite child node E with degree <= deg.
// When found, E is replaced in-place with NewCommittedColumn(E.String()) and E is returned.
// Leaf children are skipped (they are already leaves; replacing them is a no-op).
// Returns nil if no such sub-expression is found.
func pruneSearch(expr Expr, deg int) Expr {
	switch e := expr.(type) {
	case *Leaf:
		return nil
	case *Add:
		if isPrunable(e.Left) && e.Left.Degree() <= deg {
			found := e.Left
			e.Left = NewCommittedColumn(found.String())
			return found
		}
		if isPrunable(e.Right) && e.Right.Degree() <= deg {
			found := e.Right
			e.Right = NewCommittedColumn(found.String())
			return found
		}
		if r := pruneSearch(e.Left, deg); r != nil {
			return r
		}
		return pruneSearch(e.Right, deg)
	case *Sub:
		if isPrunable(e.Left) && e.Left.Degree() <= deg {
			found := e.Left
			e.Left = NewCommittedColumn(found.String())
			return found
		}
		if isPrunable(e.Right) && e.Right.Degree() <= deg {
			found := e.Right
			e.Right = NewCommittedColumn(found.String())
			return found
		}
		if r := pruneSearch(e.Left, deg); r != nil {
			return r
		}
		return pruneSearch(e.Right, deg)
	case *Mul:
		if isPrunable(e.Left) && e.Left.Degree() <= deg {
			found := e.Left
			e.Left = NewCommittedColumn(found.String())
			return found
		}
		if isPrunable(e.Right) && e.Right.Degree() <= deg {
			found := e.Right
			e.Right = NewCommittedColumn(found.String())
			return found
		}
		if r := pruneSearch(e.Left, deg); r != nil {
			return r
		}
		return pruneSearch(e.Right, deg)
	case *Pow:
		if isPrunable(e.Base) && e.Base.Degree() <= deg {
			found := e.Base
			e.Base = NewCommittedColumn(found.String())
			return found
		}
		return pruneSearch(e.Base, deg)
	}
	return nil
}

func (a *Add) Leaves(config Config) []string {
	return append(a.Left.Leaves(config), a.Right.Leaves(config)...)
}
func (s *Sub) Leaves(config Config) []string {
	return append(s.Left.Leaves(config), s.Right.Leaves(config)...)
}
func (m *Mul) Leaves(config Config) []string {
	return append(m.Left.Leaves(config), m.Right.Leaves(config)...)
}
func (p *Pow) Leaves(config Config) []string { return p.Base.Leaves(config) }

func (l *Leaf) LeavesFull(config Config) []*Leaf {
	switch l.Type {
	case CommittedColumn:
		if config.WoCommittedColumns {
			return nil
		}
	case ShiftedColumn:
		if config.WoShiftedColumns {
			return nil
		}
	case ComputableColumn:
		if config.WoComputableColumns {
			return nil
		}
	case Challenge:
		if config.WoChallenges {
			return nil
		}
	case Const:
		return nil
	}
	return []*Leaf{l}
}
func (a *Add) LeavesFull(config Config) []*Leaf {
	return append(a.Left.LeavesFull(config), a.Right.LeavesFull(config)...)
}
func (s *Sub) LeavesFull(config Config) []*Leaf {
	return append(s.Left.LeavesFull(config), s.Right.LeavesFull(config)...)
}
func (m *Mul) LeavesFull(config Config) []*Leaf {
	return append(m.Left.LeavesFull(config), m.Right.LeavesFull(config)...)
}
func (p *Pow) LeavesFull(config Config) []*Leaf { return p.Base.LeavesFull(config) }

func (a *Add) Prune(deg int) Expr { return pruneSearch(a, deg) }
func (s *Sub) Prune(deg int) Expr { return pruneSearch(s, deg) }
func (m *Mul) Prune(deg int) Expr { return pruneSearch(m, deg) }
func (p *Pow) Prune(deg int) Expr { return pruneSearch(p, deg) }

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

func (a *Add) Evaluate(vals map[string]koalabear.Element) koalabear.Element {
	l := a.Left.Evaluate(vals)
	r := a.Right.Evaluate(vals)
	l.Add(&l, &r)
	return l
}

func (s *Sub) Evaluate(vals map[string]koalabear.Element) koalabear.Element {
	l := s.Left.Evaluate(vals)
	r := s.Right.Evaluate(vals)
	l.Sub(&l, &r)
	return l
}

func (m *Mul) Evaluate(vals map[string]koalabear.Element) koalabear.Element {
	l := m.Left.Evaluate(vals)
	r := m.Right.Evaluate(vals)
	l.Mul(&l, &r)
	return l
}

// Evaluate uses binary exponentiation so that large exponents (as produced by
// squareAndMultiply trees) are still handled in O(log exp) multiplications.
func (p *Pow) Evaluate(vals map[string]koalabear.Element) koalabear.Element {
	base := p.Base.Evaluate(vals)
	var res koalabear.Element
	res.SetOne()
	exp := p.Exp
	for exp > 0 {
		if exp&1 == 1 {
			res.Mul(&res, &base)
		}
		base.Mul(&base, &base)
		exp >>= 1
	}
	return res
}

func (a *Add) EvaluateWithIdx(vals []koalabear.Element) koalabear.Element {
	l := a.Left.EvaluateWithIdx(vals)
	r := a.Right.EvaluateWithIdx(vals)
	l.Add(&l, &r)
	return l
}

func (s *Sub) EvaluateWithIdx(vals []koalabear.Element) koalabear.Element {
	l := s.Left.EvaluateWithIdx(vals)
	r := s.Right.EvaluateWithIdx(vals)
	l.Sub(&l, &r)
	return l
}

func (m *Mul) EvaluateWithIdx(vals []koalabear.Element) koalabear.Element {
	l := m.Left.EvaluateWithIdx(vals)
	r := m.Right.EvaluateWithIdx(vals)
	l.Mul(&l, &r)
	return l
}

func (p *Pow) EvaluateWithIdx(vals []koalabear.Element) koalabear.Element {
	base := p.Base.EvaluateWithIdx(vals)
	var res koalabear.Element
	res.SetOne()
	exp := p.Exp
	for exp > 0 {
		if exp&1 == 1 {
			res.Mul(&res, &base)
		}
		base.Mul(&base, &base)
		exp >>= 1
	}
	return res
}

// Clone returns a deep copy of the expression tree with no shared nodes.
func Clone(e Expr) Expr {
	switch v := e.(type) {
	case *Leaf:
		c := *v
		return &c
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

func RemoveDuplicates[T comparable](s []T) []T {
	seen := make(map[T]struct{}, len(s))
	result := make([]T, 0, len(s))

	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}

	return result
}
