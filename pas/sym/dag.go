package sym

import (
	"fmt"
	"strings"
)

// NodeKind identifies the type of an expression DAG node.
type NodeKind int

const (
	KindLeaf NodeKind = iota // leaf: CommittedColumn, Challenge, ComputableColumn, or Const
	KindAdd
	KindSub
	KindMul
	KindPow
)

// DAGNode is a node in the directed acyclic graph (DAG) representation of an
// Expr. A single *DAGNode may be referenced by multiple parents, representing
// shared sub-expressions.
//
// For commutative operators (Add, Mul), the expression (a op b) and (b op a)
// are represented by the same node: Children are stored in canonical key order
// so that the node is unique regardless of operand order in the source tree.
type DAGNode struct {
	Kind     NodeKind
	Leaf     Expr       // non-nil iff Kind == KindLeaf; holds the original leaf
	Children []*DAGNode // len 2 for Add/Sub/Mul; len 1 for Pow; len 0 for Leaf
	Exp      uint32     // exponent, only meaningful when Kind == KindPow

	key string // canonical key used for deduplication (unexported)
}

// DAG is the directed acyclic graph form of an Expr. Sub-expressions that are
// structurally identical (including commutativity for Add and Mul) share a
// single *DAGNode.
type DAG struct {
	Root  *DAGNode
	Nodes []*DAGNode // every unique node, in topological order (children before parents)
}

// ExprToDAG converts an Expr tree into a DAG by merging identical
// sub-expressions into shared nodes. Commutativity is respected: (a+b) and
// (b+a) produce the same node, as do (a*b) and (b*a). Sub is not commutative.
func ExprToDAG(e Expr) *DAG {
	b := &dagBuilder{cache: make(map[string]*DAGNode)}
	root := b.build(e)
	return &DAG{Root: root, Nodes: b.ordered}
}

type dagBuilder struct {
	cache   map[string]*DAGNode
	ordered []*DAGNode
}

// intern returns the cached node for key, or creates it via make(), records
// it, and appends it to the topological slice. Children must already be in
// b.ordered when intern is called, which is guaranteed by the post-order
// traversal in build().
func (b *dagBuilder) intern(key string, make func() *DAGNode) *DAGNode {
	if n, ok := b.cache[key]; ok {
		return n
	}
	n := make()
	n.key = key
	b.cache[key] = n
	b.ordered = append(b.ordered, n)
	return n
}

func (b *dagBuilder) build(e Expr) *DAGNode {
	switch v := e.(type) {
	case *CommittedColumn:
		key := dagKey("col", v.Name)
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *Challenge:
		key := dagKey("chal", v.Name)
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *ComputableColumn:
		key := dagKey("comp", v.Name)
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *Const:
		key := dagKey("const", v.Value.String())
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *Add:
		left, right := b.build(v.Left), b.build(v.Right)
		if left.key > right.key { // canonical order: (a+b) == (b+a)
			left, right = right, left
		}
		key := dagKey("add", left.key, right.key)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindAdd, Children: []*DAGNode{left, right}}
		})

	case *Sub:
		left, right := b.build(v.Left), b.build(v.Right)
		key := dagKey("sub", left.key, right.key) // not commutative
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindSub, Children: []*DAGNode{left, right}}
		})

	case *Mul:
		left, right := b.build(v.Left), b.build(v.Right)
		if left.key > right.key { // canonical order: (a*b) == (b*a)
			left, right = right, left
		}
		key := dagKey("mul", left.key, right.key)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindMul, Children: []*DAGNode{left, right}}
		})

	case *Pow:
		base := b.build(v.Base)
		key := dagKey("pow", base.key, fmt.Sprintf("%d", v.Exp))
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindPow, Children: []*DAGNode{base}, Exp: v.Exp}
		})
	}
	panic(fmt.Sprintf("ExprToDAG: unknown Expr type %T", e))
}

// dagKey builds a collision-free canonical string key from the given parts.
// Each part is encoded with %q (Go string literal syntax), escaping any
// embedded special characters including double quotes and backslashes.
// Adjacent %q-encoded strings are uniquely decodable without an explicit
// separator, so the overall key is collision-free regardless of part content.
func dagKey(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&b, "%q", p)
	}
	return b.String()
}
