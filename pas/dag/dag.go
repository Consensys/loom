package dag

import (
	"fmt"
	"strings"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/gnark-crypto/field/koalabear"
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
	Leaf     sym.Expr   // non-nil iff Kind == KindLeaf; holds the original leaf
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
func ExprToDAG(e sym.Expr) *DAG {
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

func (b *dagBuilder) build(e sym.Expr) *DAGNode {
	switch v := e.(type) {
	case *sym.CommittedColumn:
		key := dagKey("col", v.Name)
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *sym.Challenge:
		key := dagKey("chal", v.Name)
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *sym.ComputableColumn:
		key := dagKey("comp", v.Name)
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *sym.Const:
		key := dagKey("const", v.Value.String())
		return b.intern(key, func() *DAGNode { return &DAGNode{Kind: KindLeaf, Leaf: e} })

	case *sym.Add:
		left, right := b.build(v.Left), b.build(v.Right)
		if left.key > right.key { // canonical order: (a+b) == (b+a)
			left, right = right, left
		}
		key := dagKey("add", left.key, right.key)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindAdd, Children: []*DAGNode{left, right}}
		})

	case *sym.Sub:
		left, right := b.build(v.Left), b.build(v.Right)
		key := dagKey("sub", left.key, right.key) // not commutative
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindSub, Children: []*DAGNode{left, right}}
		})

	case *sym.Mul:
		left, right := b.build(v.Left), b.build(v.Right)
		if left.key > right.key { // canonical order: (a*b) == (b*a)
			left, right = right, left
		}
		key := dagKey("mul", left.key, right.key)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindMul, Children: []*DAGNode{left, right}}
		})

	case *sym.Pow:
		base := b.build(v.Base)
		key := dagKey("pow", base.key, fmt.Sprintf("%d", v.Exp))
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindPow, Children: []*DAGNode{base}, Exp: v.Exp}
		})
	}
	panic(fmt.Sprintf("ExprToDAG: unknown Expr type %T", e))
}

// Flatten returns a new DAG where every chain of binary Add nodes is collapsed
// into a single n-ary Add node, and every chain of binary Mul nodes into a
// single n-ary Mul node. For example:
//
//	Add(Add(a, b), c)  →  Add node with children [a, b, c]
//	Mul(a, Mul(b, c))  →  Mul node with children [a, b, c]
//
// Sub and Pow are left as binary/unary nodes (they are not associative).
// Leaf nodes are shared with the receiver; operator nodes are freshly allocated.
//
// The single pass over the topological order is sufficient: by the time a
// parent is processed, its children are already fully flattened, so absorbing
// same-kind children one level deep catches arbitrarily deep chains.
func (d *DAG) Flatten() *DAG {
	// flat maps each original *DAGNode to its flattened counterpart.
	// d.Nodes is in topological order (children before parents), so every
	// child is already in flat when its parent is processed.
	flat := make(map[*DAGNode]*DAGNode, len(d.Nodes))
	for _, n := range d.Nodes {
		flat[n] = flattenNode(n, flat)
	}

	root := flat[d.Root]

	// Rebuild the topological order for the new DAG via post-order DFS.
	// Intermediate binary nodes that were absorbed are no longer reachable
	// from the new root and are therefore excluded.
	seen := make(map[*DAGNode]bool, len(d.Nodes))
	ordered := make([]*DAGNode, 0, len(d.Nodes))
	var postOrder func(*DAGNode)
	postOrder = func(n *DAGNode) {
		if seen[n] {
			return
		}
		seen[n] = true
		for _, child := range n.Children {
			postOrder(child)
		}
		ordered = append(ordered, n)
	}
	postOrder(root)

	return &DAG{Root: root, Nodes: ordered}
}

// flattenNode returns the flattened version of n, looking up already-flattened
// children in flat.
func flattenNode(n *DAGNode, flat map[*DAGNode]*DAGNode) *DAGNode {
	switch n.Kind {
	case KindLeaf:
		return n // leaves have no children; share the original pointer

	case KindAdd:
		return &DAGNode{Kind: KindAdd, Children: absorbChildren(n, KindAdd, flat)}

	case KindMul:
		return &DAGNode{Kind: KindMul, Children: absorbChildren(n, KindMul, flat)}

	case KindSub:
		return &DAGNode{Kind: KindSub, Children: []*DAGNode{flat[n.Children[0]], flat[n.Children[1]]}}

	case KindPow:
		return &DAGNode{Kind: KindPow, Children: []*DAGNode{flat[n.Children[0]]}, Exp: n.Exp}
	}
	panic(fmt.Sprintf("Flatten: unknown NodeKind %d", n.Kind))
}

// absorbChildren builds the child list for a flattened n-ary node of the given
// kind. For each child of n, if its flattened version has the same kind, its
// own children are inlined (absorbed) rather than kept as a nested node.
func absorbChildren(n *DAGNode, kind NodeKind, flat map[*DAGNode]*DAGNode) []*DAGNode {
	children := make([]*DAGNode, 0, len(n.Children))
	for _, child := range n.Children {
		fc := flat[child]
		if fc.Kind == kind {
			children = append(children, fc.Children...)
		} else {
			children = append(children, fc)
		}
	}
	return children
}

// String returns a human-readable multi-line tree representation of the DAG.
//
// Each unique node is printed once. Nodes referenced by more than one parent
// are labelled (#0, #1, …) on their first occurrence and shown as "→ #N" on
// every subsequent one, making sharing explicit without unrolling the graph.
//
// Example output for (a*b + c) where (a*b) is shared:
//
//	add
//	├── #0: mul
//	│   ├── col:a
//	│   └── col:b
//	├── col:c
//	└── → #0
func (d *DAG) String() string {
	// Count how many parents reference each node.
	refCount := dagRefCount(d.Root)

	// Assign sequential IDs to shared nodes in topological order (d.Nodes is
	// children-before-parents), so leaves and deep sub-expressions get lower IDs.
	ids := make(map[*DAGNode]int, len(d.Nodes))
	nextID := 0
	for _, n := range d.Nodes {
		if refCount[n] > 1 {
			ids[n] = nextID
			nextID++
		}
	}

	var sb strings.Builder
	visited := make(map[*DAGNode]bool, len(d.Nodes))
	dagWriteNode(&sb, d.Root, ids, visited, "")
	return strings.TrimRight(sb.String(), "\n")
}

// dagRefCount returns the number of parent references for every node in the
// subtree rooted at root (i.e. the in-degree in the DAG).
func dagRefCount(root *DAGNode) map[*DAGNode]int {
	counts := make(map[*DAGNode]int)
	var dfs func(*DAGNode)
	dfs = func(n *DAGNode) {
		counts[n]++
		if counts[n] == 1 { // recurse only on first visit to avoid exponential blowup
			for _, child := range n.Children {
				dfs(child)
			}
		}
	}
	dfs(root)
	return counts
}

// dagNodeLabel returns a short, human-readable label for n (operator name or
// leaf type + identifier).
func dagNodeLabel(n *DAGNode) string {
	switch n.Kind {
	case KindLeaf:
		switch v := n.Leaf.(type) {
		case *sym.CommittedColumn:
			return "col:" + v.Name
		case *sym.Challenge:
			return "chal:" + v.Name
		case *sym.ComputableColumn:
			return "comp:" + v.Name
		case *sym.Const:
			return "const:" + v.Value.String()
		}
		return n.Leaf.String()
	case KindAdd:
		return "add"
	case KindSub:
		return "sub"
	case KindMul:
		return "mul"
	case KindPow:
		return fmt.Sprintf("^%d", n.Exp)
	}
	return "?"
}

// dagWriteNode writes n and its subtree into sb.
// The caller must have already written the connector for n's own line
// (e.g. "├── " or "└── "); dagWriteNode writes the label and then recurses.
// prefix is the continuation indent prepended to every line that belongs to
// n's descendants.
func dagWriteNode(sb *strings.Builder, n *DAGNode, ids map[*DAGNode]int, visited map[*DAGNode]bool, prefix string) {
	id, shared := ids[n]

	if shared && visited[n] {
		// Already printed in full elsewhere: emit a back-reference.
		fmt.Fprintf(sb, "→ #%d\n", id)
		return
	}

	// Write the label line.
	if shared {
		visited[n] = true
		fmt.Fprintf(sb, "#%d: %s\n", id, dagNodeLabel(n))
	} else {
		fmt.Fprintf(sb, "%s\n", dagNodeLabel(n))
	}

	// Recurse into children, drawing branch connectors.
	for i, child := range n.Children {
		if i < len(n.Children)-1 {
			sb.WriteString(prefix + "├── ")
			dagWriteNode(sb, child, ids, visited, prefix+"│   ")
		} else {
			sb.WriteString(prefix + "└── ")
			dagWriteNode(sb, child, ids, visited, prefix+"    ")
		}
	}
}

// Eval evaluates the DAG at the given variable assignment. It processes nodes
// in topological order (d.Nodes is children-before-parents), caching each
// result so shared nodes are computed only once.
//
// Add and Mul are n-ary: all children are summed / multiplied together.
// Sub is binary: Children[0] − Children[1].
// Pow uses the exponent stored in the node.
// Leaves are looked up in vals; missing keys cause a panic.
func (d *DAG) Eval(vals map[string]koalabear.Element) koalabear.Element {
	cache := make(map[*DAGNode]koalabear.Element, len(d.Nodes))
	for _, n := range d.Nodes {
		cache[n] = evalDAGNode(n, cache, vals)
	}
	return cache[d.Root]
}

func evalDAGNode(n *DAGNode, cache map[*DAGNode]koalabear.Element, vals map[string]koalabear.Element) koalabear.Element {
	switch n.Kind {
	case KindLeaf:
		return n.Leaf.Evaluate(vals)

	case KindAdd:
		var acc koalabear.Element
		for _, child := range n.Children {
			v := cache[child]
			acc.Add(&acc, &v)
		}
		return acc

	case KindSub:
		l, r := cache[n.Children[0]], cache[n.Children[1]]
		var res koalabear.Element
		res.Sub(&l, &r)
		return res

	case KindMul:
		var acc koalabear.Element
		acc.SetOne()
		for _, child := range n.Children {
			v := cache[child]
			acc.Mul(&acc, &v)
		}
		return acc

	case KindPow:
		base := cache[n.Children[0]]
		var res koalabear.Element
		res.SetOne()
		exp := n.Exp
		for exp > 0 {
			if exp&1 == 1 {
				res.Mul(&res, &base)
			}
			base.Mul(&base, &base)
			exp >>= 1
		}
		return res
	}
	panic(fmt.Sprintf("Eval: unknown NodeKind %d", n.Kind))
}

// Leaves returns the String() representation of every unique leaf in the DAG
// that is not excluded by config. The filtering rules are identical to those
// of Expr.Leaves: WithoutCommittedColumns, WithoutChallenges, and
// WithoutComputableColumns suppress the corresponding leaf kinds; Const leaves
// are never included. Because the DAG deduplicates nodes, each
// structurally-identical leaf appears at most once.
func (d *DAG) Leaves(config sym.Config) []string {
	var leaves []string
	for _, n := range d.Nodes {
		if n.Kind == KindLeaf {
			leaves = append(leaves, n.Leaf.Leaves(config)...)
		}
	}
	return leaves
}

// Degree returns the total degree of the DAG expression, following the same
// conventions as Expr.Degree:
//   - CommittedColumn and ComputableColumn leaves have degree 1.
//   - Challenge and non-zero Const leaves have degree 0.
//   - The zero Const leaf has degree NegInf (math.MinInt).
//   - Add/Sub: max of children's degrees (n-ary after Flatten).
//   - Mul: sum of children's degrees (n-ary after Flatten).
//   - Pow: base degree × exponent.
//
// Shared nodes are evaluated once; the cached result is reused for every
// parent that references them.
func (d *DAG) Degree() int {
	degrees := make(map[*DAGNode]int, len(d.Nodes))
	for _, n := range d.Nodes {
		degrees[n] = dagNodeDegree(n, degrees)
	}
	return degrees[d.Root]
}

func dagNodeDegree(n *DAGNode, degrees map[*DAGNode]int) int {
	switch n.Kind {
	case KindLeaf:
		return n.Leaf.Degree()

	case KindAdd, KindSub:
		deg := sym.NegInf
		for _, child := range n.Children {
			deg = max(deg, degrees[child])
		}
		return deg

	case KindMul:
		deg := 0
		for _, child := range n.Children {
			deg += degrees[child]
		}
		return deg

	case KindPow:
		return degrees[n.Children[0]] * int(n.Exp)
	}
	panic(fmt.Sprintf("Degree: unknown NodeKind %d", n.Kind))
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
