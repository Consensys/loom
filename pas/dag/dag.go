package dag

import (
	"fmt"
	"strconv"
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
	Index    int        // position in DAG.Nodes; used by EvalWithCache / EvalWithCacheVars
	VarIdx   int        // for KindLeaf: index into vars slice for EvalWithCacheVars

	key string // canonical key used for deduplication (unexported)
}

// DAG is the directed acyclic graph form of an Expr. Sub-expressions that are
// structurally identical (including commutativity for Add and Mul) share a
// single *DAGNode.
type DAG struct {
	Root     *DAGNode
	Nodes    []*DAGNode     // every unique node, in topological order (children before parents)
	VarIndex map[string]int // leaf name → index in vars slice for EvalWithCacheVars
}

// ExprToDAG converts an Expr tree into a DAG by merging identical
// sub-expressions into shared nodes. Commutativity is respected: (a+b) and
// (b+a) produce the same node, as do (a*b) and (b*a). Sub is not commutative.
func ExprToDAG(e sym.Expr) *DAG {
	b := &dagBuilder{
		cache:    make(map[string]*DAGNode),
		varIndex: make(map[string]int),
	}
	root := b.build(e)
	return &DAG{Root: root, Nodes: b.ordered, VarIndex: b.varIndex}
}

type dagBuilder struct {
	cache    map[string]*DAGNode
	ordered  []*DAGNode
	varIndex map[string]int
}

func (b *dagBuilder) assignVarIdx(name string) int {
	if idx, ok := b.varIndex[name]; ok {
		return idx
	}
	idx := len(b.varIndex)
	b.varIndex[name] = idx
	return idx
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
	n.Index = len(b.ordered)
	b.cache[key] = n
	b.ordered = append(b.ordered, n)
	return n
}

func (b *dagBuilder) build(e sym.Expr) *DAGNode {
	switch v := e.(type) {
	case *sym.ShiftedColumn:
		key := dagKey("shifted", v.Name)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindLeaf, Leaf: e, VarIdx: b.assignVarIdx(v.Name)}
		})
	case *sym.CommittedColumn:
		key := dagKey("col", v.Name)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindLeaf, Leaf: e, VarIdx: b.assignVarIdx(v.Name)}
		})

	case *sym.Challenge:
		key := dagKey("chal", v.Name)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindLeaf, Leaf: e, VarIdx: b.assignVarIdx(v.Name)}
		})

	case *sym.ComputableColumn:
		key := dagKey("comp", v.Name)
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindLeaf, Leaf: e, VarIdx: b.assignVarIdx(v.Name)}
		})

	case *sym.Const:
		key := dagKey("const", v.Value.String())
		return b.intern(key, func() *DAGNode {
			return &DAGNode{Kind: KindLeaf, Leaf: e, VarIdx: b.assignVarIdx(v.Value.String())}
		})

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

// Key returns a unique ID characterising the node
func (d *DAGNode) Key() string {
	return d.key
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

	// Reassign Index for every node in the new ordering.
	// Non-leaf nodes are newly allocated (safe to mutate). Leaf nodes are
	// shared with the original DAG, but Flatten is typically called once and
	// the original DAG is discarded, so mutation is acceptable.
	for i, n := range ordered {
		n.Index = i
	}

	return &DAG{Root: root, Nodes: ordered, VarIndex: d.VarIndex}
}

// Factorize applies the distributive law
//
//	add(mul(x,y), mul(x,z)) → mul(x, add(y,z))
//
// to every Add node, bottom-up, until no further reductions are possible
// within a single pass. Best called on a Flatten()ed DAG. Returns a new DAG
// that shares leaf nodes with the receiver.
//
// The rule is applied greedily: at each Add node the factor that appears in
// the largest number of Mul children is extracted first, then the rule is
// re-applied to the residual terms. Only factors that are nodes with a
// non-empty key (i.e. nodes from the original ExprToDAG construction) are
// considered, so newly-created intermediate nodes are never spuriously
// identified as a common factor.
func (d *DAG) Factorize() *DAG {
	// Process nodes bottom-up (d.Nodes is in topological order: children
	// before parents), mapping each original node to its rewritten form.
	rewritten := make(map[*DAGNode]*DAGNode, len(d.Nodes))
	for _, n := range d.Nodes {
		rewritten[n] = factorizeRewrite(n, rewritten)
	}

	root := rewritten[d.Root]

	// Rebuild topological order for the new DAG via post-order DFS.
	seen := make(map[*DAGNode]bool, len(d.Nodes))
	ordered := make([]*DAGNode, 0, len(d.Nodes))
	var postOrder func(*DAGNode)
	postOrder = func(n *DAGNode) {
		if seen[n] {
			return
		}
		seen[n] = true
		for _, c := range n.Children {
			postOrder(c)
		}
		ordered = append(ordered, n)
	}
	postOrder(root)

	for i, n := range ordered {
		n.Index = i
	}

	return &DAG{Root: root, Nodes: ordered, VarIndex: d.VarIndex}
}

// factorizeRewrite rewrites n after all its children have already been
// rewritten (bottom-up order). For Add nodes it calls factorizeAddChildren
// to apply the distributive law; other node kinds just thread through
// rewritten children unchanged.
func factorizeRewrite(n *DAGNode, rewritten map[*DAGNode]*DAGNode) *DAGNode {
	switch n.Kind {
	case KindLeaf:
		return n // leaves are shared unchanged

	case KindAdd:
		children := make([]*DAGNode, len(n.Children))
		for i, c := range n.Children {
			children[i] = rewritten[c]
		}
		return factorizeAddChildren(children)

	case KindMul:
		changed := false
		children := make([]*DAGNode, len(n.Children))
		for i, c := range n.Children {
			children[i] = rewritten[c]
			if children[i] != c {
				changed = true
			}
		}
		if !changed {
			return n // unchanged: preserve key for factor lookup
		}
		return &DAGNode{Kind: KindMul, Children: children} // key intentionally empty

	case KindSub:
		l, r := rewritten[n.Children[0]], rewritten[n.Children[1]]
		if l == n.Children[0] && r == n.Children[1] {
			return n
		}
		return &DAGNode{Kind: KindSub, Children: []*DAGNode{l, r}}

	case KindPow:
		base := rewritten[n.Children[0]]
		if base == n.Children[0] {
			return n
		}
		return &DAGNode{Kind: KindPow, Children: []*DAGNode{base}, Exp: n.Exp}
	}
	panic(fmt.Sprintf("Factorize: unknown NodeKind %d", n.Kind))
}

// factorizeAddChildren applies the distributive law to the children of an Add
// node and returns a (possibly factored) replacement node. It recurses until
// no further reductions are possible at this level.
//
// Only KindMul children participate in factorization. Non-Mul children (leaves,
// Pow, Sub) are carried through unchanged, which avoids the need to introduce
// a Const(1) node for the case where a term reduces to the identity.
//
// Factor candidates are restricted to nodes whose key is non-empty: this
// ensures that only nodes from the original DAG construction are used as
// factors, preventing newly-created intermediate nodes from being spuriously
// matched.
func factorizeAddChildren(children []*DAGNode) *DAGNode {
	// Count how many KindMul children contain each factor (by key).
	factorCount := make(map[string]int)
	factorByKey := make(map[string]*DAGNode)
	for _, c := range children {
		if c.Kind != KindMul {
			continue
		}
		seen := make(map[string]bool)
		for _, f := range c.Children {
			if f.key == "" {
				continue // skip keyless intermediate nodes
			}
			if !seen[f.key] {
				seen[f.key] = true
				factorCount[f.key]++
				factorByKey[f.key] = f
			}
		}
	}

	// Pick the factor with the highest count (≥ 2 to be worth extracting).
	bestKey, bestCount := "", 1
	for k, cnt := range factorCount {
		if cnt > bestCount {
			bestCount, bestKey = cnt, k
		}
	}
	if bestKey == "" {
		return &DAGNode{Kind: KindAdd, Children: children}
	}

	factor := factorByKey[bestKey]

	// Partition children: Mul children that contain the factor go into
	// withFactor (with the factor removed); all others go into withoutFactor.
	var withFactor, withoutFactor []*DAGNode
	for _, c := range children {
		if c.Kind == KindMul {
			// Find the first occurrence of the factor in this Mul's children.
			idx := -1
			for i, f := range c.Children {
				if f.key == bestKey {
					idx = i
					break
				}
			}
			if idx >= 0 {
				// Rebuild Mul without this one occurrence of the factor.
				rem := make([]*DAGNode, 0, len(c.Children)-1)
				rem = append(rem, c.Children[:idx]...)
				rem = append(rem, c.Children[idx+1:]...)
				switch len(rem) {
				case 0:
					// Mul had exactly one child = the factor itself.
					// Avoid creating a Const(1); treat as non-participating.
					withoutFactor = append(withoutFactor, c)
				case 1:
					withFactor = append(withFactor, rem[0])
				default:
					withFactor = append(withFactor, &DAGNode{Kind: KindMul, Children: rem})
				}
				continue
			}
		}
		withoutFactor = append(withoutFactor, c)
	}

	// Build mul(factor, add(withFactor...)), recursing into the inner Add to
	// factor out any additional common factors among withFactor terms.
	var inner *DAGNode
	switch len(withFactor) {
	case 0:
		// Nothing was factored (all candidates hit the len=0 edge case).
		return &DAGNode{Kind: KindAdd, Children: children}
	case 1:
		inner = withFactor[0]
	default:
		inner = factorizeAddChildren(withFactor) // recurse: more factors possible
	}
	factored := &DAGNode{Kind: KindMul, Children: []*DAGNode{factor, inner}}

	if len(withoutFactor) == 0 {
		return factored
	}

	// Combine the factored group with the remaining children and recurse to
	// extract any further common factors among the residual terms.
	residual := append(withoutFactor, factored)
	return factorizeAddChildren(residual)
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

// EvalWithCacheVars evaluates the DAG using pre-filled vars and cache slices,
// avoiding all map operations. vars must be indexed by DAGNode.VarIdx (leaf
// variables must be set by the caller before each call). cache must have
// length >= len(d.Nodes). Both slices can be reused across repeated calls.
// Only works on DAGs produced by ExprToDAG (not Flatten).
func (d *DAG) EvalWithCacheVars(vars []koalabear.Element, cache []koalabear.Element) koalabear.Element {
	for _, n := range d.Nodes {
		cache[n.Index] = evalDAGNodeSliceVars(n, cache, vars)
	}
	return cache[d.Root.Index]
}

func evalDAGNodeSliceVars(n *DAGNode, cache []koalabear.Element, vars []koalabear.Element) koalabear.Element {
	switch n.Kind {
	case KindLeaf:
		return vars[n.VarIdx]

	case KindAdd:
		var acc koalabear.Element
		for _, child := range n.Children {
			v := cache[child.Index]
			acc.Add(&acc, &v)
		}
		return acc

	case KindSub:
		l, r := cache[n.Children[0].Index], cache[n.Children[1].Index]
		var res koalabear.Element
		res.Sub(&l, &r)
		return res

	case KindMul:
		var acc koalabear.Element
		acc.SetOne()
		for _, child := range n.Children {
			v := cache[child.Index]
			acc.Mul(&acc, &v)
		}
		return acc

	case KindPow:
		base := cache[n.Children[0].Index]
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
	panic(fmt.Sprintf("EvalWithCacheVars: unknown NodeKind %d", n.Kind))
}

// EvalWithCache evaluates the DAG using the caller-supplied cache slice instead
// of allocating a new map on each call. cache must have length >= len(d.Nodes).
// Reuse the same slice across repeated calls to avoid allocation overhead.
func (d *DAG) EvalWithCache(vals map[string]koalabear.Element, cache []koalabear.Element) koalabear.Element {
	for _, n := range d.Nodes {
		cache[n.Index] = evalDAGNodeSlice(n, cache, vals)
	}
	return cache[d.Root.Index]
}

func evalDAGNodeSlice(n *DAGNode, cache []koalabear.Element, vals map[string]koalabear.Element) koalabear.Element {
	switch n.Kind {
	case KindLeaf:
		return n.Leaf.Evaluate(vals)

	case KindAdd:
		var acc koalabear.Element
		for _, child := range n.Children {
			v := cache[child.Index]
			acc.Add(&acc, &v)
		}
		return acc

	case KindSub:
		l, r := cache[n.Children[0].Index], cache[n.Children[1].Index]
		var res koalabear.Element
		res.Sub(&l, &r)
		return res

	case KindMul:
		var acc koalabear.Element
		acc.SetOne()
		for _, child := range n.Children {
			v := cache[child.Index]
			acc.Mul(&acc, &v)
		}
		return acc

	case KindPow:
		base := cache[n.Children[0].Index]
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
	panic(fmt.Sprintf("EvalWithCache: unknown NodeKind %d", n.Kind))
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
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}
