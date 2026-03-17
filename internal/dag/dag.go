package dag

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/expr"
)

// fnvKey computes an FNV-64a hash of s and returns it as a 16-char hex string.
// Used to build O(1)-length compound node keys that are content-based (and
// therefore globally unique across separate ExprToDAG calls) without the O(n²)
// string-growth that results from naively concatenating children's full keys.
func fnvKey(s string) string {
	h := fnv.New64a()
	h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 16)
}

// fnvKeyUint computes an FNV-64a hash of s as uint64 (for ordering).
func fnvKeyUint(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// NodeKind identifies the type of an expression DAG node.
type NodeKind int

const (
	KindLeaf NodeKind = iota // leaf: CommittedColumn, Challenge, VirtualColumn, or Const
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
	Leaf     *expr.Leaf        // non-nil iff Kind == KindLeaf; stored as concrete type to avoid interface dispatch in hot eval path
	Children []*DAGNode        // len 2 for Add/Sub/Mul; len 1 for Pow; len 0 for Leaf
	Exp      uint32            // exponent, only meaningful when Kind == KindPow
	Index    int               // position in DAG.Nodes; used by EvalWithCache / EvalWithCacheVars
	VarIdx   int               // for KindLeaf: index into vars slice for EvalWithCacheVars
	IsConst  bool              // true iff Kind == KindLeaf and the leaf is a Const
	ConstVal koalabear.Element // valid iff IsConst; avoids the l.Type==Const branch in the hot eval path

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
func ExprToDAG(e expr.Expr) *DAG {
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

func (b *dagBuilder) build(root expr.Expr) *DAGNode {
	// Iterative post-order traversal to avoid stack overflow on deep expression trees
	// (e.g. a sum of thousands of constraints folded left-associatively).
	type frame struct {
		expr      expr.Expr
		processed bool // true = children already pushed; time to intern this node
	}

	result := make(map[expr.Expr]*DAGNode) // expr pointer → built DAGNode
	stack := make([]frame, 0, 64)
	stack = append(stack, frame{root, false})

	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		e := f.expr

		if _, done := result[e]; done {
			continue // shared subtree already built
		}

		switch v := e.(type) {
		case *expr.Leaf:
			var prefix string
			switch v.Type {
			case expr.RotatedColumn:
				prefix = "shifted"
			case expr.CommittedColumn:
				prefix = "col"
			case expr.ChallengeColumn:
				prefix = "chal"
			case expr.VirtualColumn:
				prefix = "comp"
			case expr.ConstantColumn:
				prefix = "const"
			}
			key := dagKey(prefix, v.String())
			lv := v
			result[e] = b.intern(key, func() *DAGNode {
				n := &DAGNode{Kind: KindLeaf, Leaf: lv, VarIdx: b.assignVarIdx(lv.String())}
				if lv.Type == expr.ConstantColumn {
					n.IsConst = true
					n.ConstVal = lv.Value
				}
				return n
			})

		case *expr.Add:
			if !f.processed {
				stack = append(stack, frame{e, true}, frame{v.Left, false}, frame{v.Right, false})
			} else {
				left, right := result[v.Left], result[v.Right]
				lh, rh := fnvKeyUint(left.key), fnvKeyUint(right.key)
				if lh > rh { // canonical order by content hash
					left, right = right, left
					lh, rh = rh, lh
				}
				key := dagKey("add", strconv.FormatUint(lh, 16), strconv.FormatUint(rh, 16))
				l, r := left, right
				result[e] = b.intern(key, func() *DAGNode {
					return &DAGNode{Kind: KindAdd, Children: []*DAGNode{l, r}}
				})
			}

		case *expr.Sub:
			if !f.processed {
				stack = append(stack, frame{e, true}, frame{v.Left, false}, frame{v.Right, false})
			} else {
				left, right := result[v.Left], result[v.Right]
				key := dagKey("sub", fnvKey(left.key), fnvKey(right.key)) // Sub is not commutative; order is preserved
				l, r := left, right
				result[e] = b.intern(key, func() *DAGNode {
					return &DAGNode{Kind: KindSub, Children: []*DAGNode{l, r}}
				})
			}

		case *expr.Mul:
			if !f.processed {
				stack = append(stack, frame{e, true}, frame{v.Left, false}, frame{v.Right, false})
			} else {
				left, right := result[v.Left], result[v.Right]
				lh, rh := fnvKeyUint(left.key), fnvKeyUint(right.key)
				if lh > rh { // canonical order by content hash
					left, right = right, left
					lh, rh = rh, lh
				}
				key := dagKey("mul", strconv.FormatUint(lh, 16), strconv.FormatUint(rh, 16))
				l, r := left, right
				result[e] = b.intern(key, func() *DAGNode {
					return &DAGNode{Kind: KindMul, Children: []*DAGNode{l, r}}
				})
			}

		case *expr.Pow:
			if !f.processed {
				stack = append(stack, frame{e, true}, frame{v.Base, false})
			} else {
				base := result[v.Base]
				key := dagKey("pow", fnvKey(base.key), strconv.Itoa(int(v.Exp)))
				bs, exp := base, v.Exp
				result[e] = b.intern(key, func() *DAGNode {
					return &DAGNode{Kind: KindPow, Children: []*DAGNode{bs}, Exp: exp}
				})
			}

		default:
			panic(fmt.Sprintf("ExprToDAG: unknown Expr type %T", e))
		}
	}

	return result[root]
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

// EvalOnIthEntry evaluates the DAG at row i of the polynomial slice _Pi.
// Each leaf node's Leaf.Idx field selects which polynomial in _Pi to read from
// (must be set by the caller, e.g. via evalPointWiseInto setup).
// Row selection follows the same rules as expr.Expr.EvaluateOnIthEntry:
//   - Const leaf              : returns the constant value
//   - len(_Pi[leaf.Idx]) == 1 : constant polynomial, returns _Pi[leaf.Idx][0]
//   - RotatedColumn leaf      : returns _Pi[leaf.Idx][(i+N+leaf.Shift)%N]
//   - all other leaves        : returns _Pi[leaf.Idx][i]
//
// Composite nodes are evaluated in topological order using an internal cache
// so that shared sub-expressions are computed only once.
func (d *DAG) EvalOnIthEntry(_Pi [][]koalabear.Element, i int) koalabear.Element {
	cache := make([]koalabear.Element, len(d.Nodes))
	for _, n := range d.Nodes {
		cache[n.Index] = evalDAGNodeOnIthEntry(n, cache, _Pi, i)
	}
	return cache[d.Root.Index]
}

func evalDAGNodeOnIthEntry(n *DAGNode, cache []koalabear.Element, _Pi [][]koalabear.Element, i int) koalabear.Element {
	switch n.Kind {
	case KindLeaf:
		return n.Leaf.EvaluateOnIthEntry(_Pi, i)

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
	panic(fmt.Sprintf("EvalOnIthEntry: unknown NodeKind %d", n.Kind))
}

// EvalOnAllEntries evaluates the DAG pointwise for all N rows simultaneously
// and returns a slice of length N. Equivalent to calling EvalOnIthEntry(Pi, j)
// for j=0..N-1, but uses a single topological traversal with tight inner loops
// instead of N separate traversals. Each non-leaf node is visited exactly once.
//
// Peak memory is bounded to O(max_live_nodes × N) by reference counting: a
// node's buffer is returned to an internal pool as soon as all its parents have
// consumed it.
func (d *DAG) EvalOnAllEntries(Pi [][]koalabear.Element, N int) []koalabear.Element {
	// Pre-compute how many parent nodes reference each child.
	refCount := make([]int, len(d.Nodes))
	for _, n := range d.Nodes {
		for _, child := range n.Children {
			refCount[child.Index]++
		}
	}

	// Buffer pool: recycle N-length slices to limit peak allocation.
	// (don't use sync.Pool -> no cross-call, cross-goroutine sharing in this function case)
	var pool [][]koalabear.Element
	alloc := func() []koalabear.Element {
		if last := len(pool) - 1; last >= 0 {
			b := pool[last]
			pool = pool[:last]
			return b
		}
		return make([]koalabear.Element, N)
	}
	release := func(b []koalabear.Element) { pool = append(pool, b) }

	vectors := make([][]koalabear.Element, len(d.Nodes))

	for _, n := range d.Nodes {
		dst := alloc()

		switch n.Kind {
		case KindLeaf:
			if n.IsConst {
				for j := range N {
					dst[j] = n.ConstVal
				}
			} else {
				l := n.Leaf
				p := Pi[l.Idx]
				if len(p) == 1 {
					for j := range N {
						dst[j] = p[0]
					}
				} else if l.Type == expr.RotatedColumn {
					for j := range N {
						dst[j] = p[(j+N+l.Shift)%N]
					}
				} else {
					copy(dst, p[:N])
				}
			}

		case KindAdd:
			copy(dst, vectors[n.Children[0].Index])
			for _, child := range n.Children[1:] {
				src := vectors[child.Index]
				for j := range N {
					dst[j].Add(&dst[j], &src[j])
				}
			}

		case KindSub:
			l, r := vectors[n.Children[0].Index], vectors[n.Children[1].Index]
			for j := range N {
				dst[j].Sub(&l[j], &r[j])
			}

		case KindMul:
			copy(dst, vectors[n.Children[0].Index])
			for _, child := range n.Children[1:] {
				src := vectors[child.Index]
				for j := range N {
					dst[j].Mul(&dst[j], &src[j])
				}
			}

		case KindPow:
			base := vectors[n.Children[0].Index]
			tmp := alloc()
			copy(tmp, base)
			for j := range N {
				dst[j].SetOne()
			}
			exp := n.Exp
			for exp > 0 {
				if exp&1 == 1 {
					for j := range N {
						dst[j].Mul(&dst[j], &tmp[j])
					}
				}
				for j := range N {
					tmp[j].Mul(&tmp[j], &tmp[j])
				}
				exp >>= 1
			}
			release(tmp)
		}

		vectors[n.Index] = dst

		// Release child buffers no longer needed by any future parent.
		for _, child := range n.Children {
			refCount[child.Index]--
			if refCount[child.Index] == 0 && child != d.Root {
				release(vectors[child.Index])
				vectors[child.Index] = nil
			}
		}
	}

	return vectors[d.Root.Index]
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
// WithoutVirtualumns suppress the corresponding leaf kinds; Const leaves
// are never included. Because the DAG deduplicates nodes, each
// structurally-identical leaf appears at most once.
func (d *DAG) Leaves(config expr.Config) []string {
	var leaves []string
	for _, n := range d.Nodes {
		if n.Kind == KindLeaf {
			leaves = append(leaves, n.Leaf.Leaves(config)...)
		}
	}
	return leaves
}

// LeavesFull returns every unique non-Const leaf in the DAG that is not
// excluded by config, as full *expr.Leaf structs. The filtering rules are
// identical to those of Expr.LeavesFull. Because the DAG deduplicates nodes,
// each structurally-identical leaf appears at most once.
func (d *DAG) LeavesFull(config expr.Config) []*expr.Leaf {
	var leaves []*expr.Leaf
	for _, n := range d.Nodes {
		if n.Kind == KindLeaf {
			leaves = append(leaves, n.Leaf.LeavesFull(config)...)
		}
	}
	return leaves
}

// Degree returns the total degree of the DAG expression, following the same
// conventions as Expr.Degree:
//   - CommittedColumn and VirtualColumn leaves have degree 1.
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
		deg := expr.NegInf
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
