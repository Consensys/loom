package sym

import (
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

// sortedUniq returns a sorted, deduplicated copy — order-independent comparison helper.
func sortedUniq(s []string) []string {
	s = RemoveDuplicates(s)
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	g, w := sortedUniq(got), sortedUniq(want)
	if len(g) != len(w) {
		t.Fatalf("got %v, want %v", g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("got %v, want %v", g, w)
		}
	}
}

func TestString(t *testing.T) {

	var five koalabear.Element
	five.SetUint64(5)

	a := NewCommittedColumn("x")
	b := NewConst(five)
	c := &Add{Left: a, Right: b}
	d := &Mul{Left: a, Right: c}

	if a.String() != "x" {
		t.Errorf("Expected 'x', got '%s'", a.String())
	}

	if b.String() != "5" {
		t.Errorf("Expected '5', got '%s'", b.String())
	}

	if c.String() != "(x + 5)" {
		t.Errorf("Expected '(x + 5)', got '%s'", c.String())
	}

	if d.String() != "(x * (x + 5))" {
		t.Errorf("Expected '(x * (x + 5))', got '%s'", d.String())
	}

}

func TestPrune(t *testing.T) {

	x0 := NewCommittedColumn("x_0")
	x1 := NewCommittedColumn("x_1")
	e := x0.Add(x1).Pow(8)

	degreeBefore := e.Degree()
	beforePruning := e.String()

	degreeToPrune := 2
	_ = e.Prune(degreeToPrune)
	degreeAfter := e.Degree()
	afterPruning := e.String()
	if beforePruning != afterPruning {
		t.Fatal("pruning should not affect the string")
	}

	if degreeAfter+1 != degreeBefore {
		t.Errorf("pruning by a degree %d should decrease the degree by %d", degreeToPrune, degreeToPrune-1)
	}

}

func TestLeaves(t *testing.T) {
	var five koalabear.Element
	five.SetUint64(5)

	all := NewConfig()
	woCC := NewConfig(WithoutComputableColumns())
	woChal := NewConfig(WithoutChallenges())
	woAll := NewConfig(WithoutComputableColumns(), WithoutChallenges())

	// --- Leaf nodes ---

	// ComputableColumn: present by default, absent when excluded
	assertSameSet(t, NewComputableColumn("L0").Leaves(all), []string{"L0"})
	assertSameSet(t, NewComputableColumn("L0").Leaves(woCC), []string{})

	// CommittedColumn: always present regardless of config
	assertSameSet(t, NewCommittedColumn("x").Leaves(all), []string{"x"})
	assertSameSet(t, NewCommittedColumn("x").Leaves(woCC), []string{"x"})
	assertSameSet(t, NewCommittedColumn("x").Leaves(woChal), []string{"x"})

	// Const: never present
	assertSameSet(t, NewConst(five).Leaves(all), []string{})

	// Challenge: present by default, absent when excluded
	assertSameSet(t, NewChallenge("beta").Leaves(all), []string{"beta"})
	assertSameSet(t, NewChallenge("beta").Leaves(woChal), []string{})

	// --- Composite expressions ---

	// ComputableColumn + CommittedColumn
	e := NewComputableColumn("L0").Add(NewCommittedColumn("x"))
	assertSameSet(t, e.Leaves(all), []string{"L0", "x"})
	assertSameSet(t, e.Leaves(woCC), []string{"x"})

	// ComputableColumn * Challenge
	e = NewComputableColumn("L0").Mul(NewChallenge("gamma"))
	assertSameSet(t, e.Leaves(all), []string{"L0", "gamma"})
	assertSameSet(t, e.Leaves(woCC), []string{"gamma"})
	assertSameSet(t, e.Leaves(woChal), []string{"L0"})
	assertSameSet(t, e.Leaves(woAll), []string{})

	// Multiple ComputableColumns
	e = NewComputableColumn("L0").Add(NewComputableColumn("L1"))
	assertSameSet(t, e.Leaves(all), []string{"L0", "L1"})
	assertSameSet(t, e.Leaves(woCC), []string{})

	// Sub: ComputableColumn on the right
	e = NewCommittedColumn("x").Sub(NewComputableColumn("L0"))
	assertSameSet(t, e.Leaves(all), []string{"x", "L0"})
	assertSameSet(t, e.Leaves(woCC), []string{"x"})

	// Pow: ComputableColumn inside
	assertSameSet(t, NewComputableColumn("L0").Pow(2).Leaves(all), []string{"L0"})
	assertSameSet(t, NewComputableColumn("L0").Pow(2).Leaves(woCC), []string{})

	// Pow: CommittedColumn inside — no ComputableColumn
	assertSameSet(t, NewCommittedColumn("x").Pow(3).Leaves(all), []string{"x"})
	assertSameSet(t, NewCommittedColumn("x").Pow(3).Leaves(woCC), []string{"x"})

	// Nested: (x + L0) * (y - alpha) — all four leaf types interact
	e = NewCommittedColumn("x").Add(NewComputableColumn("L0")).Mul(NewCommittedColumn("y").Sub(NewChallenge("alpha")))
	assertSameSet(t, e.Leaves(all), []string{"x", "L0", "y", "alpha"})
	assertSameSet(t, e.Leaves(woCC), []string{"x", "y", "alpha"})
	assertSameSet(t, e.Leaves(woChal), []string{"x", "L0", "y"})
	assertSameSet(t, e.Leaves(woAll), []string{"x", "y"})

	// Same ComputableColumn appearing multiple times — deduplicated
	e = NewComputableColumn("L0").Add(NewComputableColumn("L0"))
	assertSameSet(t, e.Leaves(all), []string{"L0"})
}

func TestReplaceLeafByExpression(t *testing.T) {

	var five koalabear.Element
	five.SetUint64(5)

	// Var: matching name → replaced
	if got := NewCommittedColumn("x").ReplaceLeafByExpression("x", NewCommittedColumn("y")); got.String() != "y" {
		t.Errorf("expected 'y', got '%s'", got.String())
	}

	// Var: non-matching name → unchanged
	if got := NewCommittedColumn("x").ReplaceLeafByExpression("z", NewCommittedColumn("y")); got.String() != "x" {
		t.Errorf("expected 'x', got '%s'", got.String())
	}

	// Challenge: matching name → replaced
	if got := NewChallenge("alpha").ReplaceLeafByExpression("alpha", NewCommittedColumn("y")); got.String() != "y" {
		t.Errorf("expected 'y', got '%s'", got.String())
	}

	// Challenge: non-matching name → unchanged
	if got := NewChallenge("alpha").ReplaceLeafByExpression("beta", NewCommittedColumn("y")); got.String() != "alpha" {
		t.Errorf("expected 'alpha', got '%s'", got.String())
	}

	// Const: never replaced regardless of the leaf name
	if got := NewConst(five).ReplaceLeafByExpression("5", NewCommittedColumn("y")); got.String() != "5" {
		t.Errorf("expected '5', got '%s'", got.String())
	}

	// Add: only the matching child is replaced
	e := NewCommittedColumn("x").Add(NewConst(five))
	if got := e.ReplaceLeafByExpression("x", NewCommittedColumn("y")); got.String() != "(y + 5)" {
		t.Errorf("expected '(y + 5)', got '%s'", got.String())
	}

	// All occurrences replaced: x + x with x→y gives y + y
	e = NewCommittedColumn("x").Add(NewCommittedColumn("x"))
	if got := e.ReplaceLeafByExpression("x", NewCommittedColumn("y")); got.String() != "(y + y)" {
		t.Errorf("expected '(y + y)', got '%s'", got.String())
	}

	// Sub: alpha replaced by composite expression
	e = NewCommittedColumn("x").Sub(NewChallenge("alpha"))
	if got := e.ReplaceLeafByExpression("alpha", NewCommittedColumn("x").Mul(NewCommittedColumn("y"))); got.String() != "(x - (x * y))" {
		t.Errorf("expected '(x - (x * y))', got '%s'", got.String())
	}

	// Mul: nested replacement — x in x*(x+y) with x→a gives a*(a+y)
	e = NewCommittedColumn("x").Mul(NewCommittedColumn("x").Add(NewCommittedColumn("y")))
	if got := e.ReplaceLeafByExpression("x", NewCommittedColumn("a")); got.String() != "(a * (a + y))" {
		t.Errorf("expected '(a * (a + y))', got '%s'", got.String())
	}

	// Pow: base replaced by composite
	e = &Pow{Base: NewCommittedColumn("x"), Exp: 2}
	if got := e.ReplaceLeafByExpression("x", NewCommittedColumn("y").Add(NewCommittedColumn("z"))); got.String() != "((y + z) ^ 2)" {
		t.Errorf("expected '((y + z) ^ 2)', got '%s'", got.String())
	}

	// Original expression is not modified by replacement
	original := NewCommittedColumn("x").Add(NewCommittedColumn("y"))
	originalStr := original.String()
	_ = original.ReplaceLeafByExpression("x", NewCommittedColumn("z"))
	if original.String() != originalStr {
		t.Errorf("original modified: expected '%s', got '%s'", originalStr, original.String())
	}
}

func TestEval(t *testing.T) {

	x0 := NewCommittedColumn("x_0")
	x1 := NewCommittedColumn("x_1")
	x2 := NewCommittedColumn("x_2")
	x3 := NewCommittedColumn("x_3")

	nbCommittedColumns := 4

	varindex := make(VarIndex)
	varindex[x0.Name] = 0
	varindex[x1.Name] = 1
	varindex[x2.Name] = 2
	varindex[x3.Name] = 3

	var one, two, three, four koalabear.Element
	one.SetUint64(1)
	two.SetUint64(2)
	three.SetUint64(3)
	four.SetUint64(4)

	e := x0.Mul(x1).Add(x2).Mul(x3).Add(NewConst(one)).Mul(NewConst(two)).Add(NewConst(three)).Mul(NewConst(four))

	poly := Convert(e, varindex, nbCommittedColumns)

	horner := ToHorner(poly)

	// Evaluate at (1, 2, 3, 4)
	var input [4]koalabear.Element
	input[varindex[x0.Name]] = one
	input[varindex[x1.Name]] = two
	input[varindex[x2.Name]] = three
	input[varindex[x3.Name]] = four

	var expected, result koalabear.Element
	expected.SetUint64(180) // (((((((x_0 * x_1) + x_2) * x_3) + 1) * 2) + 3) * 4)
	result = horner.Eval(input[:])

	if !result.Equal(&expected) {
		t.Errorf("Expected %s, got %s", expected.String(), result.String())
	}

}
