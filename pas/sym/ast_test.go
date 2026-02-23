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

	a := NewVar("x")
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

	x0 := NewVar("x_0")
	x1 := NewVar("x_1")
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

func TestLeavesWOPlaceholders(t *testing.T) {
	var five koalabear.Element
	five.SetUint64(5)

	// Leaf nodes
	assertSameSet(t, NewVar("x").LeavesWOPlaceholders(), []string{"x"})
	assertSameSet(t, NewConst(five).LeavesWOPlaceholders(), []string{})
	assertSameSet(t, NewPlaceholder("beta").LeavesWOPlaceholders(), []string{})

	// Var mixed with Const — Const is excluded
	assertSameSet(t,
		NewVar("x").Add(NewConst(five)).LeavesWOPlaceholders(),
		[]string{"x"},
	)

	// Var mixed with Placeholder — Placeholder is excluded
	assertSameSet(t,
		NewVar("x").Add(NewPlaceholder("beta")).LeavesWOPlaceholders(),
		[]string{"x"},
	)

	// Multiple Vars with a Placeholder — only Vars returned
	assertSameSet(t,
		NewVar("x").Mul(NewVar("y")).Add(NewPlaceholder("beta")).LeavesWOPlaceholders(),
		[]string{"x", "y"},
	)

	// Placeholder on the left — still excluded
	assertSameSet(t,
		NewPlaceholder("alpha").Mul(NewVar("x")).LeavesWOPlaceholders(),
		[]string{"x"},
	)

	// Sub: only Vars, no Placeholders or Consts
	assertSameSet(t,
		NewVar("a").Sub(NewPlaceholder("gamma")).Sub(NewConst(five)).LeavesWOPlaceholders(),
		[]string{"a"},
	)

	// Pow: Var inside
	assertSameSet(t,
		NewVar("x").Pow(3).LeavesWOPlaceholders(),
		[]string{"x"},
	)

	// Pow: Placeholder inside — excluded
	assertSameSet(t,
		NewPlaceholder("beta").Pow(2).LeavesWOPlaceholders(),
		[]string{},
	)

	// Nested: (x + alpha) * (y - 5) — two Vars, one Placeholder, one Const
	assertSameSet(t,
		NewVar("x").Add(NewPlaceholder("alpha")).Mul(NewVar("y").Sub(NewConst(five))).LeavesWOPlaceholders(),
		[]string{"x", "y"},
	)

	// Same Var appearing multiple times — deduplicated
	assertSameSet(t,
		NewVar("x").Add(NewVar("x")).LeavesWOPlaceholders(),
		[]string{"x"},
	)
}

func TestPlaceholders(t *testing.T) {
	var five koalabear.Element
	five.SetUint64(5)

	// Leaf nodes
	assertSameSet(t, NewVar("x").Placeholders(), []string{})
	assertSameSet(t, NewConst(five).Placeholders(), []string{})
	assertSameSet(t, NewPlaceholder("beta").Placeholders(), []string{"beta"})

	// Var mixed with Placeholder — only Placeholder returned
	assertSameSet(t,
		NewVar("x").Add(NewPlaceholder("beta")).Placeholders(),
		[]string{"beta"},
	)

	// Var mixed with Const — no Placeholder
	assertSameSet(t,
		NewVar("x").Add(NewConst(five)).Placeholders(),
		[]string{},
	)

	// Multiple Placeholders
	assertSameSet(t,
		NewPlaceholder("alpha").Mul(NewPlaceholder("beta")).Placeholders(),
		[]string{"alpha", "beta"},
	)

	// Placeholder on the right of Sub
	assertSameSet(t,
		NewVar("x").Sub(NewPlaceholder("gamma")).Placeholders(),
		[]string{"gamma"},
	)

	// Vars with multiple Placeholders, no double-counting
	assertSameSet(t,
		NewVar("x").Mul(NewVar("y")).Add(NewPlaceholder("beta")).Mul(NewPlaceholder("alpha")).Placeholders(),
		[]string{"beta", "alpha"},
	)

	// Pow: Placeholder inside
	assertSameSet(t,
		NewPlaceholder("beta").Pow(2).Placeholders(),
		[]string{"beta"},
	)

	// Pow: Var inside — no Placeholder
	assertSameSet(t,
		NewVar("x").Pow(3).Placeholders(),
		[]string{},
	)

	// Nested: (x + alpha) * (y - beta) — two Placeholders, two Vars
	assertSameSet(t,
		NewVar("x").Add(NewPlaceholder("alpha")).Mul(NewVar("y").Sub(NewPlaceholder("beta"))).Placeholders(),
		[]string{"alpha", "beta"},
	)

	// Same Placeholder appearing multiple times — deduplicated
	assertSameSet(t,
		NewPlaceholder("alpha").Add(NewPlaceholder("alpha")).Placeholders(),
		[]string{"alpha"},
	)
}

func TestReplaceLeafByExpression(t *testing.T) {

	var five koalabear.Element
	five.SetUint64(5)

	// Var: matching name → replaced
	if got := NewVar("x").ReplaceLeafByExpression("x", NewVar("y")); got.String() != "y" {
		t.Errorf("expected 'y', got '%s'", got.String())
	}

	// Var: non-matching name → unchanged
	if got := NewVar("x").ReplaceLeafByExpression("z", NewVar("y")); got.String() != "x" {
		t.Errorf("expected 'x', got '%s'", got.String())
	}

	// Placeholder: matching name → replaced
	if got := NewPlaceholder("alpha").ReplaceLeafByExpression("alpha", NewVar("y")); got.String() != "y" {
		t.Errorf("expected 'y', got '%s'", got.String())
	}

	// Placeholder: non-matching name → unchanged
	if got := NewPlaceholder("alpha").ReplaceLeafByExpression("beta", NewVar("y")); got.String() != "alpha" {
		t.Errorf("expected 'alpha', got '%s'", got.String())
	}

	// Const: never replaced regardless of the leaf name
	if got := NewConst(five).ReplaceLeafByExpression("5", NewVar("y")); got.String() != "5" {
		t.Errorf("expected '5', got '%s'", got.String())
	}

	// Add: only the matching child is replaced
	e := NewVar("x").Add(NewConst(five))
	if got := e.ReplaceLeafByExpression("x", NewVar("y")); got.String() != "(y + 5)" {
		t.Errorf("expected '(y + 5)', got '%s'", got.String())
	}

	// All occurrences replaced: x + x with x→y gives y + y
	e = NewVar("x").Add(NewVar("x"))
	if got := e.ReplaceLeafByExpression("x", NewVar("y")); got.String() != "(y + y)" {
		t.Errorf("expected '(y + y)', got '%s'", got.String())
	}

	// Sub: alpha replaced by composite expression
	e = NewVar("x").Sub(NewPlaceholder("alpha"))
	if got := e.ReplaceLeafByExpression("alpha", NewVar("x").Mul(NewVar("y"))); got.String() != "(x - (x * y))" {
		t.Errorf("expected '(x - (x * y))', got '%s'", got.String())
	}

	// Mul: nested replacement — x in x*(x+y) with x→a gives a*(a+y)
	e = NewVar("x").Mul(NewVar("x").Add(NewVar("y")))
	if got := e.ReplaceLeafByExpression("x", NewVar("a")); got.String() != "(a * (a + y))" {
		t.Errorf("expected '(a * (a + y))', got '%s'", got.String())
	}

	// Pow: base replaced by composite
	e = &Pow{Base: NewVar("x"), Exp: 2}
	if got := e.ReplaceLeafByExpression("x", NewVar("y").Add(NewVar("z"))); got.String() != "((y + z) ^ 2)" {
		t.Errorf("expected '((y + z) ^ 2)', got '%s'", got.String())
	}

	// Placeholder replaced by Var → no placeholders remain
	e = NewPlaceholder("alpha").Mul(NewVar("x"))
	got := e.ReplaceLeafByExpression("alpha", NewVar("beta"))
	assertSameSet(t, got.Placeholders(), []string{})
	assertSameSet(t, got.LeavesWOPlaceholders(), []string{"beta", "x"})

	// Original expression is not modified by replacement
	original := NewVar("x").Add(NewVar("y"))
	originalStr := original.String()
	_ = original.ReplaceLeafByExpression("x", NewVar("z"))
	if original.String() != originalStr {
		t.Errorf("original modified: expected '%s', got '%s'", originalStr, original.String())
	}
}

func TestEval(t *testing.T) {

	x0 := NewVar("x_0")
	x1 := NewVar("x_1")
	x2 := NewVar("x_2")
	x3 := NewVar("x_3")

	nbVars := 4

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

	poly := Convert(e, varindex, nbVars)

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
