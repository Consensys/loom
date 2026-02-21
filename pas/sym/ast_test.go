package sym

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

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
