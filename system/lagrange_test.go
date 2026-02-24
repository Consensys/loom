package system

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

func TestParseLagrangeID(t *testing.T) {
	cases := []struct {
		entry, N int
	}{
		{0, 16},
		{3, 16},
		{15, 16},
		{0, 32},
		{7, 32},
	}

	for _, c := range cases {
		id := GetLagrangeID(c.entry, c.N)
		gotEntry, gotN, _ := ParseLagrangeID(id)
		if gotEntry != int64(c.entry) || gotN != uint64(c.N) {
			t.Errorf("ParseLagrangeID(%q) = (%d, %d), want (%d, %d)",
				id, gotEntry, gotN, c.entry, c.N)
		}
	}
}

func TestGetLagrangeFunction(t *testing.T) {

	N := 16
	for i := 0; i < N; i++ {
		lag := GetLagrangeID(i, N)
		lagrangeColumn, err := NewLagrangeColumn(lag)
		if err != nil {
			t.Fatal(err)
		}
		// ensure lagFunc is not zero
		var z koalabear.Element
		z.SetRandom()
		u := lagrangeColumn.F(z)
		if u.IsZero() {
			t.Fatal("lagrange function is zero")
		}
		// ensure lagFunc(\omega^j) if zero for j!=i
		w, _ := koalabear.Generator(uint64(N))
		omegai := koalabear.One()
		one := koalabear.One()

		for j := 0; j < N; j++ {
			col := lagrangeColumn.Gen()
			if i == j {
				c := col.GetCoefficient(j)
				if !c.Equal(&one) {
					t.Errorf("%d-th lagrange function in lagrange basis should 1 at %d", j, j)
				}
				continue
			}
			c := col.GetCoefficient(j)
			if !c.IsZero() {
				t.Errorf("%d-th lagrange function in lagrange basis should 0 at %d", i, j)
			}
			u := lagrangeColumn.F(omegai)
			if !u.IsZero() {
				t.Fatal("Lag_i(w^j) must be zero for i!=j")
			}
			omegai.Mul(&omegai, &w)
		}
	}

}

func TestAddConstraint(t *testing.T) {
	const size = 16
	const entry = 3

	var value koalabear.Element
	value.SetUint64(42)

	// Build a polynomial with the expected value at the given entry.
	coeffs := make([]koalabear.Element, size)
	for i := range coeffs {
		coeffs[i].SetRandom()
	}
	coeffs[entry] = value

	P, err := univariate.NewInterpolatedPolynomial(coeffs, "P")
	if err != nil {
		t.Fatal(err)
	}

	// Get the Lagrange basis column for the entry and add it to the trace manually.
	lagrangeID := GetLagrangeID(entry, size)
	lagGen, err := NewLagrangeColumn(lagrangeID)
	lagrangeCol := lagGen.Gen()

	S := System{
		Trace: map[string]*univariate.Polynomial{
			"P":        &P,
			lagrangeID: &lagrangeCol,
		},
		N: size,
	}

	// Construct the Lagrange constraint manually: (P - value) * LAGRANGE_entry = 0
	C := sym.NewVar("P").Sub(sym.NewConst(value)).Mul(sym.NewVar(lagrangeID))

	if err := AddConstraint(&S, C); err != nil {
		t.Fatal(err)
	}

	if len(S.Constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(S.Constraints))
	}
	if len(S.CachedConstraints) != 0 {
		t.Fatalf("expected 0 cached constraints, got %d", len(S.CachedConstraints))
	}

	if err := BruteForceChecker(S); err != nil {
		t.Fatal(err)
	}
	if err := QuotientChecker(S); err != nil {
		t.Fatal(err)
	}

	// CacheMe routes the constraint to CachedConstraints instead.
	S2 := System{
		Trace: map[string]*univariate.Polynomial{
			"P":        &P,
			lagrangeID: &lagrangeCol,
		},
		N: size,
	}
	if err := AddConstraint(&S2, C, CacheMe()); err != nil {
		t.Fatal(err)
	}
	if len(S2.Constraints) != 0 {
		t.Fatalf("expected 0 active constraints, got %d", len(S2.Constraints))
	}
	if len(S2.CachedConstraints) != 1 {
		t.Fatalf("expected 1 cached constraint, got %d", len(S2.CachedConstraints))
	}
}

func TestFold(t *testing.T) {

	const size = 16

	// Build a polynomial P with known values at entries 0, 1, 2.
	var v0, v1, v2 koalabear.Element
	v0.SetUint64(7)
	v1.SetUint64(13)
	v2.SetUint64(42)

	coeffs := make([]koalabear.Element, size)
	for i := range coeffs {
		coeffs[i].SetRandom()
	}
	coeffs[0] = v0
	coeffs[1] = v1
	coeffs[2] = v2

	P, err := univariate.NewInterpolatedPolynomial(coeffs, "P")
	if err != nil {
		t.Fatal(err)
	}

	S := System{
		Trace:             map[string]*univariate.Polynomial{"P": &P},
		Constraints:       []Constraint{},
		CachedConstraints: []Constraint{},
		N:                 size,
	}

	// Cache three Lagrange constraints: P[0]=v0, P[1]=v1, P[2]=v2.
	if err := NewLagrangeConstraint(&S, "P", 0, v0, CacheMe()); err != nil {
		t.Fatal(err)
	}
	if err := NewLagrangeConstraint(&S, "P", 1, v1, CacheMe()); err != nil {
		t.Fatal(err)
	}
	if err := NewLagrangeConstraint(&S, "P", 2, v2, CacheMe()); err != nil {
		t.Fatal(err)
	}

	if len(S.CachedConstraints) != 3 {
		t.Fatalf("expected 3 cached constraints, got %d", len(S.CachedConstraints))
	}
	if len(S.Constraints) != 0 {
		t.Fatalf("expected 0 active constraints before Fold, got %d", len(S.Constraints))
	}

	// Fold the three cached constraints into one using a challenge.
	var alpha koalabear.Element
	alpha.SetUint64(5)
	challenge := Challenge{Name: "alpha", Value: alpha}
	addChallengeInTrace(&S, challenge)

	if err := FoldCachedConstraints(&S, challenge); err != nil {
		t.Fatal(err)
	}

	// After Fold: cache must be empty, exactly one constraint recorded.
	if len(S.CachedConstraints) != 0 {
		t.Fatalf("expected empty cache after Fold, got %d", len(S.CachedConstraints))
	}
	if len(S.Constraints) != 1 {
		t.Fatalf("expected 1 constraint after Fold, got %d", len(S.Constraints))
	}

	if err := BruteForceChecker(S); err != nil {
		t.Fatal(err)
	}
	if err := QuotientChecker(S); err != nil {
		t.Fatal(err)
	}
}

func TestLagrangeSystem(t *testing.T) {

	// generate a random polynomial P in Lagrange form of size 16, whose 5-th entry is equal to 10
	size := 16
	entry := 5
	var targetValue koalabear.Element
	targetValue.SetUint64(10)

	// Create random evaluations
	coeffs := make([]koalabear.Element, size)
	for i := 0; i < size; i++ {
		coeffs[i].SetRandom()
	}
	// Set the 5th entry to 10
	coeffs[entry] = targetValue

	// Create polynomial in Lagrange form (NewInterpolatedPolynomial creates in Lagrange basis)
	P, err := univariate.NewInterpolatedPolynomial(coeffs, "P")
	if err != nil {
		t.Fatalf("Failed to create polynomial: %v", err)
	}

	// Verify P is in Lagrange basis and the 5th entry is 10
	if P.EP.Basis != univariate.Lagrange {
		t.Fatalf("Expected Lagrange basis, got %v", P.EP.Basis)
	}
	actualValue := P.GetCoefficient(entry)
	if !actualValue.Equal(&targetValue) {
		t.Fatalf("Expected P[%d] = %v, got %v", entry, targetValue.String(), actualValue.String())
	}

	// create a Lagrange protocol
	T := make(map[string]*univariate.Polynomial)
	T["P0"] = &P
	S := System{
		Trace:             T,
		Constraints:       []Constraint{},
		CachedConstraints: []Constraint{},
		N:                 size,
	}
	err = NewLagrangeConstraint(&S, "P0", entry, targetValue)
	if err != nil {
		t.Fatal(err)
	}

	err = BruteForceChecker(S)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(S)
	if err != nil {
		t.Fatal(err)
	}

}
