package cs

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
)

// TestPermutationMultiColumnsSystem verifies that NewPermtutationProtocol
// correctly accepts a valid permutation and rejects an invalid one.
func TestPermutationMultiColumnsSystem(t *testing.T) {

	size := 16
	n := 2 // number of groups
	k := 3 // polynomials per group

	// Build P1: P1[i][j] has value i*k*size + j*size + row + 1 at each position,
	// so all values across all groups and columns are distinct.
	makeGroup := func(t *testing.T, coeffs [][][]koalabear.Element, prefix string) [][]univariate.Polynomial {
		t.Helper()
		polys := make([][]univariate.Polynomial, n)
		var err error
		for i := 0; i < n; i++ {
			polys[i] = make([]univariate.Polynomial, k)
			for j := 0; j < k; j++ {
				polys[i][j], err = univariate.NewInterpolatedPolynomial(
					coeffs[i][j], fmt.Sprintf("%s_%d_%d", prefix, i, j))
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		return polys
	}

	coeffs1 := make([][][]koalabear.Element, n)
	for i := 0; i < n; i++ {
		coeffs1[i] = make([][]koalabear.Element, k)
		for j := 0; j < k; j++ {
			coeffs1[i][j] = make([]koalabear.Element, size)
			for row := 0; row < size; row++ {
				coeffs1[i][j][row].SetUint64(uint64(i*k*size + j*size + row + 1))
			}
		}
	}

	// Build P2 as a tuple-level permutation of P1: rotate the n*size tuples by (n*size/2 + 1).
	// Each tuple is (P1[0][0][row], P1[0][1][row], ..., P1[n-1][k-1][row]).
	total := n * size
	shift := total/2 + 1
	coeffs2 := make([][][]koalabear.Element, n)
	for i := 0; i < n; i++ {
		coeffs2[i] = make([][]koalabear.Element, k)
		for j := 0; j < k; j++ {
			coeffs2[i][j] = make([]koalabear.Element, size)
		}
	}
	for i := 0; i < n; i++ {
		for row := 0; row < size; row++ {
			dst := i*size + row
			src := (dst + shift) % total
			srcGroup := src / size
			srcRow := src % size
			for j := 0; j < k; j++ {
				coeffs2[i][j][row].Set(&coeffs1[srcGroup][j][srcRow])
			}
		}
	}

	P1 := makeGroup(t, coeffs1, "P1")
	P2 := makeGroup(t, coeffs2, "P2")

	t.Run("valid permutation", func(t *testing.T) {
		S, T, err := NewPermtutationProtocol(P1, P2)
		if err != nil {
			t.Fatal(err)
		}
		if err := BruteForceChecker(S); err != nil {
			t.Fatalf("BruteForceChecker: %v", err)
		}
		if err := Verify(&T); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("invalid permutation", func(t *testing.T) {
		// P3: copy of P1 but with one tuple-element changed, breaking multiset equality.
		coeffs3 := make([][][]koalabear.Element, n)
		for i := 0; i < n; i++ {
			coeffs3[i] = make([][]koalabear.Element, k)
			for j := 0; j < k; j++ {
				coeffs3[i][j] = make([]koalabear.Element, size)
				copy(coeffs3[i][j], coeffs1[i][j])
			}
		}
		coeffs3[0][0][0].SetUint64(999999) // break the first tuple

		P3 := makeGroup(t, coeffs3, "P3")

		S, _, err := NewPermtutationProtocol(P1, P3)
		if err != nil {
			t.Fatal(err)
		}
		if err := BruteForceChecker(S); err == nil {
			t.Fatal("expected BruteForceChecker to fail for non-permutation, but it passed")
		}
	})
}
