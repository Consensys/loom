package fri

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

func TestFoldLayerBaseBitReversedMatchesNormalReference(t *testing.T) {
	var alpha koalabear.Element
	alpha.SetUint64(7)
	invTwo := testInvTwo()

	for _, n := range []int{8, 32} {
		t.Run(fmt.Sprintf("N%d", n), func(t *testing.T) {
			domain := fft.NewDomain(uint64(n))
			layer := testBaseLayer(n, 10)

			got := foldLayerBase(layer, alpha, domain, invTwo)
			want := foldLayerBaseNormalReference(layer, alpha, domain, invTwo)

			if len(got) != len(want) {
				t.Fatalf("len(got) = %d, want %d", len(got), len(want))
			}
			for i := range got {
				if !got[i].Equal(&want[i]) {
					t.Fatalf("row %d: got %s, want %s", i, got[i].String(), want[i].String())
				}
			}
		})
	}
}

func TestFoldLayerExtBitReversedMatchesNormalReference(t *testing.T) {
	var alpha ext.E6
	alpha.B0.A0.SetUint64(7)
	alpha.B1.A1.SetUint64(11)
	alpha.B2.A0.SetUint64(13)
	invTwo := testInvTwo()

	for _, n := range []int{8, 32} {
		t.Run(fmt.Sprintf("N%d", n), func(t *testing.T) {
			domain := fft.NewDomain(uint64(n))
			layer := testExtLayer(n, 20)

			got := foldLayerExt(layer, alpha, domain, invTwo)
			want := foldLayerExtNormalReference(layer, alpha, domain, invTwo)

			if len(got) != len(want) {
				t.Fatalf("len(got) = %d, want %d", len(got), len(want))
			}
			for i := range got {
				if !got[i].Equal(&want[i]) {
					t.Fatalf("row %d: got %s, want %s", i, got[i].String(), want[i].String())
				}
			}
		})
	}
}

func foldLayerBaseNormalReference(layer []koalabear.Element, alpha koalabear.Element, domain *fft.Domain, invTwo koalabear.Element) []koalabear.Element {
	n := len(layer)
	half := n / 2
	normal := make([]koalabear.Element, n)
	for i := range normal {
		normal[i].Set(&layer[bitReverseIndex(i, n)])
	}

	foldedNormal := make([]koalabear.Element, half)
	for i := range foldedNormal {
		p, q := normal[i], normal[i+half]
		xInv := powElement(domain.GeneratorInv, i)

		var sum, diff koalabear.Element
		sum.Add(&p, &q)
		sum.Mul(&sum, &invTwo)
		diff.Sub(&p, &q)
		diff.Mul(&diff, &invTwo)
		diff.Mul(&diff, &xInv)
		diff.Mul(&diff, &alpha)
		foldedNormal[i].Add(&sum, &diff)
	}

	want := make([]koalabear.Element, half)
	for i := range foldedNormal {
		want[bitReverseIndex(i, half)].Set(&foldedNormal[i])
	}
	return want
}

func foldLayerExtNormalReference(layer []ext.E6, alpha ext.E6, domain *fft.Domain, invTwo koalabear.Element) []ext.E6 {
	n := len(layer)
	half := n / 2
	normal := make([]ext.E6, n)
	for i := range normal {
		normal[i].Set(&layer[bitReverseIndex(i, n)])
	}

	foldedNormal := make([]ext.E6, half)
	for i := range foldedNormal {
		p, q := normal[i], normal[i+half]
		xInv := powElement(domain.GeneratorInv, i)

		var sum, diff ext.E6
		sum.Add(&p, &q)
		sum.MulByElement(&sum, &invTwo)
		diff.Sub(&p, &q)
		diff.MulByElement(&diff, &invTwo)
		diff.MulByElement(&diff, &xInv)
		diff.Mul(&diff, &alpha)
		foldedNormal[i].Add(&sum, &diff)
	}

	want := make([]ext.E6, half)
	for i := range foldedNormal {
		want[bitReverseIndex(i, half)].Set(&foldedNormal[i])
	}
	return want
}

func powElement(x koalabear.Element, exponent int) koalabear.Element {
	var res koalabear.Element
	res.ExpInt64(x, int64(exponent))
	return res
}

func testInvTwo() koalabear.Element {
	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)
	return invTwo
}
