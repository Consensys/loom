package poly

import (
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

// Evaluation claimed evaluation of a polynomial outside of the RS domain
type Evaluation struct {
	Shift int
	Val   koalabear.Element
}

// Evaluations bare name -> list of evaluations, possibly shifted
type Evaluations map[string][]Evaluation

func LinComb(v []koalabear.Element, alpha koalabear.Element) koalabear.Element {
	var res koalabear.Element
	for _, _v := range v {
		res.Mul(&res, &alpha)
		res.Add(&res, &_v)
	}
	return res
}

// DeepQuotient computes q(X) = (v - p(X)) / (z - X) where p is in Lagrange Normal form
// over domain d and v = p(z) is the claimed evaluation at z outside the domain.
// Returns q in Lagrange Normal form: q[j] = (v - p(ω^j)) / (z - ω^j).
// Panics (division by zero) if z happens to be a domain point.
func DeepQuotient(p Polynomial, v, z koalabear.Element, d *fft.Domain) Polynomial {
	N := len(p)
	q := make(Polynomial, N)
	var omegaJ koalabear.Element
	omegaJ.SetOne()
	omega := d.Generator
	for j := 0; j < N; j++ {
		var num, den koalabear.Element
		num.Sub(&v, &p[j])
		den.Sub(&z, &omegaJ)
		den.Inverse(&den)
		q[j].Mul(&num, &den)
		omegaJ.Mul(&omegaJ, &omega)
	}
	return q
}

// ComputeDeepQuotientValues returns (fz - fwi) / (z - wi)
// for fz in fz and fwi in fwi
// fz are the claimed evaluations of Polynomials at z (z is outside of a RS domain)
// fwi are the evaluations of polynomials at wi (a point on a RS domain).
// if fz corresponds to a shifted polynomial, instead of computing (fz - fwi) / (z - wi) we compute
// (fz - fwi) / (w^shift*z - wi)
// len(fz) = len(fwi), but each fz might contain several evals (as many as shifts)
func ComputeDeepQuotientValues(fz Evaluations, fwi []koalabear.Element, z, wi koalabear.Element, N uint64) []koalabear.Element {

	res := make([]koalabear.Element, 0, len(fz))
	g, _ := koalabear.Generator(N)

	// registers the w^shift*z - wi for various shift
	inv := map[int]koalabear.Element{}
	var tmp koalabear.Element
	tmp.Sub(&z, &wi)
	tmp.Inverse(&tmp)
	inv[0] = tmp

	set := 0
	for _, y := range fz {
		for _, ys := range y {
			tmp.Sub(&ys.Val, &fwi[set])
			_, ok := inv[ys.Shift]
			if !ok {
				var _g koalabear.Element
				_g.Exp(g, big.NewInt(int64(ys.Shift)))
				_g.Mul(&z, &_g).Sub(&_g, &wi).Inverse(&_g)
				inv[ys.Shift] = _g
			}
			den := inv[ys.Shift]
			tmp.Mul(&tmp, &den)
			res = append(res, tmp)
		}
		set++
	}
	return res
}
