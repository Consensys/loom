package sym

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

type Monomial struct {
	Exponents []uint32 // length = n
}

func encode(exp []uint32) string {
	r := new(strings.Builder)
	for _, e := range exp {
		fmt.Fprintf(r, "%d,", e)
	}
	return r.String()
}

func decode(s string) []uint32 {
	result := make([]uint32, 0, 8)

	var current uint32
	for i := 0; i < len(s); i++ {
		c := s[i]

		if c == ',' {
			result = append(result, current)
			current = 0
			continue
		}

		current = current*10 + uint32(c-'0')
	}

	return result
}

type Polynomial struct {
	numCommittedColumns int
	Coeff               map[string]koalabear.Element
}

type VarIndex map[string]int

func ConstPoly(n int, c koalabear.Element) Polynomial {
	if c.IsZero() {
		return Polynomial{numCommittedColumns: n, Coeff: map[string]koalabear.Element{}}
	}

	zero := make([]uint32, n)
	m := encode(zero)

	return Polynomial{
		numCommittedColumns: n,
		Coeff: map[string]koalabear.Element{
			m: c,
		},
	}
}

func VarPoly(n, idx int) Polynomial {
	exp := make([]uint32, n)
	exp[idx] = 1

	var one koalabear.Element
	one.SetOne()
	return Polynomial{
		numCommittedColumns: n,
		Coeff: map[string]koalabear.Element{
			encode(exp): one,
		},
	}
}

func (p Polynomial) Add(q Polynomial) Polynomial {
	result := make(map[string]koalabear.Element)

	// copy p
	for m, c := range p.Coeff {
		result[m] = c
	}

	// add q
	for m, c := range q.Coeff {
		if existing, ok := result[m]; ok {
			sum := existing.Add(&existing, &c)
			if sum.IsZero() {
				delete(result, m)
			} else {
				result[m] = *sum
			}
		} else {
			result[m] = c
		}
	}

	return Polynomial{numCommittedColumns: p.numCommittedColumns, Coeff: result}
}

func (p Polynomial) Sub(q Polynomial) Polynomial {
	result := make(map[string]koalabear.Element)

	// copy p
	for m, c := range p.Coeff {
		result[m] = c
	}

	// subtract q
	for m, c := range q.Coeff {
		var negC koalabear.Element
		negC.Neg(&c)

		if existing, ok := result[m]; ok {
			var diff koalabear.Element
			diff.Add(&existing, &negC)
			if diff.IsZero() {
				delete(result, m)
			} else {
				result[m] = diff
			}
		} else {
			result[m] = negC
		}
	}

	return Polynomial{numCommittedColumns: p.numCommittedColumns, Coeff: result}
}

func (p Polynomial) Mul(q Polynomial) Polynomial {
	result := make(map[string]koalabear.Element)

	for m1, c1 := range p.Coeff {
		exp1 := decode(m1)

		for m2, c2 := range q.Coeff {
			exp2 := decode(m2)

			newExp := make([]uint32, p.numCommittedColumns)
			for i := 0; i < p.numCommittedColumns; i++ {
				newExp[i] = exp1[i] + exp2[i]
			}

			key := encode(newExp)
			var coeff koalabear.Element
			coeff.Mul(&c1, &c2)

			if existing, ok := result[key]; ok {
				var sum koalabear.Element
				sum.Add(&existing, &coeff)
				coeff = sum
			}

			if coeff.IsZero() {
				delete(result, key)
			} else {
				result[key] = coeff
			}
		}
	}

	return Polynomial{numCommittedColumns: p.numCommittedColumns, Coeff: result}
}

func (p Polynomial) Pow(k uint32) Polynomial {

	var one koalabear.Element
	one.SetOne()

	if k == 0 {
		return ConstPoly(p.numCommittedColumns, one)
	}
	if k == 1 {
		return p
	}

	result := ConstPoly(p.numCommittedColumns, one)
	base := p

	for k > 0 {
		if k&1 == 1 {
			result = result.Mul(base)
		}
		base = base.Mul(base)
		k >>= 1
	}

	return result
}

// Degree returns the total degree of the polynomial (maximum sum of exponents across all monomials)
func (p Polynomial) Degree() int {
	if len(p.Coeff) == 0 {
		return NegInf // Zero polynomial has degree -infinity
	}

	maxDegree := NegInf
	for monomialKey := range p.Coeff {
		exponents := decode(monomialKey)
		totalDegree := 0
		for _, exp := range exponents {
			totalDegree += int(exp)
		}
		if totalDegree > maxDegree {
			maxDegree = totalDegree
		}
	}

	return maxDegree
}

// NumCommittedColumns returns the number of variables in the polynomial
func (p Polynomial) NumCommittedColumns() int {
	return p.numCommittedColumns
}

func Convert(e Expr, varIndex VarIndex, n int) Polynomial {
	switch node := e.(type) {

	case *Const:
		return ConstPoly(n, node.Value)

	case *CommittedColumn:
		idx := varIndex[node.Name]
		return VarPoly(n, idx)

	case *Challenge:
		idx := varIndex[node.Name]
		return VarPoly(n, idx)

	case *ComputableColumn:
		idx := varIndex[node.Name]
		return VarPoly(n, idx)

	case *Add:
		left := Convert(node.Left, varIndex, n)
		right := Convert(node.Right, varIndex, n)
		return left.Add(right)

	case *Sub:
		left := Convert(node.Left, varIndex, n)
		right := Convert(node.Right, varIndex, n)
		return left.Sub(right)

	case *Mul:
		left := Convert(node.Left, varIndex, n)
		right := Convert(node.Right, varIndex, n)
		return left.Mul(right)

	case *Pow:
		base := Convert(node.Base, varIndex, n)
		return base.Pow(node.Exp)

	default:
		panic("unsupported node")
	}
}
