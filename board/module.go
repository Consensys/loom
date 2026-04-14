package board

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	"github.com/consensys/loom/trace"
)

type Relation = expr.Expr

type Module struct {
	Relations []Relation
	GenCol    []Gen // public columns generator (lagrange, permutation columns, selectors, etc)
	N         int
}

func NewModule() Module {
	var res Module
	res.Relations = make([]Relation, 0)
	res.GenCol = make([]Gen, 0)
	return res
}

type CompiledModule struct {
	GenCol            []Gen // public columns generator (lagrange, permutation columns, etc)
	N                 int
	VanishingRelation *dag.DAG
	D                 *fft.Domain
}

type Gen interface {
	Gen(t trace.Trace, m *CompiledModule)
}

type LagrangeGen struct {
	i, N int
}

func (p LagrangeGen) Gen(t trace.Trace, m *CompiledModule) {
	res := make([]koalabear.Element, p.N)
	res[p.i].SetOne()
	name := constants.LagrangeName(p.i, p.N)
	if _, ok := t[name]; ok {
		return
	}
	t[name] = res
}

func (m *Module) LagrangeCol(i int) expr.Expr {
	m.GenCol = append(m.GenCol, LagrangeGen{i: i, N: m.N})
	name := constants.LagrangeName(i, m.N)
	return &expr.Leaf{Type: expr.LagrangeColumn, Name: name}
}

func (m *Module) AssertEqualAt(A, B expr.Expr, i int) {
	relation := A.Sub(B)
	relation = relation.Mul(m.LagrangeCol(i))
	m.AssertZero(relation)
}

func (m *Module) AssertZero(relation expr.Expr) {
	m.Relations = append(m.Relations, relation)
}

func (m *Module) AssertZeroExceptAt(relation expr.Expr, i ...int) {
	one := koalabear.One()
	conj := expr.Const(one).Sub(m.LagrangeCol(i[0]))
	for k := 1; k < len(i); k++ {
		_conj := expr.Const(one).Sub(m.LagrangeCol(i[k]))
		conj = conj.Mul(_conj)
	}
	_relation := relation.Mul(conj)
	m.AssertZero(_relation)
}

func (m *Module) AssertZeroAt(relation expr.Expr, i ...int) {
	disj := expr.Expr(m.LagrangeCol(i[0]))
	for k := 1; k < len(i); k++ {
		disj = disj.Add(m.LagrangeCol(i[k]))
	}
	_relation := relation.Mul(disj)
	m.AssertZero(_relation)
}

type SelectorGen struct {
	Idx  []int
	Name string
}

func (s SelectorGen) Gen(t trace.Trace, m *Module) error {
	res := make([]koalabear.Element, m.N)
	for _, idx := range s.Idx {
		res[idx].SetOne()
	}
	err := trace.RegisterColumn(t, s.Name, res)
	if err != nil {
		return err
	}
	return nil
}

type PermutationGen struct {
	S    []int64
	Name string
}

func (p PermutationGen) Gen(t trace.Trace, m *Module) error {

	// 1 - gen permutation support
	if len(p.S)%m.N != 0 {
		return fmt.Errorf("size of permutation %d is not a multiplie of the module size %d", len(p.S), m.N)
	}
	nbChunks := len(p.S) / m.N
	support, err := generateSupport(nbChunks, m.N)
	if err != nil {
		return err
	}
	for i := 0; i < nbChunks; i++ {
		err := trace.RegisterColumn(t, fmt.Sprintf("ID_%d", i), support[i])
		if err != nil {
			return err
		}
	}

	// 2 - register permutation columns
	perm := generatePermutation(support, p.S)
	for i := 0; i < nbChunks; i++ {
		err := trace.RegisterColumn(t, fmt.Sprintf("%s_%d", p.Name, i), perm[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func generateSupport(nbChunks, N int) ([][]koalabear.Element, error) {
	var acc koalabear.Element
	frGen := fft.GeneratorFullMultiplicativeGroup()
	acc.Set(&frGen)
	res := make([][]koalabear.Element, nbChunks)
	res[0] = make([]koalabear.Element, N)
	res[0][0].SetOne()
	g, err := koalabear.Generator(uint64(N))
	if err != nil {
		return res, err
	}
	for i := 1; i < N; i++ {
		res[0][i].Mul(&res[0][i-1], &g)
	}
	for i := 1; i < nbChunks; i++ {
		res[i] = make([]koalabear.Element, N)
		for j := 0; j < N; j++ {
			res[i][j].Mul(&res[i-1][j], &frGen)
		}
	}
	return res, nil
}

func generatePermutation(support [][]koalabear.Element, S []int64) [][]koalabear.Element {
	res := make([][]koalabear.Element, len(support))
	N := len(support[0])
	for i := 0; i < len(support); i++ {
		res[i] = make([]koalabear.Element, N)
	}
	for i := 0; i < len(S); i++ {
		s := S[i]
		res[i/N][i%N].Set(&support[int(s)/N][int(s)%N])
	}
	return res
}
