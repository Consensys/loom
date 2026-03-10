package proveractions

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
)

// PERMUTATION_SUPPORT prefix for the columns containing the support of a permutation
const PERMUTATION_SUPPORT = "ID"

func GetPermutationSupport(i int) string {
	return fmt.Sprintf("%s_%d", PERMUTATION_SUPPORT, i)
}

type PermutationContext struct {
	// S full permutation, i -> S[i]
	S []int
}

func (pc PermutationContext) String() string {
	return "gen_permutation"
}

func (pc PermutationContext) GetID() PAIdentifier {
	return PERMUTATION_GEN
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

func generatePermutation(support [][]koalabear.Element, S []int) [][]koalabear.Element {
	res := make([][]koalabear.Element, len(support))
	N := len(support[0])
	for i := 0; i < len(support); i++ {
		res[i] = make([]koalabear.Element, N)
	}
	for i := 0; i < len(S); i++ {
		s := S[i]
		res[i/N][i%N].Set(&support[s/N][s%N])
	}
	return res
}

func ComputePermutationColumns(trace trace.Trace, proof *Proof, mu *sync.Mutex, _ []sym.Expr, outputs []string, ctx Ctx) error {

	// 1. get the context
	permutationCtx, ok := ctx.(PermutationContext)
	if !ok {
		return fmt.Errorf("wrong context for ComputePermutationColumns")
	}

	// 2. the size of the permutation should be divisible by N, check how many chunk there are
	sizePermutation := len(permutationCtx.S)
	if sizePermutation%proof.N != 0 {
		return fmt.Errorf("wrong permutation size: it should be a multiple of %d, got %d", proof.N, sizePermutation)
	}

	// 3. generation of the permutation support
	nbChunks := sizePermutation / proof.N
	support, err := generateSupport(nbChunks, proof.N)
	if err != nil {
		return err
	}
	for i := 0; i < len(support); i++ {
		err = RegisterColumn(trace, GetPermutationSupport(i), support[i], mu)
		if err != nil {
			return err
		}
	}

	// 4. generation of the permutation columns
	permutation := generatePermutation(support, permutationCtx.S)
	if len(outputs) != nbChunks {
		return fmt.Errorf("expected %d outputs, got %d\n", nbChunks, len(outputs))
	}
	for i := 0; i < len(outputs); i++ {
		err = RegisterColumn(trace, outputs[i], permutation[i], mu)
		if err != nil {
			return err
		}
	}

	return nil
}
