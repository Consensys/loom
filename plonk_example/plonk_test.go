package plonk_example

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	gnark_plonk "github.com/consensys/gnark/backend/plonk/koalabear"
	gnark_cs "github.com/consensys/gnark/constraint/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/iop/cs"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// plonk circuit
type Circuit struct {
	A, B, C frontend.Variable
	D       frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {

	a := api.Mul(c.A, c.B)
	a = api.Add(a, c.C)

	for i := 0; i < 20; i++ {
		a = api.Mul(a, a)
	}

	api.AssertIsDifferent(a, c.D)

	return nil
}

func GetPlonkTrace(t *testing.T) cs.Trace {

	assignment := Circuit{
		A: 3,
		B: 4,
		C: 5,
		D: 6,
	}
	witness, err := frontend.NewWitness(&assignment, koalabear.Modulus())
	if err != nil {
		t.Fatal(err)
	}

	var circuit Circuit

	ccs, err := frontend.CompileU32(koalabear.Modulus(), scs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	spr, ok := ccs.(*gnark_cs.SparseR1CS)
	if !ok {
		t.Fatal("cannot cast ccs to *gnark_cs.SparseR1CS")
	}

	nbConstraints := ccs.GetNbConstraints()
	size := univariate.NextPowerOfTwo(nbConstraints)
	d := fft.NewDomain(uint64(size))

	publicTrace := gnark_plonk.NewTrace(spr, d)

	isolution, err := spr.Solve(witness)
	if err != nil {
		t.Fatal(err)
	}
	solution, ok := isolution.(*gnark_cs.SparseR1CSSolution)
	if !ok {
		t.Fatal("cannot cast isolution to *gnark_cs.SparseR1CSSolution")
	}

	T, err := BuildTrace(publicTrace, solution)
	if err != nil {
		t.Fatal(err)
	}

	return T

}

// getColByName local function only
func getColByName(trace cs.Trace, name string) univariate.Polynomial {
	var res univariate.Polynomial
	for i := 0; i < len(trace); i++ {
		if trace[i].ID == name {
			res = trace[i]
		}
	}
	return res
}

func TestPlonk(t *testing.T) {

	T := GetPlonkTrace(t)

	// Now we have a plonk trace, that is a list of columns.
	//  It is a 'real life' example of a trace processing.
	//
	// We have a trace:
	//
	// 	QL | QR | QM | QO | QK | S1 | S2 | S3 | L | R | O | ID1 | ID2 | ID3
	//  1  | 3  | 91 | ..
	//  ...
	//
	// with a list of constraints attached to it:
	//	1. QL*L + QR*R + QM*L*R + QO*O + QK = 0 // vanishing constraint
	//  2. ( (L,ID1), (R,ID2), (O,ID2) ) and ( (L,S1), (R,S2), (O,S3) ) are equal up to permutation

	// 1. QL*L + QR*R + QM*L*R + QO*O + QK = 0
	qll := sym.NewVar(ID_Ql).Mul(sym.NewVar(ID_L))
	qrr := sym.NewVar(ID_Qr).Mul(sym.NewVar(ID_R))
	qmlr := sym.NewVar(ID_Qm).Mul(sym.NewVar(ID_L)).Mul(sym.NewVar(ID_R))
	qoo := sym.NewVar(ID_Qo).Mul(sym.NewVar(ID_O))
	qk := sym.NewVar(ID_Qk)
	C := qll.Add(qrr).Add(qmlr).Add(qoo).Add(qk)
	arithSystem, arithProof, err := cs.NewVanishingProtocol(T[:11], C)
	if err != nil {
		t.Fatal(err)
	}
	err = cs.BruteForceChecker(arithSystem)
	if err != nil {
		t.Fatal(err)
	}
	err = cs.Verify(&arithProof)
	if err != nil {
		t.Fatal(err)
	}

	// 2. ( (L,ID1), (R,ID2), (O,ID2) ) and ( (L,S1), (R,S2), (O,S3) ) are equal up to permutation
	group1 := make([][]univariate.Polynomial, 3)
	group2 := make([][]univariate.Polynomial, 3)
	for i := 0; i < 3; i++ {
		group1[i] = make([]univariate.Polynomial, 2)
		group2[i] = make([]univariate.Polynomial, 2)
	}
	group1[0][0] = getColByName(T, ID_L)
	group1[0][1] = getColByName(T, ID_ID1)
	group1[1][0] = getColByName(T, ID_R)
	group1[1][1] = getColByName(T, ID_ID2)
	group1[2][0] = getColByName(T, ID_O)
	group1[2][1] = getColByName(T, ID_ID3)

	group2[0][0] = getColByName(T, ID_L)
	group2[0][1] = getColByName(T, ID_S1)
	group2[1][0] = getColByName(T, ID_R)
	group2[1][1] = getColByName(T, ID_S2)
	group2[2][0] = getColByName(T, ID_O)
	group2[2][1] = getColByName(T, ID_S3)

	sysPermutation, proofPermutation, err := cs.NewPermtutationProtocol(group1, group2)
	if err != nil {
		t.Fatal(err)
	}
	err = cs.BruteForceChecker(sysPermutation)
	if err != nil {
		t.Fatal(err)
	}
	err = cs.Verify(&proofPermutation)
	if err != nil {
		t.Fatal(err)
	}
}
