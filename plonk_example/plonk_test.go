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

func GetPlonkTrace(t *testing.T) (cs.Trace, int) {

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

	nbPublic := ccs.GetNbPublicVariables()
	nbConstraints := ccs.GetNbConstraints()
	// Domain size must accommodate both public-input placeholder rows and actual
	// constraint rows, matching gnark's evaluateLROSmallDomain which uses
	// NextPowerOfTwo(nbConstraints + len(cs.Public)).
	size := univariate.NextPowerOfTwo(nbConstraints + nbPublic)
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

	T, err := BuildTrace(publicTrace, solution, nbPublic)
	if err != nil {
		t.Fatal(err)
	}

	return T, int(d.Cardinality)

}

// relation returns the Expr a + challenge*b
func foldingHelper(a, b, challenge string) sym.Expr {
	return sym.NewVar(a).Add(sym.NewVar(b).Mul(sym.NewPlaceholder(challenge)))
}

// f1 := L+β ID1, f2 := R+β ID2, f3 := O+β ID3,
//
// g1 := L+β S1, g2 := R+β S2, g3 := O+β S3
func generateFoldings(protocol *cs.Protocol) error {
	foldings := []struct {
		a, b, id string
	}{
		{ID_L, ID_ID1, "f1"},
		{ID_R, ID_ID2, "f2"},
		{ID_O, ID_ID3, "f3"},
		{ID_L, ID_S1, "g1"},
		{ID_R, ID_S2, "g2"},
		{ID_O, ID_S3, "g3"},
	}
	for _, f := range foldings {
		if err := protocol.NewIOP(
			cs.NewSimpleIOP,
			foldingHelper(f.a, f.b, "beta"),
			f.id,
			"", // no challenge generated during this protocol
			cs.WithCaching(),
		); err != nil {
			return err
		}
	}
	return nil
}

func TestPlonk(t *testing.T) {

	T, N := GetPlonkTrace(t)

	// Upon receiving a trace and a list of hardcoded constraints, we build the protocol for proving satisfiability of the trace against the constraint.
	// 1 - We build a system, storing the trace and the vanishing constraints constraints (to follow go-corset naming)
	// In plonk, there is one such constraint:
	// QL*L + QR*R + QM*L*R + QO*O + QK = 0

	// QL*L + QR*R + QM*L*R + QO*O + QK = 0
	C := sym.NewVar(ID_Ql).Mul(sym.NewVar(ID_L)).
		Add(sym.NewVar(ID_Qr).Mul(sym.NewVar(ID_R))).
		Add(sym.NewVar(ID_Qm).Mul(sym.NewVar(ID_L)).Mul(sym.NewVar(ID_R))).
		Add(sym.NewVar(ID_Qo).Mul(sym.NewVar(ID_O))).
		Add(sym.NewVar(ID_Qk))

	S := cs.NewSystem(T, []cs.Constraint{}, []cs.Constraint{C}, N) // we cache QL*L + QR*R + QM*L*R + QO*O + QK, we are going to fold it later

	// 2 - we begin the protocol
	protocol := cs.NewProtocol(S)

	// 3 - for the permutation argument, we need to prove that
	// ( (L, ID1), (R, ID2), (O, ID3)) and ( (L, S1), (R, S2), (O, S3)) must be equal as multisets
	// 3.1 - sample random β depending on L, R, O, ID1, ID2, ID3, S1, S2, S3
	// 3.2 - fold each subsets: f1 := L+β ID1, f2 := R+β ID2, f3 := O+β ID3, g1 := L+β S1, g2 := R+β S2, g3 := O+β S3
	// 3.3 - run the hinted IOP NewGrandProductIOP, to prove that (f1, f2, f3) and (g1, g2, g3) are equal up to permutation. It outputs a new polynomial R
	// 3.4 - ensure R[0]=1 by adding a Lagrange constraint

	// the challenge is recorded in the trace, as a constant column. There is no need to pick it in this very particular case
	_, err := protocol.SendMeAChallenge([]string{ID_L, ID_R, ID_O, ID_ID1, ID_ID2, ID_ID3, ID_S1, ID_S2, ID_S3}, "beta")
	if err != nil {
		t.Fatal(err)
	}

	// 3.2 - fold each subset into a single column
	if err = generateFoldings(&protocol); err != nil {
		t.Fatal(err)
	}

	// NewGrandProductIOP runs grand product between the sets (f1, f2, f3) and (g1, g2, g3)
	err = protocol.NewHintedIOP(
		cs.NewGrandProductIOP,
		[]string{"f1", "f2", "f3", "g1", "g2", "g3"},
		"GrandProduct",
		"gamma",
		cs.WithCaching(), // cache the constraint, we are going to fold it later
	)
	if err != nil {
		t.Fatal(err)
	}

	// add a lagrange constraint, ensuring that GrandProduct[0]=1
	var one koalabear.Element
	one.SetOne()
	err = protocol.NewLagrangeConstraint("GrandProduct", 0, one, cs.WithCaching())
	if err != nil {
		t.Fatal(err)
	}

	// Fold all the cached constraint
	err = protocol.FoldCachedConstraints("alpha") // the prover queries alpha from the verifier. The verifier derives the alpha from the commitments of the polynomials in the constraints to fold
	if err != nil {
		t.Fatal(err)
	}

	// Finalise the protocol:
	// prover compute the quotient,
	// verifier sends zeta (point of evaluation)
	// prover sends opening proof of all polynomials in the final constraint
	proof, err := protocol.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the proof
	cs.Verify(&proof)

}
