package plonk_example

import (
	"testing"

	"github.com/consensys/loom"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/viz"
)

func getIthPlonkRelation(n int) constraint.Relation {

	C := expr.Col(ID_Ql).Mul(expr.Col(ithInstance(ID_L, n))).
		Add(expr.Col(ID_Qr).Mul(expr.Col(ithInstance(ID_R, n)))).
		Add(expr.Col(ID_Qm).Mul(expr.Col(ithInstance(ID_L, n))).Mul(expr.Col(ithInstance(ID_R, n)))).
		Add(expr.Col(ID_Qo).Mul(expr.Col(ithInstance(ID_O, n)))).
		Add(expr.Col(ID_Qk))

	return C
}

func mergeTrace(t1, t2 trace.Trace) trace.Trace {
	res := make(trace.Trace, len(t1)+len(t2))
	for k, v := range t1 {
		res[k] = v
	}
	for k, v := range t2 {
		res[k] = v
	}
	return res
}

func BenchmarkCompile(b *testing.B) {

	// This would be the result of a tracer in a real life example (here we use gnark as a tracer)
	basetrace, S, N, _ := GetPlonkTrace()

	fulltrace := GetPublicPart(basetrace)

	nbTraces := 5
	for i := 0; i < nbTraces; i++ {
		ithprivatepart := GetPrivatePartCopy(basetrace, i)
		fulltrace = mergeTrace(fulltrace, ithprivatepart)
	}

	system := constraint.NewBuilder(N, nil)

	// This is the result of the constraint (lisp ?) file in a real life example. Here we know in advance the shape of the constraints
	// QL*L + QR*R + QM*L*R + QO*O + QK = 0
	for i := 0; i < nbTraces; i++ {
		C := getIthPlonkRelation(i)
		system.AssertZero(C)
		id_l_i := expr.Col(ithInstance(ID_L, i))
		id_r_i := expr.Col(ithInstance(ID_R, i))
		id_o_i := expr.Col(ithInstance(ID_O, i))
		_ = arguments.CopyPermutation(&system, []expr.Expr{id_l_i, id_r_i, id_o_i}, S)

	}

	for i := 0; i < b.N; i++ {
		system.Compile(nil)
	}

}

func TestPlonk(t *testing.T) {

	// This would be the result of a tracer in a real life example (here we use gnark as a tracer)
	basetrace, S, N, err := GetPlonkTrace()
	if err != nil {
		t.Fatal(nil)
	}
	fulltrace := GetPublicPart(basetrace)

	nbTraces := 3
	for i := 0; i < nbTraces; i++ {
		ithprivatepart := GetPrivatePartCopy(basetrace, i)
		fulltrace = mergeTrace(fulltrace, ithprivatepart)
	}

	system := constraint.NewBuilder(N, nil)

	// This is the result of the constraint (lisp ?) file in a real life example. Here we know in advance the shape of the constraints
	// QL*L + QR*R + QM*L*R + QO*O + QK = 0
	// ( (L, ID1), (R, ID2), (O, ID3)) and ( (L, S1), (R, S2), (O, S3)) must be equal as multisets
	for i := 0; i < nbTraces; i++ {
		C := getIthPlonkRelation(i)
		system.AssertZero(C)
		id_l_i := expr.Col(ithInstance(ID_L, i))
		id_r_i := expr.Col(ithInstance(ID_R, i))
		id_o_i := expr.Col(ithInstance(ID_O, i))
		err = arguments.CopyPermutation(&system, []expr.Expr{id_l_i, id_r_i, id_o_i}, S)
		if err != nil {
			t.Fatal(err)
		}
	}

	publicColumns := []string{ID_Ql, ID_Qr, ID_Qm, ID_Qo, ID_Qk}

	cp := system.Compile(publicColumns)

	viz.WriteDerivationPlanDagToHTML(cp, "plonk_dag.html")
	// viz.WriteProofTranscriptRoundsDagToHTML(cp, "plonk_dag.html")

	err = loom.Setup(&cp, fulltrace)

	proof, err := loom.Prove(cp, fulltrace, nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	viz.WriteProofTranscriptRoundsDagToHTML(&proof, "plonk_transcript_rounds.html")

	err = loom.Verify(cp, &proof, nil, 1)
	if err != nil {
		t.Fatal(err)
	}

}
