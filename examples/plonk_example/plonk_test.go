package plonk_example

import (
	"testing"

	"github.com/consensys/loom"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/trace"
)

func getKnownColumns(n int) map[string]bool {

	knowncolumns := make(map[string]bool)
	knowncolumns[ID_Ql] = true
	knowncolumns[ID_Qr] = true
	knowncolumns[ID_Qm] = true
	knowncolumns[ID_Qo] = true
	knowncolumns[ID_Qk] = true
	knowncolumns[ID_ID1] = true
	knowncolumns[ID_ID2] = true
	knowncolumns[ID_ID3] = true
	knowncolumns[ID_S1] = true
	knowncolumns[ID_S2] = true
	knowncolumns[ID_S3] = true
	for i := 0; i < n; i++ {
		knowncolumns[ithInstance(ID_L, i)] = true
		knowncolumns[ithInstance(ID_R, i)] = true
		knowncolumns[ithInstance(ID_O, i)] = true
	}
	return knowncolumns
}

func getIthPlonkRelation(n int) constraint.Relation {

	C := expr.Col(ID_Ql).Mul(expr.Col(ithInstance(ID_L, n))).
		Add(expr.Col(ID_Qr).Mul(expr.Col(ithInstance(ID_R, n)))).
		Add(expr.Col(ID_Qm).Mul(expr.Col(ithInstance(ID_L, n))).Mul(expr.Col(ithInstance(ID_R, n)))).
		Add(expr.Col(ID_Qo).Mul(expr.Col(ithInstance(ID_O, n)))).
		Add(expr.Col(ID_Qk))

	return C
}

// func getIthTuples(n int) (multiSetIds1 [][]string, multiSetIds2 [][]string) {
// 	multiSetIds1 = [][]string{
// 		[]string{ithInstance(ID_L, n), ID_ID1},
// 		[]string{ithInstance(ID_R, n), ID_ID2},
// 		[]string{ithInstance(ID_O, n), ID_ID3},
// 	}

// 	multiSetIds2 = [][]string{
// 		[]string{ithInstance(ID_L, n), ID_S1},
// 		[]string{ithInstance(ID_R, n), ID_S2},
// 		[]string{ithInstance(ID_O, n), ID_S3},
// 	}
// 	return
// }

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
		system.Compile()
	}

}

func TestPlonk(t *testing.T) {

	// This would be the result of a tracer in a real life example (here we use gnark as a tracer)
	basetrace, S, N, err := GetPlonkTrace()
	if err != nil {
		t.Fatal(nil)
	}
	fulltrace := GetPublicPart(basetrace)

	nbTraces := 1
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

	cp := system.Compile()

	proof, err := loom.Prove(cp, fulltrace, nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	err = loom.Verify(cp, &proof, nil, 1)
	if err != nil {
		t.Fatal(err)
	}

}
