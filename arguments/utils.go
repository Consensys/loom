package arguments

import (
	"fmt"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

func AddLogupEqualityCheck(builder *board.Builder, moduleS, moduleT string, logupS, logupT []expr.Expr) {

	if moduleS != moduleT {
		positives := make([]string, len(logupS))
		negatives := make([]string, len(logupT))
		ns := builder.Modules[moduleS].N - 1
		nt := builder.Modules[moduleT].N - 1
		for i, ls := range logupS {
			lsName := fmt.Sprintf("%s_%d", ls.String(), ns)
			positives[i] = lsName
			builder.AddMakeIthValuePublicStep(moduleS, ls, lsName, ns) // this step makes logupS[N-1] accessible to the verifier
		}
		for i, lt := range logupT {
			ltName := fmt.Sprintf("%s_%d", lt.String(), nt)
			negatives[i] = ltName
			builder.AddMakeIthValuePublicStep(moduleT, lt, ltName, nt)
		}
		builder.LogupBus = append(builder.LogupBus, board.NewLogupBus(positives, negatives))
	} else {
		m := builder.Modules[moduleS]
		positives := logupS[0]
		for i := 1; i < len(logupS); i++ {
			positives.Add(logupS[i])
		}
		negatives := logupT[0]
		for i := 1; i < len(logupT); i++ {
			negatives.Add(logupT[i])
		}
		m.AssertEqualAt(positives, negatives, m.N-1)
		builder.Modules[moduleS] = m
	}
}
