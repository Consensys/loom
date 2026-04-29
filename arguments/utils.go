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
		nsRelative := 0 // absolute position modulesS.N-1-nsRelative
		ntRelative := 0 // absolute position modulesS.N-1-ntRelative
		for i, ls := range logupS {
			lsName := fmt.Sprintf("%s_%d", ls.String(), nsRelative)
			positives[i] = lsName
			builder.AddMakeRelativeIthValuePublicStep(moduleS, ls, lsName, nsRelative) // this step makes logupS[N-1] accessible to the verifier
		}
		for i, lt := range logupT {
			ltName := fmt.Sprintf("%s_%d", lt.String(), ntRelative)
			negatives[i] = ltName
			builder.AddMakeRelativeIthValuePublicStep(moduleT, lt, ltName, ntRelative) // this step makes logupS[N-1] accessible to the verifier
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
		m.AssertEqualRelativeAt(positives, negatives, 0)
		builder.Modules[moduleS] = m
	}
}
