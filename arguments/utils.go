package arguments

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandomString(n int) (string, error) {
	result := make([]byte, n)

	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		result[i] = letters[num.Int64()]
	}

	return string(result), nil
}

func AddLogupEqualityCheck(builder *board.Builder, moduleS, moduleT string, _logupS, _logupT []string) {

	logupS := make([]board.LogupInfo, len(_logupS))
	logupT := make([]board.LogupInfo, len(_logupT))
	for i, n := range _logupS {
		logupS[i] = board.NewLogupInfo(moduleS, n)
	}
	for i, n := range _logupT {
		logupT[i] = board.NewLogupInfo(moduleT, n)
	}

	if moduleS != moduleT {
		builder.AddLogupBus(
			board.NewrossModulesLogupBusTuple(
				logupS,
				logupT,
			),
		)
	} else {
		m := builder.Modules[moduleS]
		positives := expr.Col(_logupS[0])
		for i := 1; i < len(_logupS); i++ {
			positives.Add(expr.Col(_logupS[i]))
		}
		negatives := expr.Col(_logupT[0])
		for i := 1; i < len(_logupT); i++ {
			negatives.Add(expr.Col(_logupT[i]))
		}
		m.AssertEqualAt(positives, negatives, m.N-1)
		builder.Modules[moduleS] = m
	}
}
