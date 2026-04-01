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

	logupS := make([]board.Logup, len(_logupS))
	logupT := make([]board.Logup, len(_logupT))
	for i, n := range _logupS {
		logupS[i] = board.NewLogup(moduleS, n)
	}
	for i, n := range _logupT {
		logupT[i] = board.NewLogup(moduleT, n)
	}

	if moduleS != moduleT {
		builder.AddCrossModulesLogupBus(
			board.NewrossModulesLogupBusTuple(
				logupS,
				logupT,
			),
		)
	} else {
		m := builder.Modules[moduleS]
		lagrange := m.LagrangeCol(m.N - 1)
		positives := expr.Col(_logupS[0])
		for i := 1; i < len(_logupS); i++ {
			positives.Add(expr.Col(_logupS[i]))
		}
		negatives := expr.Col(_logupT[0])
		for i := 1; i < len(_logupT); i++ {
			negatives.Add(expr.Col(_logupT[i]))
		}
		relation := lagrange.Mul(positives.Sub(negatives))
		m.AssertZero(relation)
		builder.Modules[moduleS] = m
	}
}
