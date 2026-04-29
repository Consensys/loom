// some namings shared accross protocols, prefixed by the name of the repo, to ensure there is no collisin with other challenges
package constants

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const RANGE_MODULE = "range"
const FINAL_EVALUATION_POINT = "__zeta"
const SUFFIX_SHIFT_SPLIT = "_"
const SUFFIX_SHIFT = "shift"
const LOGUP = "logup"
const SIZE_RANDOM_STRING = 10 // size of the names randomly created for the intermediate columns issued with prover actions

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

func RangeModuleName(bound uint64) string {
	return fmt.Sprintf("%s_%d", RANGE_MODULE, bound)
}

func RangeColName(bound uint64) string {
	return fmt.Sprintf("%s.%s_%d", RANGE_MODULE, "bound", bound)
}

func QuotientChunkName(moduleName string, chunk int) string {
	return fmt.Sprintf("%s.%d", moduleName, chunk)
}

func ParseLagrangeName(name string) (i int) {
	parts := strings.Split(name, ".Lagrange_")
	if len(parts) != 2 {
		panic(fmt.Errorf("invalid format"))
	}
	i, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}
	return
}

// CanonicalChallengeName returns the shared challenge name for all Fiat-Shamir steps
// at a given BFS level in the challenge-dependency DAG.
func CanonicalChallengeName(level int) string {
	return fmt.Sprintf("challenge@loom_%d", level)
}

func GetShiftedName(name string, shift int) string {
	if shift == 0 {
		return name
	}
	return fmt.Sprintf("%s_%s_%d", name, SUFFIX_SHIFT, shift)
}

func SplitShiftedName(name string) (string, int, error) {
	parts := strings.Split(name, SUFFIX_SHIFT_SPLIT)
	shiftString := parts[len(parts)-1]
	shift, err := strconv.ParseInt(shiftString, 10, 64)
	if err != nil {
		return "", 0, err
	}
	if len(parts) < 3 || parts[len(parts)-2] != SUFFIX_SHIFT {
		return "", 0, fmt.Errorf("non shifted column")
	}
	res := ""
	for i := 0; i < len(parts)-2; i++ {
		res += parts[i]
		if i < len(parts)-3 {
			res += SUFFIX_SHIFT_SPLIT
		}
	}
	return res, int(shift), nil
}
