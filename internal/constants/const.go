// some namings shared accross protocols, prefixed by the name of the repo, to ensure there is no collisin with other challenges
package constants

import (
	"fmt"
	"strconv"
	"strings"
)

const FINAL_QUOTIENT = "__quotient"
const FINAL_EVALUATION_POINT = "__zeta"
const FINAL_FOLDING_CHALLENGE = "__alpha"
const SUFFIX_SHIFT_SPLIT = "_"
const SUFFIX_SHIFT = "shift"
const SIZE_RANDOM_STRING = 10 // size of the names randomly created for the intermediate columns issued with prover actions

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
