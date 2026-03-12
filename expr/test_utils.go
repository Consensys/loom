package expr

import (
	"sort"
	"testing"
)

// sortedUniq returns a sorted, deduplicated copy — order-independent comparison helper.
func sortedUniq(s []string) []string {
	s = RemoveDuplicates(s)
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

func AssertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	g, w := sortedUniq(got), sortedUniq(want)
	if len(g) != len(w) {
		t.Fatalf("got %v, want %v", g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("got %v, want %v", g, w)
		}
	}
}
