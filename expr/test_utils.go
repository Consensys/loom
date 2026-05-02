// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
