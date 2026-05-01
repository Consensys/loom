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

package viz

import (
	"encoding/csv"
	"os"
	"sort"

	"github.com/consensys/loom/trace"
)

func WriteRawTraceToCSV(filename string, trace trace.Trace) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 1️⃣ Collect and sort keys for deterministic column order
	keys := make([]string, 0, len(trace))
	for k := range trace {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2️⃣ Compute N as the max column length
	N := 0
	for _, poly := range trace {
		if len(poly) > N {
			N = len(poly)
		}
	}

	// 3️⃣ Write header row
	if err := writer.Write(keys); err != nil {
		return err
	}

	// 4️⃣ Write rows
	for i := 0; i < N; i++ {
		row := make([]string, len(keys))

		for j, k := range keys {
			poly := trace[k]
			var c string
			if len(poly) == 1 {
				c = poly[0].String()
			} else if i < len(poly) {
				c = poly[i].String()
			}
			row[j] = c
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
