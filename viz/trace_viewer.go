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

	"github.com/consensys/loom/field"
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

	type column struct {
		name   string
		header string
		field  field.Kind
	}
	cols := make([]column, 0, len(trace.Base)+len(trace.Ext))
	for k := range trace.Base {
		cols = append(cols, column{name: k, header: k, field: field.Base})
	}
	for k := range trace.Ext {
		cols = append(cols, column{name: k, header: k + "[ext]", field: field.Ext})
	}
	sort.Slice(cols, func(i, j int) bool { return cols[i].header < cols[j].header })

	N := 0
	for _, poly := range trace.Base {
		if len(poly) > N {
			N = len(poly)
		}
	}
	for _, poly := range trace.Ext {
		if len(poly) > N {
			N = len(poly)
		}
	}

	headers := make([]string, len(cols))
	for i, col := range cols {
		headers[i] = col.header
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	for i := 0; i < N; i++ {
		row := make([]string, len(cols))

		for j, col := range cols {
			var c string
			if col.field == field.Base {
				poly := trace.Base[col.name]
				if len(poly) == 1 {
					c = poly[0].String()
				} else if i < len(poly) {
					c = poly[i].String()
				}
			} else {
				poly := trace.Ext[col.name]
				if len(poly) == 1 {
					c = poly[0].String()
				} else if i < len(poly) {
					c = poly[i].String()
				}
			}
			row[j] = c
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
