package viewer

import (
	"encoding/csv"
	"os"
	"sort"

	"github.com/consensys/giop/trace"
)

func WriteTraceToCSV(filename string, trace trace.Trace, N int) error {
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

	// 2️⃣ Write header row
	if err := writer.Write(keys); err != nil {
		return err
	}

	// 4️⃣ Write rows
	for i := 0; i < N; i++ {
		row := make([]string, len(keys))

		for j, k := range keys {
			c := trace[k].GetCoefficient(i)
			row[j] = c.String()
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
