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
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

// ViewDag writes an HTML file at path out that renders the step DAG of program.
// Steps are organized by execution level (left to right). Column nodes represent
// data, step nodes represent computations. Arrows show data flow.
func ViewDag(program board.Program, out string) {
	f, err := os.Create(out)
	if err != nil {
		panic(fmt.Sprintf("ViewDag: create %s: %v", out, err))
	}
	defer f.Close()
	fmt.Fprint(f, stepDagHTML(program))
}

// ---- JSON-serialisable vis.js types ----------------------------------------

type visColor struct {
	Background string `json:"background"`
	Border     string `json:"border"`
}

type visFont struct {
	Color string `json:"color"`
	Face  string `json:"face"`
	Size  int    `json:"size"`
}

type visNode struct {
	ID    int      `json:"id"`
	Label string   `json:"label"`
	Level int      `json:"level"`
	Shape string   `json:"shape"`
	Color visColor `json:"color"`
	Font  visFont  `json:"font"`
}

type visEdge struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// ---- graph builder ----------------------------------------------------------

func stepDagHTML(program board.Program) string {
	config := expr.NewConfig()

	var nodes []visNode
	var edges []visEdge
	nextID := 0

	colID := map[string]int{}     // column name → node ID
	colVisLvl := map[string]int{} // column name → vis.js level
	challenges := map[string]bool{}

	getColID := func(name string) int {
		if id, ok := colID[name]; ok {
			return id
		}
		id := nextID
		nextID++
		colID[name] = id
		return id
	}

	for lvl, steps := range program.Steps {
		stepVisLvl := 2*lvl + 1

		for _, step := range steps {
			if isFS(step) {
				challenges[step.Outs[0]] = true
			}

			stepNodeID := nextID
			nextID++

			nodes = append(nodes, visNode{
				ID:    stepNodeID,
				Label: stepLabel(step),
				Level: stepVisLvl,
				Shape: "box",
				Color: stepColor(step),
				Font:  visFont{Color: "#cdd6f4", Face: "monospace", Size: 13},
			})

			// Input edges: one per unique base column name in Ins.
			// For canonical FS steps (Ins is nil), inputs come from program.FiatShamir[round].
			seen := map[string]bool{}
			if isFS(step) {
				var round int
				fmt.Sscanf(step.Outs[0], "challenge@loom_%d", &round)
				if round < len(program.FScolumnsDependencies) {
					for _, name := range program.FScolumnsDependencies[round] {
						if seen[name] {
							continue
						}
						seen[name] = true
						cid := getColID(name)
						if _, ok := colVisLvl[name]; !ok {
							colVisLvl[name] = 0
						}
						edges = append(edges, visEdge{From: cid, To: stepNodeID})
					}
				}
			} else {
				for _, inp := range step.Ins {
					for _, leaf := range inp.LeavesFull(config) {
						name := leaf.Name
						if seen[name] {
							continue
						}
						seen[name] = true
						cid := getColID(name)
						if _, ok := colVisLvl[name]; !ok {
							colVisLvl[name] = 0
						}
						edges = append(edges, visEdge{From: cid, To: stepNodeID})
					}
				}
			}

			// Output edges: step → each output column node
			for _, out := range step.Outs {
				outID := getColID(out)
				colVisLvl[out] = 2*lvl + 2
				edges = append(edges, visEdge{From: stepNodeID, To: outID})
			}
		}
	}

	// Create column nodes (done after all steps so colVisLvl is fully populated)
	for name, id := range colID {
		lvl := 0
		if l, ok := colVisLvl[name]; ok {
			lvl = l
		}
		nodes = append(nodes, visNode{
			ID:    id,
			Label: name,
			Level: lvl,
			Shape: "ellipse",
			Color: columnColor(lvl, challenges[name]),
			Font:  visFont{Color: "#cdd6f4", Face: "monospace", Size: 12},
		})
	}

	nodesJSON, _ := json.Marshal(nodes)
	edgesJSON, _ := json.Marshal(edges)
	return fmt.Sprintf(dagHTMLTemplate, nodesJSON, edgesJSON)
}

// ---- helpers ----------------------------------------------------------------

func isFS(ps board.ProverStep) bool {
	_, ok := ps.Ctx.(board.FSCtx)
	return ok
}

func stepLabel(ps board.ProverStep) string {
	switch c := ps.Ctx.(type) {
	case board.FSCtx:
		_ = c
		return "FiatShamir"
	case board.MakeIthValuePublicCtx:
		return fmt.Sprintf("PickValue\npos=%d", c.Pos)
	case board.CMCtx:
		_ = c
		return "CountMultiplicity"
	case board.LogUpCtx:
		_ = c
		return "LogUp"
	case board.GPCtx:
		_ = c
		return "GrandProduct"
	default:
		return "Step"
	}
}

func stepColor(ps board.ProverStep) visColor {
	if isFS(ps) {
		return visColor{Background: "#6c3483", Border: "#512e5f"}
	}
	return visColor{Background: "#1a5276", Border: "#154360"}
}

func columnColor(visLvl int, isChallenge bool) visColor {
	if isChallenge {
		return visColor{Background: "#9a7d0a", Border: "#7d6608"}
	}
	if visLvl == 0 {
		// initial input: never produced by any step
		return visColor{Background: "#424949", Border: "#2e4057"}
	}
	return visColor{Background: "#1a5276", Border: "#154360"}
}

// ---- HTML template ----------------------------------------------------------

const dagHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Step DAG</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
html,body{margin:0;height:100%%;background:#1e1e2e;color:#cdd6f4;font-family:monospace}
#network{width:100%%;height:100%%;display:block}
#legend{position:fixed;top:12px;right:12px;background:rgba(24,24,37,.93);padding:12px 16px;border-radius:8px;font-size:12px;line-height:1.7;z-index:10}
.li{display:flex;align-items:center}
.sq{width:13px;height:13px;border-radius:2px;margin-right:8px;flex-shrink:0}
</style>
</head>
<body>
<div id="network"></div>
<div id="legend">
  <div class="li"><div class="sq" style="background:#424949"></div>Input column</div>
  <div class="li"><div class="sq" style="background:#1a5276"></div>Computed column</div>
  <div class="li"><div class="sq" style="background:#9a7d0a"></div>Challenge</div>
  <div class="li"><div class="sq" style="background:#6c3483"></div>FiatShamir step</div>
  <div class="li"><div class="sq" style="background:#1a5276;border:2px solid #154360"></div>Computation step</div>
</div>
<script>
var nodes=new vis.DataSet(%s);
var edges=new vis.DataSet(%s);
new vis.Network(document.getElementById('network'),{nodes,edges},{
  layout:{hierarchical:{direction:'LR',levelSeparation:260,nodeSpacing:100,sortMethod:'directed'}},
  edges:{
    arrows:{to:{enabled:true,scaleFactor:.7}},
    smooth:{type:'cubicBezier',forceDirection:'horizontal'},
    color:{color:'#585b70',highlight:'#89b4fa'}
  },
  interaction:{hover:true,tooltipDelay:100},
  physics:false
});
</script>
</body>
</html>`
