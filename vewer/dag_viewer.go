package viewer

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/consensys/giop/cs"
)

// Layout constants (pixels in the SVG coordinate space).
const (
	dagNW      = 170 // node width
	dagNH      = 38  // node height
	dagLayerDx = 270 // horizontal distance between layer centres
	dagRowDy   = 60  // vertical distance between node centres within a layer
	dagPadX    = 20  // left margin
	dagPadY    = 30  // top margin
)

// dagNode carries the data the HTML renderer needs for a single node.
type dagNode struct {
	ID    string  `json:"id"`
	Label string  `json:"label"` // shortened for display; full ID shown on hover
	Kind  string  `json:"kind"`  // "committed" | "challenge"
	X     float64 `json:"x"`     // centre x
	Y     float64 `json:"y"`     // centre y
}

// dagEdge carries the data the HTML renderer needs for a single directed edge.
type dagEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // "committed" | "challenge"
}

type dagPayload struct {
	Nodes []dagNode `json:"nodes"`
	Edges []dagEdge `json:"edges"`
	NW    int       `json:"nw"`
	NH    int       `json:"nh"`
}

// dagShortLabel strips the module-path prefix shared by the built-in challenge names.
func dagShortLabel(id string) string {
	return strings.TrimPrefix(id, "github.com/consensys/giop@")
}

// WriteDagToHTML writes a self-contained HTML file that visualises the DAG
// formed by rounds.
//
// Each Round contributes one challenge node (output) that depends on:
//   - DependenciesCommittedColumns  → committed-column leaf nodes (always known)
//   - DependenciesChallenges        → other challenge nodes (Kahn's unknowns)
//
// Visual conventions:
//   - Blue rectangles : committed-column nodes
//   - Purple rounded rectangles : challenge nodes
//   - Dashed blue arrows  : committed column → challenge
//   - Solid purple arrows : challenge → challenge
func WriteDagToHTML(rounds []cs.Round, filename string) error {
	// ── 1. collect unique nodes and edges ─────────────────────────────────────
	kindOf := make(map[string]string) // id → "committed" | "challenge"
	var edges []dagEdge

	// Track the order challenges appear in the rounds list so the layout is
	// deterministic and matches the proof's Fiat-Shamir sequence.
	challengeOrd := make(map[string]int)

	for _, r := range rounds {
		if _, seen := challengeOrd[r.ChallengeName]; !seen {
			challengeOrd[r.ChallengeName] = len(challengeOrd)
		}
		kindOf[r.ChallengeName] = "challenge"

		for _, col := range r.DependenciesCommittedColumns {
			if _, seen := kindOf[col]; !seen {
				kindOf[col] = "committed"
			}
			edges = append(edges, dagEdge{From: col, To: r.ChallengeName, Kind: "committed"})
		}
		for _, dep := range r.DependenciesChallenges {
			if _, seen := kindOf[dep]; !seen {
				kindOf[dep] = "challenge"
				challengeOrd[dep] = len(challengeOrd)
			}
			edges = append(edges, dagEdge{From: dep, To: r.ChallengeName, Kind: "challenge"})
		}
	}

	// ── 2. assign layers via iterative propagation ────────────────────────────
	// Build a challenge-only predecessor map (committed columns are always layer 0).
	predOf := make(map[string][]string)
	for _, e := range edges {
		if e.Kind == "challenge" {
			predOf[e.To] = append(predOf[e.To], e.From)
		}
	}

	layerOf := make(map[string]int)
	for id, k := range kindOf {
		if k == "committed" {
			layerOf[id] = 0
		} else {
			layerOf[id] = 1 // will be corrected below
		}
	}
	for {
		changed := false
		for id, k := range kindOf {
			if k != "challenge" {
				continue
			}
			want := 1
			for _, p := range predOf[id] {
				if l := layerOf[p] + 1; l > want {
					want = l
				}
			}
			if layerOf[id] != want {
				layerOf[id] = want
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// ── 3. group by layer and sort within each layer ──────────────────────────
	byLayer := make(map[int][]string)
	maxLayer := 0
	for id := range kindOf {
		l := layerOf[id]
		byLayer[l] = append(byLayer[l], id)
		if l > maxLayer {
			maxLayer = l
		}
	}
	for l, ids := range byLayer {
		sort.Slice(ids, func(i, j int) bool {
			ki, kj := kindOf[ids[i]], kindOf[ids[j]]
			// Committed columns: alphabetical order.
			if ki == "committed" && kj == "committed" {
				return ids[i] < ids[j]
			}
			// Challenges: proof order.
			return challengeOrd[ids[i]] < challengeOrd[ids[j]]
		})
		byLayer[l] = ids
	}

	// ── 4. compute (x, y) positions; centre each layer vertically ────────────
	maxRows := 0
	for _, ids := range byLayer {
		if len(ids) > maxRows {
			maxRows = len(ids)
		}
	}
	totalH := float64(maxRows-1) * dagRowDy

	posOf := make(map[string][2]float64)
	for l := 0; l <= maxLayer; l++ {
		ids := byLayer[l]
		layerH := float64(len(ids)-1) * dagRowDy
		baseY := (totalH-layerH)/2.0 + dagPadY
		for i, id := range ids {
			posOf[id] = [2]float64{
				float64(l)*dagLayerDx + dagPadX + float64(dagNW)/2,
				baseY + float64(i)*dagRowDy + float64(dagNH)/2,
			}
		}
	}

	// ── 5. build the JSON payload ─────────────────────────────────────────────
	var nodes []dagNode
	for id, k := range kindOf {
		p := posOf[id]
		nodes = append(nodes, dagNode{
			ID: id, Label: dagShortLabel(id), Kind: k, X: p[0], Y: p[1],
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	payload, err := json.Marshal(dagPayload{Nodes: nodes, Edges: edges, NW: dagNW, NH: dagNH})
	if err != nil {
		return fmt.Errorf("dag: json: %w", err)
	}

	// ── 6. write the HTML file ────────────────────────────────────────────────
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	tmpl, err := template.New("dag").Parse(dagHTMLTemplate)
	if err != nil {
		return fmt.Errorf("dag: template: %w", err)
	}
	return tmpl.Execute(f, string(payload))
}

// dagHTMLTemplate is a self-contained HTML page.
// {{.}} is replaced by the JSON payload string.
const dagHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IOP Round DAG</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:#0d1117;
  font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
  color:#c9d1d9;overflow:hidden}
/* ── toolbar ── */
#bar{
  height:46px;padding:0 16px;
  background:#161b22;border-bottom:1px solid #21262d;
  display:flex;align-items:center;gap:20px;flex-shrink:0}
#bar h1{font-size:.85rem;font-weight:600;letter-spacing:.05em;white-space:nowrap;color:#e6edf3}
#bar h1 span{color:#58a6ff}
#legend{display:flex;gap:16px;align-items:center;font-size:.72rem;color:#8b949e}
.li{display:flex;align-items:center;gap:6px;white-space:nowrap}
#hint{margin-left:auto;font-size:.68rem;color:#484f58;white-space:nowrap}
/* ── viewport ── */
#vp{
  position:fixed;top:46px;left:0;right:0;bottom:0;
  overflow:hidden;cursor:grab}
#vp:active{cursor:grabbing}
svg{width:100%;height:100%}
/* ── node styles ── */
.nc rect{fill:#0d2137;stroke:#388bfd;stroke-width:1.5}
.nc text{fill:#79c0ff}
.nq rect{fill:#1c1333;stroke:#a371f7;stroke-width:1.5}
.nq text{fill:#d2a8ff}
/* ── edge styles ── */
.ec{stroke:#388bfd;stroke-width:1.2;fill:none;stroke-dasharray:5 3}
.eq{stroke:#a371f7;stroke-width:1.5;fill:none}
/* ── tooltip ── */
#tip{
  position:fixed;display:none;
  background:#161b22;border:1px solid #30363d;
  color:#c9d1d9;font-size:.7rem;padding:5px 9px;
  border-radius:4px;pointer-events:none;
  max-width:480px;word-break:break-all;z-index:99}
</style>
</head>
<body>

<div id="bar">
  <h1>&#x25B6;&nbsp;IOP Round <span>DAG</span></h1>
  <div id="legend">
    <div class="li">
      <svg width="13" height="13">
        <rect width="13" height="13" rx="2" fill="#0d2137" stroke="#388bfd" stroke-width="1.5"/>
      </svg>
      Committed column
    </div>
    <div class="li">
      <svg width="13" height="13">
        <rect width="13" height="13" rx="5" fill="#1c1333" stroke="#a371f7" stroke-width="1.5"/>
      </svg>
      Challenge
    </div>
    <div class="li">
      <svg width="30" height="4">
        <line x1="0" y1="2" x2="30" y2="2"
              stroke="#388bfd" stroke-width="1.5" stroke-dasharray="5 3"/>
      </svg>
      from committed
    </div>
    <div class="li">
      <svg width="30" height="4">
        <line x1="0" y1="2" x2="30" y2="2" stroke="#a371f7" stroke-width="1.5"/>
      </svg>
      from challenge
    </div>
  </div>
  <div id="hint">scroll to zoom &middot; drag to pan &middot; hover for full ID</div>
</div>

<div id="vp">
  <svg id="svg">
    <defs id="defs"></defs>
    <g id="g"></g>
  </svg>
</div>
<div id="tip"></div>

<script>
const D = {{.}};
const NS = "http://www.w3.org/2000/svg";
const NW = D.nw, NH = D.nh;

// index nodes by id for fast edge lookup
const byId = {};
D.nodes.forEach(n => { byId[n.id] = n; });

// ── arrowhead markers ─────────────────────────────────────────────────────────
const defs = document.getElementById("defs");
function mkMarker(id, col) {
  const m = document.createElementNS(NS, "marker");
  m.setAttribute("id", id);
  m.setAttribute("markerWidth",  "8");
  m.setAttribute("markerHeight", "6");
  m.setAttribute("refX", "8"); // tip of triangle at path endpoint
  m.setAttribute("refY", "3");
  m.setAttribute("orient", "auto");
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", "M0,0 L0,6 L8,3 z");
  p.setAttribute("fill", col);
  m.appendChild(p);
  defs.appendChild(m);
}
mkMarker("ac", "#388bfd"); // committed
mkMarker("aq", "#a371f7"); // challenge

// ── draw edges first so they appear behind nodes ──────────────────────────────
const g = document.getElementById("g");
D.edges.forEach(e => {
  const s = byId[e.from], t = byId[e.to];
  if (!s || !t) return;
  // connect right-centre of source to left-centre of target
  const x1 = s.x + NW / 2;
  const y1 = s.y;
  const x2 = t.x - NW / 2;
  const y2 = t.y;
  const mx = (x1 + x2) / 2; // cubic bezier: horizontal tangents
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d",
    "M" + x1 + "," + y1 +
    " C" + mx + "," + y1 +
    " " + mx + "," + y2 +
    " " + x2 + "," + y2);
  path.setAttribute("class", e.kind === "committed" ? "ec" : "eq");
  path.setAttribute("marker-end", "url(#a" + (e.kind === "committed" ? "c" : "q") + ")");
  g.appendChild(path);
});

// ── draw nodes ────────────────────────────────────────────────────────────────
const tip = document.getElementById("tip");
D.nodes.forEach(n => {
  const ng = document.createElementNS(NS, "g");
  ng.setAttribute("class", n.kind === "committed" ? "nc" : "nq");
  // translate so (0,0) is the top-left corner of the node rectangle
  ng.setAttribute("transform",
    "translate(" + (n.x - NW / 2) + "," + (n.y - NH / 2) + ")");

  const rect = document.createElementNS(NS, "rect");
  rect.setAttribute("width",  NW);
  rect.setAttribute("height", NH);
  rect.setAttribute("rx", n.kind === "committed" ? "3" : "8");

  // truncate long labels; full id is shown in the tooltip
  let lbl = n.label;
  if (lbl.length > 21) lbl = lbl.slice(0, 19) + "\u2026";

  const text = document.createElementNS(NS, "text");
  text.setAttribute("x", NW / 2);
  text.setAttribute("y", NH / 2 + 4); // vertically centred
  text.setAttribute("text-anchor", "middle");
  text.setAttribute("font-size", "11");
  text.setAttribute("font-family",
    'ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace');
  text.textContent = lbl;

  ng.appendChild(rect);
  ng.appendChild(text);

  // tooltip: show full id on hover
  ng.addEventListener("mouseenter", ev => {
    tip.textContent = n.id;
    tip.style.display = "block";
    moveTip(ev);
  });
  ng.addEventListener("mousemove", moveTip);
  ng.addEventListener("mouseleave", () => { tip.style.display = "none"; });

  g.appendChild(ng);
});

function moveTip(ev) {
  tip.style.left = (ev.clientX + 14) + "px";
  tip.style.top  = (ev.clientY -  4) + "px";
}

// ── auto-fit: centre and scale the graph to fill the viewport on load ─────────
let tx = 0, ty = 0, sc = 1;
function apply() {
  g.setAttribute("transform",
    "translate(" + tx + "," + ty + ") scale(" + sc + ")");
}

// compute bounding box from node positions (no getBBox needed)
let minX =  Infinity, minY =  Infinity;
let maxX = -Infinity, maxY = -Infinity;
D.nodes.forEach(n => {
  minX = Math.min(minX, n.x - NW / 2);
  minY = Math.min(minY, n.y - NH / 2);
  maxX = Math.max(maxX, n.x + NW / 2);
  maxY = Math.max(maxY, n.y + NH / 2);
});
const pad = 40;
minX -= pad; minY -= pad; maxX += pad; maxY += pad;
const vp = document.getElementById("vp");
const cw = vp.clientWidth, ch = vp.clientHeight;
const fw = maxX - minX, fh = maxY - minY;
sc = Math.min(cw / fw, ch / fh, 1.5);    // never zoom in more than 1.5×
tx = -minX * sc + (cw - fw * sc) / 2;
ty = -minY * sc + (ch - fh * sc) / 2;
apply();

// ── pan (drag) and zoom (wheel) ───────────────────────────────────────────────
let dragging = false, ox = 0, oy = 0;
vp.addEventListener("mousedown", e => {
  dragging = true; ox = e.clientX - tx; oy = e.clientY - ty;
});
window.addEventListener("mouseup",   () => { dragging = false; });
window.addEventListener("mousemove", e => {
  if (!dragging) return;
  tx = e.clientX - ox;
  ty = e.clientY - oy;
  apply();
});
vp.addEventListener("wheel", e => {
  e.preventDefault();
  const f = e.deltaY < 0 ? 1.12 : 0.89;
  const rc = vp.getBoundingClientRect();
  const mx = e.clientX - rc.left;
  const my = e.clientY - rc.top;
  tx = mx - (mx - tx) * f;
  ty = my - (my - ty) * f;
  sc *= f;
  apply();
}, { passive: false });
</script>
</body>
</html>`
