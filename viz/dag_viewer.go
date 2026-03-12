package viz

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	derive "github.com/consensys/loom/internal/derive"
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
	return strings.TrimPrefix(id, "github.com/consensys/loom@")
}

// WriteDagToHTML writes a self-contained HTML file that visualises the DAG
// formed by rounds.
//
// Each TranscriptRound contributes one challenge node (output) that depends on:
//   - DependenciesCommittedColumns  → committed-column leaf nodes (always known)
//   - DependenciesChallenges        → other challenge nodes (Kahn's unknowns)
//
// Visual conventions:
//   - Blue rectangles : committed-column nodes
//   - Purple rounded rectangles : challenge nodes
//   - Dashed blue arrows  : committed column → challenge
//   - Solid purple arrows : challenge → challenge
func WriteProofTranscriptRoundsDagToHTML(rounds []derive.TranscriptRound, filename string) error {
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
<title>IOP TranscriptRound DAG</title>
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
#hint{font-size:.68rem;color:#484f58;white-space:nowrap}
#reset{
  margin-left:auto;
  background:#21262d;border:1px solid #30363d;color:#c9d1d9;
  padding:4px 12px;border-radius:5px;cursor:pointer;
  font-size:.72rem;font-family:inherit;white-space:nowrap}
#reset:hover{background:#30363d;border-color:#484f58}
/* ── viewport ── */
#vp{
  position:fixed;top:46px;left:0;right:0;bottom:0;
  overflow:hidden;cursor:grab}
#vp.panning{cursor:grabbing}
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
  <h1>&#x25B6;&nbsp;IOP TranscriptRound <span>DAG</span></h1>
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
  <div id="hint">scroll to zoom &middot; drag canvas to pan &middot; drag node to move &middot; hover for full ID</div>
  <button id="reset" onclick="resetLayout()">&#x21BA; Reset layout</button>
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

// ── mutable positions (graph coords, updated as nodes are dragged) ────────────
const initPos = {}, pos = {};
D.nodes.forEach(n => {
  initPos[n.id] = {x: n.x, y: n.y};
  pos[n.id]     = {x: n.x, y: n.y};
});

// ── viewport transform ────────────────────────────────────────────────────────
let tx = 0, ty = 0, sc = 1;
const g  = document.getElementById("g");
const vp = document.getElementById("vp");
function apply() {
  g.setAttribute("transform", "translate("+tx+","+ty+") scale("+sc+")");
}
// screen → graph coordinate conversion
function toGraph(cx, cy) {
  return {x: (cx - tx) / sc, y: (cy - ty) / sc};
}

// ── arrowhead markers ─────────────────────────────────────────────────────────
const defs = document.getElementById("defs");
function mkMarker(id, col) {
  const m = document.createElementNS(NS, "marker");
  m.setAttribute("id", id);
  m.setAttribute("markerWidth",  "8");
  m.setAttribute("markerHeight", "6");
  m.setAttribute("refX", "8");
  m.setAttribute("refY", "3");
  m.setAttribute("orient", "auto");
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", "M0,0 L0,6 L8,3 z");
  p.setAttribute("fill", col);
  m.appendChild(p);
  defs.appendChild(m);
}
mkMarker("ac", "#388bfd");
mkMarker("aq", "#a371f7");

// ── edge path string (right-centre of source → left-centre of target) ─────────
function mkEdgePath(sx, sy, ex, ey) {
  const x1 = sx + NW / 2, y1 = sy;
  const x2 = ex - NW / 2, y2 = ey;
  const mx = (x1 + x2) / 2;
  return "M"+x1+","+y1+" C"+mx+","+y1+" "+mx+","+y2+" "+x2+","+y2;
}

// ── draw edges first (store path elements for live update) ────────────────────
const edgePaths = D.edges.map(e => {
  const s = pos[e.from], t = pos[e.to];
  if (!s || !t) return null;
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", mkEdgePath(s.x, s.y, t.x, t.y));
  path.setAttribute("class", e.kind === "committed" ? "ec" : "eq");
  path.setAttribute("marker-end", "url(#a"+(e.kind === "committed" ? "c" : "q")+")");
  g.appendChild(path);
  return {e, path};
}).filter(Boolean);

// update all edge paths that touch node id
function updateEdges(id) {
  edgePaths.forEach(({e, path}) => {
    if (e.from !== id && e.to !== id) return;
    const s = pos[e.from], t = pos[e.to];
    path.setAttribute("d", mkEdgePath(s.x, s.y, t.x, t.y));
  });
}

// ── draw nodes ────────────────────────────────────────────────────────────────
const tip    = document.getElementById("tip");
const nodeEl = {};               // id → SVG g element
let dragId = null, dragOx = 0, dragOy = 0;

D.nodes.forEach(n => {
  const ng = document.createElementNS(NS, "g");
  ng.setAttribute("class", n.kind === "committed" ? "nc" : "nq");
  ng.setAttribute("transform",
    "translate("+(pos[n.id].x - NW/2)+","+(pos[n.id].y - NH/2)+")");
  ng.style.cursor = "grab";

  const rect = document.createElementNS(NS, "rect");
  rect.setAttribute("width",  NW);
  rect.setAttribute("height", NH);
  rect.setAttribute("rx", n.kind === "committed" ? "3" : "8");

  let lbl = n.label;
  if (lbl.length > 21) lbl = lbl.slice(0, 19) + "\u2026";
  const text = document.createElementNS(NS, "text");
  text.setAttribute("x", NW / 2);
  text.setAttribute("y", NH / 2 + 4);
  text.setAttribute("text-anchor", "middle");
  text.setAttribute("font-size", "11");
  text.setAttribute("font-family",
    'ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace');
  text.textContent = lbl;

  ng.appendChild(rect);
  ng.appendChild(text);

  // tooltip
  ng.addEventListener("mouseenter", ev => {
    tip.textContent = n.id;
    tip.style.display = "block";
    moveTip(ev);
  });
  ng.addEventListener("mousemove", moveTip);
  ng.addEventListener("mouseleave", () => { tip.style.display = "none"; });

  // node drag — stopPropagation prevents viewport pan from activating
  ng.addEventListener("mousedown", ev => {
    ev.stopPropagation();
    dragId = n.id;
    ng.style.cursor = "grabbing";
    const gp = toGraph(ev.clientX, ev.clientY);
    dragOx = gp.x - pos[n.id].x;
    dragOy = gp.y - pos[n.id].y;
  });

  g.appendChild(ng);
  nodeEl[n.id] = ng;
});

function moveTip(ev) {
  tip.style.left = (ev.clientX + 14) + "px";
  tip.style.top  = (ev.clientY -  4) + "px";
}

// move node element and refresh its edges
function renderNode(id) {
  const p = pos[id];
  nodeEl[id].setAttribute("transform",
    "translate("+(p.x - NW/2)+","+(p.y - NH/2)+")");
  updateEdges(id);
}

// reset all nodes to their initial positions
function resetLayout() {
  D.nodes.forEach(n => {
    pos[n.id] = {x: initPos[n.id].x, y: initPos[n.id].y};
    renderNode(n.id);
  });
}

// ── auto-fit on load ──────────────────────────────────────────────────────────
let minX =  Infinity, minY =  Infinity;
let maxX = -Infinity, maxY = -Infinity;
D.nodes.forEach(n => {
  minX = Math.min(minX, n.x - NW / 2); minY = Math.min(minY, n.y - NH / 2);
  maxX = Math.max(maxX, n.x + NW / 2); maxY = Math.max(maxY, n.y + NH / 2);
});
const pad = 40;
minX -= pad; minY -= pad; maxX += pad; maxY += pad;
const cw = vp.clientWidth, ch = vp.clientHeight;
const fw = maxX - minX, fh = maxY - minY;
sc = Math.min(cw / fw, ch / fh, 1.5);
tx = -minX * sc + (cw - fw * sc) / 2;
ty = -minY * sc + (ch - fh * sc) / 2;
apply();

// ── pan (viewport drag) and zoom (wheel) ──────────────────────────────────────
let panning = false, ox = 0, oy = 0;
vp.addEventListener("mousedown", e => {
  panning = true;
  vp.classList.add("panning");
  ox = e.clientX - tx; oy = e.clientY - ty;
});
window.addEventListener("mouseup", () => {
  panning = false;
  vp.classList.remove("panning");
  if (dragId) {
    nodeEl[dragId].style.cursor = "grab";
    dragId = null;
  }
});
window.addEventListener("mousemove", e => {
  if (dragId) {
    const gp = toGraph(e.clientX, e.clientY);
    pos[dragId] = {x: gp.x - dragOx, y: gp.y - dragOy};
    renderNode(dragId);
    return;
  }
  if (panning) {
    tx = e.clientX - ox;
    ty = e.clientY - oy;
    apply();
  }
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
}, {passive: false});
</script>
</body>
</html>`
