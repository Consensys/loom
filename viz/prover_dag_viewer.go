package viz

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/consensys/giop/cs"
	proveractions "github.com/consensys/giop/prover_actions"
)

// actionLabel returns a display label for a DerivationStep from its Ctx.String().
func actionLabel(pa proveractions.DerivationStep) string {
	if pa.Ctx != nil {
		return pa.Ctx.String()
	}
	if len(pa.Outputs) == 0 {
		return "action"
	}
	parts := make([]string, len(pa.Outputs))
	for i, o := range pa.Outputs {
		parts[i] = dagShortLabel(o)
	}
	return "→ " + strings.Join(parts, ", ")
}

// WriteDerivationPlanDagToHTML writes a self-contained HTML file visualising the
// DAG of DerivationPlan inside cciop.
//
// Each DerivationStep is a node. Column IDs extracted from its Inputs that never
// appear as any action's Output are "known" (initial) columns. Column IDs that
// appear as some action's Output are "computed" columns.
//
// Visual conventions:
//   - Blue rectangles     : known (initial) input columns
//   - Green rectangles    : computed output columns
//   - Orange rounded rect : DerivationStep node (labelled by its output columns)
//   - Dashed blue arrow   : column → action (input dependency)
//   - Solid orange arrow  : action → column (produced output)
func WriteDerivationPlanDagToHTML(cciop cs.Program, filename string) error {
	actions := cciop.DerivationPlan

	// ── 1. find which columns are produced by actions ────────────────────────
	producedBy := make(map[string]bool)
	for _, pa := range actions {
		for _, out := range pa.Outputs {
			producedBy[out] = true
		}
	}

	// ── 2. build nodes and edges ─────────────────────────────────────────────
	kindOf := make(map[string]string)  // id → "known" | "computed" | "action"
	labelOf := make(map[string]string) // id → display label
	var edges []dagEdge

	aID := func(i int) string { return fmt.Sprintf("__action_%d", i) }

	for i, pa := range actions {
		id := aID(i)
		kindOf[id] = "action"
		labelOf[id] = actionLabel(pa)

		// edges from input columns → this action
		for _, col := range proveractions.GetColumnsId(pa.Inputs) {
			if _, seen := kindOf[col]; !seen {
				if producedBy[col] {
					kindOf[col] = "computed"
				} else {
					kindOf[col] = "known"
				}
				labelOf[col] = dagShortLabel(col)
			}
			edges = append(edges, dagEdge{From: col, To: id, Kind: "to_action"})
		}

		// edges from this action → output columns
		for _, out := range pa.Outputs {
			if _, seen := kindOf[out]; !seen {
				kindOf[out] = "computed"
				labelOf[out] = dagShortLabel(out)
			}
			edges = append(edges, dagEdge{From: id, To: out, Kind: "from_action"})
		}
	}

	// ── 3. layer assignment ─────────────────────────────────────────────────
	// DerivationPlan are already in topological order (from Kahn's compiler).
	layerOf := make(map[string]int)
	for id, k := range kindOf {
		if k == "known" {
			layerOf[id] = 0
		}
	}
	for i, pa := range actions {
		id := aID(i)
		layer := 1
		for _, col := range proveractions.GetColumnsId(pa.Inputs) {
			if l := layerOf[col] + 1; l > layer {
				layer = l
			}
		}
		layerOf[id] = layer
		for _, out := range pa.Outputs {
			layerOf[out] = layer + 1
		}
	}

	// ── 4. group by layer and sort within each layer ─────────────────────────
	byLayer := make(map[int][]string)
	maxLayer := 0
	for id := range kindOf {
		l := layerOf[id]
		byLayer[l] = append(byLayer[l], id)
		if l > maxLayer {
			maxLayer = l
		}
	}
	kindOrder := map[string]int{"known": 0, "action": 1, "computed": 2}
	for l, ids := range byLayer {
		sort.Slice(ids, func(i, j int) bool {
			ki, kj := kindOf[ids[i]], kindOf[ids[j]]
			if ki != kj {
				return kindOrder[ki] < kindOrder[kj]
			}
			return ids[i] < ids[j]
		})
		byLayer[l] = ids
	}

	// ── 5. compute (x, y) positions; centre each layer vertically ────────────
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

	// ── 6. build JSON payload ─────────────────────────────────────────────────
	var nodes []dagNode
	for id, k := range kindOf {
		p := posOf[id]
		nodes = append(nodes, dagNode{
			ID: id, Label: labelOf[id], Kind: k, X: p[0], Y: p[1],
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	payload, err := json.Marshal(dagPayload{Nodes: nodes, Edges: edges, NW: dagNW, NH: dagNH})
	if err != nil {
		return fmt.Errorf("prover dag: json: %w", err)
	}

	// ── 7. write the HTML file ────────────────────────────────────────────────
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	tmpl, err := template.New("prover_dag").Parse(proverStepsHTMLTemplate)
	if err != nil {
		return fmt.Errorf("prover dag: template: %w", err)
	}
	return tmpl.Execute(f, string(payload))
}

// proverStepsHTMLTemplate is a self-contained HTML page for the prover actions DAG.
// {{.}} is replaced by the JSON payload string.
const proverStepsHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Prover Steps DAG</title>
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
#bar h1 span{color:#e3b341}
#legend{display:flex;gap:16px;align-items:center;font-size:.72rem;color:#8b949e}
.li{display:flex;align-items:center;gap:6px;white-space:nowrap}
#resetBtn{
  margin-left:12px;padding:4px 10px;
  background:#21262d;border:1px solid #30363d;border-radius:4px;
  color:#c9d1d9;font-size:.72rem;cursor:pointer;white-space:nowrap}
#resetBtn:hover{background:#30363d}
#hint{margin-left:auto;font-size:.68rem;color:#484f58;white-space:nowrap}
/* ── viewport ── */
#vp{
  position:fixed;top:46px;left:0;right:0;bottom:0;
  overflow:hidden;cursor:grab}
#vp.panning{cursor:grabbing}
#vp.node-drag{cursor:move}
svg{width:100%;height:100%}
/* ── node styles ── */
.nk rect{fill:#0d2137;stroke:#388bfd;stroke-width:1.5}   /* known   : blue   */
.nk text{fill:#79c0ff}
.nv rect{fill:#0d2111;stroke:#3fb950;stroke-width:1.5}   /* computed: green  */
.nv text{fill:#7ee787}
.na rect{fill:#2a1a00;stroke:#e3b341;stroke-width:1.5}   /* action  : orange */
.na text{fill:#f0c860}
/* ── edge styles ── */
.eti{stroke:#388bfd;stroke-width:1.2;fill:none;stroke-dasharray:5 3}  /* col→action : dashed blue   */
.efo{stroke:#e3b341;stroke-width:1.5;fill:none}                       /* action→col : solid  orange */
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
  <h1>&#x25B6;&nbsp;Prover Steps <span>DAG</span></h1>
  <div id="legend">
    <div class="li">
      <svg width="13" height="13">
        <rect width="13" height="13" rx="2" fill="#0d2137" stroke="#388bfd" stroke-width="1.5"/>
      </svg>
      Known column
    </div>
    <div class="li">
      <svg width="13" height="13">
        <rect width="13" height="13" rx="2" fill="#0d2111" stroke="#3fb950" stroke-width="1.5"/>
      </svg>
      Computed column
    </div>
    <div class="li">
      <svg width="13" height="13">
        <rect width="13" height="13" rx="5" fill="#2a1a00" stroke="#e3b341" stroke-width="1.5"/>
      </svg>
      Prover action
    </div>
    <div class="li">
      <svg width="30" height="4">
        <line x1="0" y1="2" x2="30" y2="2"
              stroke="#388bfd" stroke-width="1.5" stroke-dasharray="5 3"/>
      </svg>
      input
    </div>
    <div class="li">
      <svg width="30" height="4">
        <line x1="0" y1="2" x2="30" y2="2" stroke="#e3b341" stroke-width="1.5"/>
      </svg>
      output
    </div>
    <button id="resetBtn" onclick="resetLayout()">&#x21BA; Reset layout</button>
  </div>
  <div id="hint">scroll to zoom &middot; drag canvas to pan &middot; drag node to move &middot; hover for full ID</div>
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

const byId = {};
D.nodes.forEach(n => { byId[n.id] = n; });

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
mkMarker("ai", "#388bfd"); // input  (blue)
mkMarker("ao", "#e3b341"); // output (orange)

function nodeClass(kind) {
  if (kind === "known")    return "nk";
  if (kind === "computed") return "nv";
  return "na"; // action
}
function edgeClass(kind)  { return kind === "to_action" ? "eti" : "efo"; }
function edgeMarker(kind) { return kind === "to_action" ? "ai"  : "ao";  }

// ── mutable per-node positions (data-space, centred on node) ─────────────────
const pos = {};
D.nodes.forEach(n => { pos[n.id] = { x: n.x, y: n.y }; });

function edgePath(sid, tid) {
  const s = pos[sid], t = pos[tid];
  const x1 = s.x + NW / 2, y1 = s.y;
  const x2 = t.x - NW / 2, y2 = t.y;
  const mx = (x1 + x2) / 2;
  return "M" + x1 + "," + y1 +
    " C" + mx + "," + y1 +
    " " + mx + "," + y2 +
    " " + x2 + "," + y2;
}

// ── draw edges first ──────────────────────────────────────────────────────────
const g = document.getElementById("g");
const edgeEls = []; // {from, to, el}

D.edges.forEach(e => {
  if (!byId[e.from] || !byId[e.to]) return;
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", edgePath(e.from, e.to));
  path.setAttribute("class",      edgeClass(e.kind));
  path.setAttribute("marker-end", "url(#" + edgeMarker(e.kind) + ")");
  g.appendChild(path);
  edgeEls.push({ from: e.from, to: e.to, el: path });
});

// adjacency map: node id → edges that touch it
const adjEdges = {};
D.nodes.forEach(n => { adjEdges[n.id] = []; });
edgeEls.forEach(e => {
  adjEdges[e.from].push(e);
  adjEdges[e.to].push(e);
});

function redrawEdges(id) {
  (adjEdges[id] || []).forEach(e => {
    e.el.setAttribute("d", edgePath(e.from, e.to));
  });
}

function placeNode(id) {
  const p = pos[id];
  nodeEls[id].setAttribute("transform",
    "translate(" + (p.x - NW / 2) + "," + (p.y - NH / 2) + ")");
}

// ── draw nodes ────────────────────────────────────────────────────────────────
const nodeEls = {};
const tip = document.getElementById("tip");

D.nodes.forEach(n => {
  const ng = document.createElementNS(NS, "g");
  nodeEls[n.id] = ng;
  ng.setAttribute("class", nodeClass(n.kind));
  ng.setAttribute("transform",
    "translate(" + (n.x - NW / 2) + "," + (n.y - NH / 2) + ")");

  const rect = document.createElementNS(NS, "rect");
  rect.setAttribute("width",  NW);
  rect.setAttribute("height", NH);
  rect.setAttribute("rx", n.kind === "action" ? "8" : "3");

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

  ng.addEventListener("mouseenter", ev => {
    tip.textContent = n.kind === "action" ? n.label : n.id;
    tip.style.display = "block";
    moveTip(ev);
  });
  ng.addEventListener("mousemove", moveTip);
  ng.addEventListener("mouseleave", () => { tip.style.display = "none"; });

  // ── node drag ──
  ng.addEventListener("mousedown", ev => {
    ev.stopPropagation(); // prevent canvas pan
    draggingNode = n.id;
    // offset in data-space between cursor and node centre
    nodeDragOx = (ev.clientX - tx) / sc - pos[n.id].x;
    nodeDragOy = (ev.clientY - ty) / sc - pos[n.id].y;
    vp.classList.add("node-drag");
  });

  g.appendChild(ng);
});

function moveTip(ev) {
  tip.style.left = (ev.clientX + 14) + "px";
  tip.style.top  = (ev.clientY -  4) + "px";
}

// ── pan/zoom state ────────────────────────────────────────────────────────────
let tx = 0, ty = 0, sc = 1;
function applyTransform() {
  g.setAttribute("transform",
    "translate(" + tx + "," + ty + ") scale(" + sc + ")");
}

const vp = document.getElementById("vp");

function fitToNodes() {
  let minX =  Infinity, minY =  Infinity;
  let maxX = -Infinity, maxY = -Infinity;
  D.nodes.forEach(n => {
    const p = pos[n.id];
    minX = Math.min(minX, p.x - NW / 2);
    minY = Math.min(minY, p.y - NH / 2);
    maxX = Math.max(maxX, p.x + NW / 2);
    maxY = Math.max(maxY, p.y + NH / 2);
  });
  const pad = 40;
  minX -= pad; minY -= pad; maxX += pad; maxY += pad;
  const cw = vp.clientWidth, ch = vp.clientHeight;
  const fw = maxX - minX, fh = maxY - minY;
  sc = Math.min(cw / fw, ch / fh, 1.5);
  tx = -minX * sc + (cw - fw * sc) / 2;
  ty = -minY * sc + (ch - fh * sc) / 2;
  applyTransform();
}

fitToNodes();

// ── pan interaction ───────────────────────────────────────────────────────────
let panning = false, panOx = 0, panOy = 0;
let draggingNode = null, nodeDragOx = 0, nodeDragOy = 0;

vp.addEventListener("mousedown", e => {
  panning = true;
  panOx = e.clientX - tx;
  panOy = e.clientY - ty;
  vp.classList.add("panning");
});

window.addEventListener("mouseup", () => {
  panning = false;
  draggingNode = null;
  vp.classList.remove("panning", "node-drag");
});

window.addEventListener("mousemove", e => {
  if (draggingNode) {
    const nx = (e.clientX - tx) / sc - nodeDragOx;
    const ny = (e.clientY - ty) / sc - nodeDragOy;
    pos[draggingNode].x = nx;
    pos[draggingNode].y = ny;
    placeNode(draggingNode);
    redrawEdges(draggingNode);
  } else if (panning) {
    tx = e.clientX - panOx;
    ty = e.clientY - panOy;
    applyTransform();
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
  applyTransform();
}, { passive: false });

// ── reset layout ──────────────────────────────────────────────────────────────
function resetLayout() {
  D.nodes.forEach(n => {
    pos[n.id].x = n.x;
    pos[n.id].y = n.y;
    placeNode(n.id);
    redrawEdges(n.id);
  });
  fitToNodes();
}
</script>
</body>
</html>`
