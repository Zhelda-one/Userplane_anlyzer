#!/usr/bin/env python3
"""Simple web UI for enhanced M-Plane analyzer (Nokia-patched) + interactive chain map.

Features
- Upload .txt/.xml/.log NETCONF M-Plane logs/configs
- Runs patched analyzer (Nokia NETCONF trace supported)
- Shows HTML result preview
- Displays TXT / JSON results in-browser only (no server-side save)
- Interactive chain map (Link -> Endpoint -> Carrier -> PE -> Transport Flow)
  * Click node to inspect details
  * PE links included

No external dependencies (stdlib only). Python 3.13+ compatible (no cgi module).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
import tempfile
import traceback
import uuid
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import importlib.util

BASE_DIR = Path(__file__).resolve().parent
# Prefer Nokia patch v2, then v1, then generic enhanced parser.
ANALYZER_CANDIDATES = [
    # Preferred: v2 + endpoint array/restricted-interfaces/supported-reference-level rendering
    BASE_DIR / "analyze_mplane_enhanced_nokia_patch_v2_with_array_srl.py",
    BASE_DIR / "analyze_mplane_enhanced_nokia_patch_v2.py",
    BASE_DIR / "analyze_mplane_enhanced_nokia_patch.py",
    BASE_DIR / "analyze_mplane_enhanced.py",
]
UPLOAD_DIR = BASE_DIR / "mplane_web_uploads"
MAX_UPLOAD_MB = 50

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _pick_analyzer_path() -> Path:
    for p in ANALYZER_CANDIDATES:
        if p.exists():
            return p
    return ANALYZER_CANDIDATES[0]


ANALYZER_PATH = _pick_analyzer_path()


def load_analyzer_module(path: Path):
    spec = importlib.util.spec_from_file_location("mplane_analyzer", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load analyzer module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ANALYZER = load_analyzer_module(ANALYZER_PATH)


def safe_name(name: str) -> str:
    name = os.path.basename(name or "upload.txt")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:180] or "upload.txt"


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def html_page(title: str, body: str) -> bytes:
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.4; }}
.container {{ max-width: 1400px; margin: auto; }}
.card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
pre {{ background: #f7f7f7; border: 1px solid #eee; padding: 12px; overflow-x: auto; white-space: pre-wrap; }}
#reportPreview { font-size: 12px; line-height: 1.25; }
#mmSelJson { font-size: 11px; line-height: 1.2; }  # (선택) Selected Node JSON도 같이 줄이기
code {{ background: #f3f3f3; padding: 1px 4px; border-radius: 4px; }}
label {{ display: inline-block; min-width: 140px; margin-top: 6px; }}
input[type=file], select, input[type=text] {{ min-width: 320px; max-width: 100%; }}
button {{ padding: 8px 14px; cursor: pointer; }}
.muted {{ color: #666; }}
.row {{ margin: 8px 0; }}
.alert {{ background:#fff8e1; border:1px solid #f0d97a; padding:10px; border-radius:8px; }}
.err {{ background:#ffecec; border-color:#ef9a9a; }}
a {{ text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.grid {{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
.grid3 {{ display:grid; grid-template-columns: 2fr 1fr; gap: 12px; }}
@media (max-width: 1100px) {{ .grid {{ grid-template-columns: 1fr; }} .grid3 {{ grid-template-columns: 1fr; }} }}
/* interactive graph */
.mm-wrap {{ border:1px solid #e6e6e6; border-radius:10px; background:#fff; }}
.mm-toolbar {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; padding:10px; border-bottom:1px solid #eee; }}
.mm-toolbar input, .mm-toolbar select {{ min-width: unset; }}
.mm-layout {{ display:grid; grid-template-columns: minmax(600px,1fr) 380px; gap: 0; }}
@media (max-width: 1200px) {{ .mm-layout {{ grid-template-columns: 1fr; }} }}
.mm-canvas {{ overflow:auto; border-right:1px solid #eee; background:#fcfcfc; }}
.mm-side {{ padding:12px; }}
.mm-legend span {{ display:inline-block; margin-right:8px; margin-bottom:6px; padding:2px 8px; border-radius:999px; font-size:12px; border:1px solid #ddd; }}
svg.mm-svg text {{ font-size:12px; dominant-baseline:middle; user-select:none; }}
svg.mm-svg .edge {{ stroke:#b8bcc4; stroke-width:1.2; fill:none; }}
svg.mm-svg .edge.highlight {{ stroke:#ff9800; stroke-width:2.2; }}
svg.mm-svg .node {{ cursor:pointer; }}
svg.mm-svg .node rect {{ stroke:#8d99ae; stroke-width:1; rx:8; ry:8; }}
svg.mm-svg .node.active rect {{ stroke:#ff9800; stroke-width:2; }}
svg.mm-svg .node .badge {{ font-size:10px; opacity:.8; }}
svg.mm-svg .type-link rect {{ fill:#e8f0fe; }}
svg.mm-svg .type-endpoint rect {{ fill:#e8f5e9; }}
svg.mm-svg .type-carrier rect {{ fill:#fff3e0; }}
svg.mm-svg .type-pe rect {{ fill:#f3e5f5; }}
svg.mm-svg .type-tf rect {{ fill:#e0f7fa; }}
small.kv {{ color:#555; }}
</style>
</head>
<body>
<div class="container">{body}</div>
</body>
</html>"""
    return page.encode("utf-8")


def render_index(message: str = "", error: bool = False) -> bytes:
    msg_html = f'<div class="alert {"err" if error else ""}">{html.escape(message)}</div>' if message else ''
    body = f"""
<h1>M-Plane Analyzer Web (TXT/XML Upload)</h1>
<p class="muted">Uploads M-Plane NETCONF TXT/XML/LOG and analyzes with <code>{html.escape(ANALYZER_PATH.name)}</code> (Nokia trace supported in patched versions).</p>
{msg_html}
<div class="card">
<form method="post" action="/analyze" enctype="multipart/form-data">
  <div class="row"><label>Input file</label><input type="file" name="mplane_file" accept=".txt,.xml,.log,text/plain,application/xml,text/xml" required></div>
  <div class="row"><label>Report section</label>
    <select name="show">
      <option value="all" selected>all</option>
      <option value="chain">chain</option>
      <option value="endpoint">endpoint</option>
      <option value="validate">validate</option>
      <option value="warnings">warnings</option>
      <option value="history">history</option>
    </select>
  </div>
  <div class="row"><label>Job label (optional)</label><input type="text" name="job_label" placeholder="e.g. nokia_rmod"></div>
  <div class="row"><button type="submit">Analyze &amp; Show Result</button></div>
</form>
</div>
<div class="card">
  <b>Supported:</b> generic semicolon NETCONF traces, Nokia <code>Sending message:/Received message:</code> traces (patched analyzer), raw XML dumps.
</div>
"""
    return html_page("M-Plane Analyzer Web", body)


def _coerce_list(v):
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return [v]
    return []


def _json_for_html_script(obj) -> str:
    # Safe to place inside <script type="application/json">...</script>
    s = json.dumps(obj, ensure_ascii=False)
    return s.replace("</", "<\\/")


def build_chain_graph_from_payload(payload: dict) -> dict:
    """
    Build a UI-friendly graph from analyzer JSON payload.
    Expected keys resemble StateStore fields:
      links_tx, links_rx, endpoints_tx, endpoints_rx, carriers_tx, carriers_rx, processing_elements, prach_configs
    """
    payload = payload or {}
    links_tx = payload.get("links_tx") or {}
    links_rx = payload.get("links_rx") or {}
    endpoints_tx = payload.get("endpoints_tx") or {}
    endpoints_rx = payload.get("endpoints_rx") or {}
    carriers_tx = payload.get("carriers_tx") or {}
    carriers_rx = payload.get("carriers_rx") or {}
    pes = payload.get("processing_elements") or {}
    prach_configs = payload.get("prach_configs") or {}

    nodes = []
    edges = []
    node_index = {}

    def add_node(nid: str, ntype: str, label: str, lane: int, data: dict | None = None, meta: dict | None = None):
        if not nid:
            return
        if nid in node_index:
            # merge some data only if previously placeholder
            idx = node_index[nid]
            if data and not nodes[idx].get("data"):
                nodes[idx]["data"] = data
            return
        node_index[nid] = len(nodes)
        nodes.append({
            "id": nid,
            "type": ntype,
            "label": str(label)[:80],
            "lane": lane,
            "data": data or {},
            "meta": meta or {},
        })

    def add_edge(src: str, dst: str, etype: str, label: str = ""):
        if not src or not dst:
            return
        edges.append({"source": src, "target": dst, "type": etype, "label": label})

    def ep_key_for(direction: str) -> str:
        return "low-level-tx-endpoint" if direction == "TX" else "low-level-rx-endpoint"

    def car_key_for(direction: str) -> str:
        return "tx-array-carrier" if direction == "TX" else "rx-array-carrier"

    def build_for(direction: str, links: dict, eps: dict, cars: dict):
        for link_name, link in sorted((links or {}).items()):
            link = link or {}
            ep_name = str(link.get(ep_key_for(direction), "N/A"))
            car_name = str(link.get(car_key_for(direction), "N/A"))
            pe_name = str(link.get("processing-element", "") or "N/A")

            lid = f"{direction}:LINK:{link_name}"
            eid = f"{direction}:EP:{ep_name}"
            cid = f"{direction}:CAR:{car_name}"
            pid = f"PE:{pe_name}"

            ep = (eps or {}).get(ep_name) or {}
            car = (cars or {}).get(car_name) or {}
            pe = (pes or {}).get(pe_name) or {}

            add_node(lid, "link", f"{direction} Link: {link_name}", 0, data=link, meta={"direction": direction})
            add_node(eid, "endpoint", f"{direction} EP: {ep_name}", 1, data=ep, meta={"direction": direction})
            add_node(cid, "carrier", f"{direction} CAR: {car_name}", 2, data=car, meta={"direction": direction})
            add_node(pid, "pe", f"PE: {pe_name}", 3, data=pe, meta={"direction": direction})

            add_edge(lid, eid, "link-endpoint")
            add_edge(lid, cid, "link-carrier")
            add_edge(lid, pid, "link-pe")

            # Optional PRACH connection info embedded in endpoint node metadata (not rendered as extra node to reduce clutter)
            prach_key = None
            if isinstance(ep, dict):
                for keyname in ("static-prach-configuration", "prach-group"):
                    v = ep.get(keyname)
                    if v not in (None, "", []):
                        prach_key = str(v)
                        break
            if prach_key:
                nodes[node_index[eid]].setdefault("meta", {})["prach_ref"] = {
                    "key": prach_key,
                    "exists": prach_key in prach_configs,
                    "config": (prach_configs.get(prach_key) or {}),
                }

            # PE -> transport-flow nodes
            tf = pe.get("transport-flow", {}) if isinstance(pe, dict) else {}
            tf_list = _coerce_list(tf)
            for idx, flow in enumerate(tf_list, 1):
                tfid = f"{pid}:TF:{idx}"
                if isinstance(flow, dict):
                    label = f"TF[{idx}] {flow.get('interface-name') or '-'}"
                else:
                    label = f"TF[{idx}]"
                add_node(tfid, "tf", label, 4, data=flow if isinstance(flow, dict) else {"value": flow}, meta={"direction": direction, "pe": pe_name})
                add_edge(pid, tfid, "pe-tf")

    build_for("TX", links_tx, endpoints_tx, carriers_tx)
    build_for("RX", links_rx, endpoints_rx, carriers_rx)

    # Orphans (PE present but not linked)
    for pe_name, pe in sorted((pes or {}).items()):
        pid = f"PE:{pe_name}"
        add_node(pid, "pe", f"PE: {pe_name}", 3, data=pe, meta={"orphan": True})
        tf_list = _coerce_list((pe or {}).get("transport-flow", {}) if isinstance(pe, dict) else {})
        for idx, flow in enumerate(tf_list, 1):
            tfid = f"{pid}:TF:{idx}"
            label = f"TF[{idx}] {flow.get('interface-name') or '-'}" if isinstance(flow, dict) else f"TF[{idx}]"
            add_node(tfid, "tf", label, 4, data=flow if isinstance(flow, dict) else {"value": flow}, meta={"pe": pe_name})
            # avoid duplicate edge
            if not any(e["source"] == pid and e["target"] == tfid for e in edges):
                add_edge(pid, tfid, "pe-tf")

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "links_tx": len(links_tx),
            "links_rx": len(links_rx),
            "pe": len(pes),
        },
    }


def render_chain_map_card(graph: dict) -> str:
    graph_json = _json_for_html_script(graph)
    return f"""
<div class="card">
  <h3>Interactive Chain Map (Mind-map style)</h3>
  <p class="muted">Click a node to inspect details. Chain includes <b>Link → Endpoint / Carrier / PE → Transport Flow</b> and supports PE linkage.</p>
  <div class="mm-wrap">
    <div class="mm-toolbar">
      <label style="min-width:auto;">Filter</label>
      <input id="mmFilter" type="text" placeholder="Search name / interface / vlan / mac..." style="width:280px;">
      <label style="min-width:auto;">Direction</label>
      <select id="mmDir">
        <option value="ALL">ALL</option>
        <option value="TX">TX</option>
        <option value="RX">RX</option>
      </select>
      <span class="mm-legend">
        <span style="background:#e8f0fe;">Link</span>
        <span style="background:#e8f5e9;">Endpoint</span>
        <span style="background:#fff3e0;">Carrier</span>
        <span style="background:#f3e5f5;">PE</span>
        <span style="background:#e0f7fa;">TF</span>
      </span>
      <small class="kv" id="mmStats"></small>
    </div>
    <div class="mm-layout">
      <div class="mm-canvas">
        <svg id="mmSvg" class="mm-svg" width="1400" height="700" viewBox="0 0 1400 700"></svg>
      </div>
      <div class="mm-side">
        <div><b>Selected Node</b></div>
        <div id="mmSelMeta" class="muted" style="margin:6px 0 10px;">(click a node)</div>
        <pre id="mmSelJson" style="max-height:560px; overflow:auto;">{{}}</pre>
      </div>
    </div>
  </div>
  <script id="mmGraphData" type="application/json">{graph_json}</script>
  <script>
  (function(){{
    const graph = JSON.parse(document.getElementById('mmGraphData').textContent || '{{}}');
    const svg = document.getElementById('mmSvg');
    const filterEl = document.getElementById('mmFilter');
    const dirEl = document.getElementById('mmDir');
    const statsEl = document.getElementById('mmStats');
    const selMeta = document.getElementById('mmSelMeta');
    const selJson = document.getElementById('mmSelJson');

    const laneOrder = ['link','endpoint','carrier','pe','tf'];
    const laneX = {{0:40,1:310,2:580,3:850,4:1120}};
    const nodeW = 240, nodeH = 42, gapY = 16, topPad = 40;
    let activeId = null;

    function norm(v) {{ return (v == null ? '' : String(v)).toLowerCase(); }}
    function nodeSearchText(n) {{
      let txt = n.label + ' ' + JSON.stringify(n.data || {{}}) + ' ' + JSON.stringify(n.meta || {{}});
      return norm(txt);
    }}

    function passes(n, q, dir) {{
      if (dir !== 'ALL') {{
        const nd = (n.meta && n.meta.direction) ? String(n.meta.direction) : '';
        // allow PE/TF without explicit dir when ALL only; if dir selected, require dir or show if orphan false? hide unknowns.
        if (nd !== dir) return false;
      }}
      if (!q) return true;
      return nodeSearchText(n).includes(q);
    }}

    function computeLayout(nodes, edges) {{
      // Keep nodes if pass filter or neighbor of pass node for context
      const q = norm(filterEl.value.trim());
      const dir = dirEl.value;
      const passMap = new Map(nodes.map(n => [n.id, passes(n, q, dir)]));
      const neighborKeep = new Set();
      edges.forEach(e => {{
        if (passMap.get(e.source) || passMap.get(e.target)) {{
          neighborKeep.add(e.source); neighborKeep.add(e.target);
        }}
      }});
      const keepNodes = nodes.filter(n => passMap.get(n.id) || neighborKeep.has(n.id));
      const keepSet = new Set(keepNodes.map(n => n.id));
      const keepEdges = edges.filter(e => keepSet.has(e.source) && keepSet.has(e.target));

      // Group by lane and sort for stable display
      const byLane = {{0:[],1:[],2:[],3:[],4:[]}};
      keepNodes.forEach(n => byLane[n.lane]?.push(n));
      for (const k of Object.keys(byLane)) {{
        byLane[k].sort((a,b)=>a.label.localeCompare(b.label));
      }}

      // y positions
      const pos = new Map();
      let maxRows = 0;
      for (const lane of [0,1,2,3,4]) {{
        const arr = byLane[lane] || [];
        maxRows = Math.max(maxRows, arr.length);
        arr.forEach((n, i) => {{
          pos.set(n.id, {{x: laneX[lane], y: topPad + i * (nodeH + gapY)}});
        }});
      }}

      // simple relaxation: align non-link nodes to avg of incoming neighbors (a few iterations)
      for (let iter=0; iter<3; iter++) {{
        for (const lane of [1,2,3,4]) {{
          const arr = byLane[lane] || [];
          arr.forEach((n, i) => {{
            const incoming = keepEdges.filter(e => e.target === n.id).map(e => pos.get(e.source)).filter(Boolean);
            const outgoing = keepEdges.filter(e => e.source === n.id).map(e => pos.get(e.target)).filter(Boolean);
            const refs = incoming.length ? incoming : outgoing;
            if (refs.length) {{
              const avg = refs.reduce((s,p)=>s+p.y,0)/refs.length;
              pos.get(n.id).y = (pos.get(n.id).y * 0.4) + (avg * 0.6);
            }}
          }});
          // resolve overlaps after relaxation
          const sorted = arr.slice().sort((a,b)=>pos.get(a.id).y - pos.get(b.id).y);
          let yCursor = topPad;
          sorted.forEach(n => {{
            const p = pos.get(n.id);
            p.y = Math.max(p.y, yCursor);
            yCursor = p.y + nodeH + 8;
          }});
        }}
      }}

      const height = Math.max(700, topPad + maxRows * (nodeH + gapY) + 80);
      const width = 1400;
      return {{keepNodes, keepEdges, pos, width, height}};
    }}

    function clearSvg() {{
      while (svg.firstChild) svg.removeChild(svg.firstChild);
    }}

    function el(name, attrs = {{}}, text = null) {{
      const x = document.createElementNS('http://www.w3.org/2000/svg', name);
      for (const [k,v] of Object.entries(attrs)) x.setAttribute(k, v);
      if (text != null) x.textContent = text;
      return x;
    }}

    function draw() {{
      const nodes = graph.nodes || [];
      const edges = graph.edges || [];
      const layout = computeLayout(nodes, edges);
      svg.setAttribute('width', layout.width);
      svg.setAttribute('height', layout.height);
      svg.setAttribute('viewBox', `0 0 ${{layout.width}} ${{layout.height}}`);
      clearSvg();

      statsEl.textContent = `visible nodes: ${{layout.keepNodes.length}} / ${{nodes.length}}, edges: ${{layout.keepEdges.length}} / ${{edges.length}}`;

      // defs
      const defs = el('defs');
      const marker = el('marker', {{id:'arrow', markerWidth:'8', markerHeight:'8', refX:'7', refY:'4', orient:'auto'}});
      marker.appendChild(el('path', {{d:'M0,0 L8,4 L0,8 z', fill:'#b8bcc4'}}));
      defs.appendChild(marker);
      svg.appendChild(defs);

      // lane titles
      [['LINK',0],['ENDPOINT',1],['CARRIER',2],['PE',3],['TF',4]].forEach(([t,l])=>{{
        svg.appendChild(el('text', {{x: laneX[l], y: 18, fill:'#555', 'font-weight':'700'}}, t));
      }});

      // adjacency for highlight
      const adj = new Map();
      (graph.edges || []).forEach(e => {{
        if (!adj.has(e.source)) adj.set(e.source, new Set());
        if (!adj.has(e.target)) adj.set(e.target, new Set());
        adj.get(e.source).add(e.target);
        adj.get(e.target).add(e.source);
      }});

      // edges
      layout.keepEdges.forEach(e => {{
        const s = layout.pos.get(e.source), t = layout.pos.get(e.target);
        if (!s || !t) return;
        const x1 = s.x + nodeW;
        const y1 = s.y + nodeH/2;
        const x2 = t.x;
        const y2 = t.y + nodeH/2;
        const dx = Math.max(40, (x2 - x1) * 0.5);
        const d = `M ${{x1}} ${{y1}} C ${{x1+dx}} ${{y1}}, ${{x2-dx}} ${{y2}}, ${{x2}} ${{y2}}`;
        const p = el('path', {{d, class:'edge', 'marker-end':'url(#arrow)'}});
        if (activeId && (e.source === activeId || e.target === activeId)) p.setAttribute('class','edge highlight');
        svg.appendChild(p);
      }});

      // nodes
      layout.keepNodes.forEach(n => {{
        const p = layout.pos.get(n.id);
        if (!p) return;
        const g = el('g', {{class:`node type-${{n.type}} ${{activeId===n.id ? 'active':''}}`, transform:`translate(${{p.x}},${{p.y}})`}});
        g.dataset.id = n.id;

        const rect = el('rect', {{x:0, y:0, width:nodeW, height:nodeH}});
        const label = el('text', {{x:10, y:17, fill:'#111'}}, n.label.length > 34 ? n.label.slice(0,34)+'…' : n.label);
        const badge = el('text', {{x:10, y:32, class:'badge', fill:'#555'}}, n.type.toUpperCase());
        g.appendChild(rect); g.appendChild(label); g.appendChild(badge);

        g.addEventListener('click', () => {{
          activeId = n.id;
          const isNeighbor = (id) => id === n.id || (adj.get(n.id) && adj.get(n.id).has(id));
          selMeta.textContent = `${{n.label}}  [${{n.type}}]`;
          selJson.textContent = JSON.stringify({{
            id: n.id,
            type: n.type,
            label: n.label,
            meta: n.meta || {{}},
            data: n.data || {{}},
            connected_to: (graph.edges || []).filter(e => e.source===n.id || e.target===n.id)
          }}, null, 2);
          draw();
        }});

        svg.appendChild(g);
      }});
    }}

    filterEl.addEventListener('input', draw);
    dirEl.addEventListener('change', draw);
    draw();
  }})();
  </script>
</div>
"""


def render_result(job_id: str, original_name: str, report_text: str, summary: dict, chain_graph: dict | None = None) -> bytes:
    preview_limit = 120000
    truncated = len(report_text) > preview_limit
    preview = report_text[:preview_limit] + ("\n\n... [TRUNCATED IN BROWSER PREVIEW] ..." if truncated else "")
    counts = summary.get("counts", {})
    graph_card = render_chain_map_card(chain_graph or {"nodes": [], "edges": []})
    body = f"""
<h1>Analysis Result</h1>
<p><a href="/">← Back to upload</a></p>
<div class="card">
  <div class="grid">
    <div>
      <div><b>Job ID:</b> <code>{html.escape(job_id)}</code></div>
      <div><b>Uploaded file:</b> {html.escape(original_name)}</div>
      <div><b>Analyzed at:</b> {html.escape(summary.get('analyzed_at','-'))}</div>
      <div><b>Show mode:</b> {html.escape(summary.get('show','all'))}</div>
      <div><b>Analyzer:</b> <code>{html.escape(summary.get('analyzer','-'))}</code></div>
    </div>
    <div>
      <div><b>Counts:</b></div>
      <ul>
        <li>TX carriers: {counts.get('carriers_tx', 0)} / RX carriers: {counts.get('carriers_rx', 0)}</li>
        <li>TX endpoints: {counts.get('endpoints_tx', 0)} / RX endpoints: {counts.get('endpoints_rx', 0)}</li>
        <li>TX links: {counts.get('links_tx', 0)} / RX links: {counts.get('links_rx', 0)}</li>
        <li>PRACH configs: {counts.get('prach_configs', 0)} / Processing elements: {counts.get('processing_elements', 0)}</li>
        <li>Validations: {summary.get('validations_count', 0)} / Parser warnings: {summary.get('warnings_count', 0)}</li>
      </ul>
    </div>
  </div>
  <p class="muted">Reports are rendered in-browser only. Server-side file saving and download links are disabled.</p>
</div>

{graph_card}

<div class="card"><h3>Report Preview {"(truncated)" if truncated else ""}</h3><pre>{html.escape(preview)}</pre></div>
"""
    return html_page("Analysis Result", body)


def build_summary(state, show_mode: str):
    return {
        "analyzed_at": now_str(),
        "show": show_mode,
        "analyzer": ANALYZER_PATH.name,
        "validations_count": len(getattr(state, "validations", []) or []),
        "warnings_count": len(getattr(state, "warnings", []) or []),
        "counts": {
            "carriers_tx": len(getattr(state, "carriers_tx", {}) or {}),
            "carriers_rx": len(getattr(state, "carriers_rx", {}) or {}),
            "endpoints_tx": len(getattr(state, "endpoints_tx", {}) or {}),
            "endpoints_rx": len(getattr(state, "endpoints_rx", {}) or {}),
            "links_tx": len(getattr(state, "links_tx", {}) or {}),
            "links_rx": len(getattr(state, "links_rx", {}) or {}),
            "prach_configs": len(getattr(state, "prach_configs", {}) or {}),
            "processing_elements": len(getattr(state, "processing_elements", {}) or {}),
        }
    }


def run_analysis(input_text: str, original_name: str, show_mode: str):
    suffix = Path(original_name).suffix or ".txt"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False) as tmp:
        tmp.write(input_text)
        temp_path = Path(tmp.name)
    try:
        state = ANALYZER.parse_mplane_log(str(temp_path))
    finally:
        temp_path.unlink(missing_ok=True)
    report = ANALYZER.render_report(state, show=show_mode)
    payload = ANALYZER.dataclass_to_jsonable_state(state)
    return state, report, payload


def _parse_multipart_form(headers, body: bytes):
    ctype = headers.get("Content-Type", "")
    if not ctype.startswith("multipart/form-data"):
        raise ValueError("Use multipart/form-data upload.")

    # Build a pseudo email message so stdlib email parser can parse multipart body.
    raw = (f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n").encode("utf-8") + body
    msg = BytesParser(policy=email_policy).parsebytes(raw)
    if not msg.is_multipart():
        raise ValueError("Multipart parse failed.")

    fields = {}
    files = {}
    for part in msg.iter_parts():
        cd = part.get("Content-Disposition", "")
        if "form-data" not in cd:
            continue
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if not name:
            continue
        if filename is not None:
            files[name] = {
                "filename": filename,
                "content": payload,
                "content_type": part.get_content_type(),
            }
        else:
            try:
                fields[name] = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                fields[name] = payload.decode("utf-8", errors="replace")
    return fields, files


class MPlaneWebHandler(BaseHTTPRequestHandler):
    server_version = "MPlaneAnalyzerWeb/1.3"

    def _send_bytes(self, data: bytes, status=200, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, text: str, status=200):
        self._send_bytes(text.encode("utf-8"), status=status, content_type="text/plain; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_bytes(render_index())
            return
        if parsed.path == "/healthz":
            return self._send_text("ok")
        self._send_bytes(html_page("Not Found", "<h1>404</h1><p>Not found</p>"), status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/analyze":
            return self.handle_analyze()
        self._send_bytes(html_page("Not Found", "<h1>404</h1><p>Not found</p>"), status=404)

    def handle_download(self, parsed):
        return self._send_text("Downloads are disabled; reports are no longer saved on the server.", status=410)

    def handle_analyze(self):
        try:
            clen = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            clen = 0
        if clen <= 0:
            return self._send_bytes(render_index("Empty request body.", error=True), status=400)
        if clen > MAX_UPLOAD_MB * 1024 * 1024:
            return self._send_bytes(render_index(f"Upload too large (>{MAX_UPLOAD_MB}MB).", error=True), status=413)

        try:
            body = self.rfile.read(clen)
            fields, files = _parse_multipart_form(self.headers, body)
        except Exception as e:
            return self._send_bytes(render_index(f"Failed to parse form: {e}", error=True), status=400)

        file_item = files.get("mplane_file")
        if not file_item:
            return self._send_bytes(render_index("No file uploaded.", error=True), status=400)

        show_mode = (fields.get("show", "all") or "all").strip().lower()
        if show_mode not in {"all", "chain", "endpoint", "validate", "warnings", "history"}:
            show_mode = "all"

        original_name = safe_name(file_item.get("filename") or "upload.txt")
        raw_bytes = file_item.get("content", b"") or b""
        if not raw_bytes:
            return self._send_bytes(render_index("Uploaded file is empty.", error=True), status=400)
        if len(raw_bytes) > MAX_UPLOAD_MB * 1024 * 1024:
            return self._send_bytes(render_index(f"Upload too large (>{MAX_UPLOAD_MB}MB).", error=True), status=413)

        text = raw_bytes.decode("utf-8", errors="replace")
        job_label = re.sub(r"[^A-Za-z0-9._-]+", "_", (fields.get("job_label", "") or "").strip())[:40]
        job_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
        if job_label:
            job_id = f"{job_label}_{job_id}"

        try:
            state, report, payload = run_analysis(text, original_name, show_mode)
            summary = build_summary(state, show_mode)
            summary.update({"job_id": job_id, "original_name": original_name})

            chain_graph = build_chain_graph_from_payload(payload)
            summary["graph_stats"] = chain_graph.get("stats", {})
            self._send_bytes(render_result(
                job_id, original_name, report, summary,
                chain_graph=chain_graph,
            ))
        except Exception as e:
            tb = traceback.format_exc()
            body_html = f"""
<h1>Analysis Failed</h1>
<p><a href="/">← Back to upload</a></p>
<div class="card"><div class="alert err">{html.escape(str(e))}</div>
<h3>Traceback</h3><pre>{html.escape(tb)}</pre></div>
"""
            self._send_bytes(html_page("Analysis Failed", body_html), status=500)

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s - %s\n" % (now_str(), self.address_string(), fmt % args))


def parse_args():
    p = argparse.ArgumentParser(description="Web server for M-Plane analyzer (TXT/XML upload)")
    p.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    p.add_argument("--max-upload-mb", type=int, default=50, help="Max upload size MB (default: 50)")
    return p.parse_args()


def main():
    global MAX_UPLOAD_MB
    args = parse_args()
    MAX_UPLOAD_MB = max(1, int(args.max_upload_mb))
    server = ThreadingHTTPServer((args.host, args.port), MPlaneWebHandler)
    print(f"[OK] M-Plane Analyzer Web running on http://{args.host}:{args.port}")
    print(f"     Analyzer module: {ANALYZER_PATH}")
    print(f"     Max upload size : {MAX_UPLOAD_MB} MB")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
