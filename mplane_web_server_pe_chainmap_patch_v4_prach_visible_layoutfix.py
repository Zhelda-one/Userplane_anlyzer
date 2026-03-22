#!/usr/bin/env python3
"""Simple web UI for enhanced M-Plane analyzer (Nokia-patched) + interactive chain map.

Features
- Upload .txt/.xml/.log NETCONF M-Plane logs/configs
- Runs patched analyzer (Nokia NETCONF trace supported)
- Shows HTML result preview
- Download TXT / JSON outputs
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
RESULT_DIR = BASE_DIR / "mplane_web_results"
MAX_UPLOAD_MB = 50

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)


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
* {{ box-sizing: border-box; }}
:root {{
  color-scheme: light;
  --bg: linear-gradient(180deg, #f4f7ff 0%, #eef4ff 35%, #f7f9fc 100%);
  --card: rgba(255,255,255,0.82);
  --card-strong: rgba(255,255,255,0.96);
  --border: rgba(123, 145, 194, 0.22);
  --shadow: 0 18px 60px rgba(36, 62, 120, 0.10);
  --text: #16304d;
  --muted: #5f728c;
  --primary: #3867ff;
  --primary-2: #6c4dff;
  --accent: #00b8d9;
  --success: #0f9d7a;
  --warn-bg: rgba(255, 243, 205, 0.95);
  --warn-border: rgba(217, 171, 32, 0.35);
  --err-bg: rgba(255, 233, 233, 0.96);
  --err-border: rgba(226, 85, 85, 0.30);
}}
html, body {{ min-height: 100%; }}
body {{
  font-family: Inter, "Segoe UI", Arial, sans-serif;
  margin: 0;
  color: var(--text);
  line-height: 1.5;
  background:
    radial-gradient(circle at top left, rgba(108, 77, 255, 0.14), transparent 28%),
    radial-gradient(circle at top right, rgba(0, 184, 217, 0.16), transparent 24%),
    var(--bg);
}}
body::before {{
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(115deg, rgba(255,255,255,0.30), transparent 35%),
    linear-gradient(235deg, rgba(255,255,255,0.14), transparent 42%);
}}
.container {{ max-width: 1440px; margin: auto; padding: 28px 24px 44px; position: relative; z-index: 1; }}
.page-stack {{ display:flex; flex-direction:column; gap:18px; }}
.hero {{
  position: relative;
  overflow: hidden;
  padding: 30px 32px;
  border-radius: 28px;
  color: #fff;
  background: linear-gradient(135deg, #183b8c 0%, #315efb 45%, #23b8d4 100%);
  box-shadow: 0 24px 80px rgba(36, 62, 120, 0.25);
}}
.hero::after {{
  content: "";
  position: absolute;
  right: -90px;
  top: -70px;
  width: 260px;
  height: 260px;
  border-radius: 50%;
  background: rgba(255,255,255,0.12);
}}
.hero h1, .hero h2 {{ margin: 0 0 8px; line-height: 1.1; }}
.hero p {{ margin: 0; color: rgba(255,255,255,0.85); max-width: 860px; }}
.hero-grid {{ display:grid; grid-template-columns: minmax(0, 1.7fr) minmax(280px, 1fr); gap: 20px; align-items: end; }}
.hero-stats, .chip-row {{ display:flex; flex-wrap:wrap; gap:10px; }}
.hero-stat, .chip {{
  display:inline-flex; align-items:center; gap:8px;
  padding: 10px 14px; border-radius: 999px;
  background: rgba(255,255,255,0.14);
  border: 1px solid rgba(255,255,255,0.16);
  backdrop-filter: blur(12px);
}}
.hero-stat strong {{ font-size: 15px; }}
.card {{
  border: 1px solid var(--border);
  border-radius: 24px;
  padding: 22px;
  margin-bottom: 0;
  background: var(--card);
  box-shadow: var(--shadow);
  backdrop-filter: blur(16px);
}}
.card strong {{ color: var(--text); }}
.card-title {{ display:flex; justify-content:space-between; align-items:flex-start; gap:18px; margin-bottom: 16px; }}
.card-title h3 {{ margin:0; font-size: 22px; }}
.card-title p {{ margin:6px 0 0; color: var(--muted); }}
.eyebrow {{
  display:inline-flex; align-items:center; gap:8px;
  font-size: 12px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--primary-2);
}}
pre {{
  background: rgba(17, 31, 58, 0.96);
  color: #eaf1ff;
  border: 1px solid rgba(71, 100, 162, 0.35);
  padding: 16px;
  overflow-x: auto;
  white-space: pre-wrap;
  border-radius: 18px;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.06);
}}
code {{
  background: rgba(53, 88, 169, 0.10);
  color: #20407a;
  padding: 2px 6px;
  border-radius: 8px;
}}
label {{ display:block; margin: 0 0 8px; font-size: 13px; font-weight: 700; color: var(--muted); }}
input[type=file], select, input[type=text] {{
  width: 100%;
  min-width: 0;
  max-width: 100%;
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(111, 135, 180, 0.22);
  background: rgba(255,255,255,0.94);
  color: var(--text);
  outline: none;
  transition: border-color .2s ease, box-shadow .2s ease, transform .2s ease;
}}
input[type=file]:focus, select:focus, input[type=text]:focus {{
  border-color: rgba(56, 103, 255, 0.55);
  box-shadow: 0 0 0 4px rgba(56, 103, 255, 0.10);
}}
button, .btn {{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  padding: 12px 18px;
  border-radius: 16px;
  border: 0;
  cursor: pointer;
  font-weight: 700;
  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-2) 100%);
  color: #fff;
  text-decoration: none;
  box-shadow: 0 14px 30px rgba(74, 94, 230, 0.24);
  transition: transform .18s ease, box-shadow .18s ease, opacity .18s ease;
}}
button:hover, .btn:hover {{ transform: translateY(-1px); box-shadow: 0 16px 34px rgba(74, 94, 230, 0.28); text-decoration:none; }}
.btn.secondary {{
  background: rgba(255,255,255,0.88);
  color: var(--text);
  border: 1px solid rgba(111, 135, 180, 0.22);
  box-shadow: none;
}}
.btn.ghost {{
  background: rgba(255,255,255,0.10);
  color: #fff;
  border: 1px solid rgba(255,255,255,0.18);
  box-shadow: none;
}}
.muted {{ color: var(--muted); }}
.row {{ margin: 0; }}
.form-grid {{ display:grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 16px; }}
.span-12 {{ grid-column: span 12; }}
.span-6 {{ grid-column: span 6; }}
.span-4 {{ grid-column: span 4; }}
.span-8 {{ grid-column: span 8; }}
.alert {{
  background: var(--warn-bg);
  border: 1px solid var(--warn-border);
  padding: 14px 16px;
  border-radius: 18px;
  color: #6c4f00;
}}
.err {{ background: var(--err-bg); border-color: var(--err-border); color: #8a2020; }}
a {{ color: inherit; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.grid {{ display:grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
.grid3 {{ display:grid; grid-template-columns: 2fr 1fr; gap: 18px; }}
.feature-list, .metric-grid {{ display:grid; gap: 12px; }}
.feature-list {{ grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
.feature-item, .metric-card {{
  border-radius: 20px;
  padding: 16px;
  border: 1px solid rgba(111, 135, 180, 0.18);
  background: var(--card-strong);
}}
.feature-item strong, .metric-card strong {{ display:block; font-size: 15px; margin-bottom: 6px; }}
.metric-grid {{ grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }}
.metric-card .metric-value {{ font-size: 28px; font-weight: 800; line-height: 1.1; }}
.metric-card .metric-label {{ color: var(--muted); font-size: 13px; }}
.badge {{
  display:inline-flex; align-items:center; gap:6px;
  padding: 6px 10px; border-radius: 999px;
  background: rgba(56, 103, 255, 0.10); color: var(--primary-2);
  font-size: 12px; font-weight: 700;
}}
.toolbar {{ display:flex; flex-wrap:wrap; gap: 10px; align-items:center; }}
.dropzone {{
  position: relative;
  border: 1.5px dashed rgba(96, 120, 171, 0.32);
  border-radius: 22px;
  padding: 22px;
  background: linear-gradient(180deg, rgba(243, 247, 255, 0.96), rgba(255,255,255,0.92));
  transition: border-color .18s ease, transform .18s ease, background .18s ease;
}}
.dropzone.dragover {{
  border-color: rgba(56, 103, 255, 0.68);
  transform: translateY(-1px);
  background: linear-gradient(180deg, rgba(234, 241, 255, 0.98), rgba(255,255,255,0.96));
}}
.dropzone input[type=file] {{
  position: absolute;
  inset: 0;
  opacity: 0;
  cursor: pointer;
}}
.dropzone-main {{ pointer-events:none; display:flex; flex-direction:column; gap:10px; align-items:flex-start; }}
.dropzone-icon {{
  width: 46px; height: 46px; border-radius: 14px;
  display:grid; place-items:center;
  background: linear-gradient(135deg, rgba(56, 103, 255, 0.16), rgba(108, 77, 255, 0.18));
  font-size: 22px;
}}
.file-pill {{
  display:none;
  align-items:center;
  gap:8px;
  padding: 8px 12px;
  border-radius: 999px;
  background: rgba(16, 185, 129, 0.10);
  color: #0f7a64;
  font-size: 13px;
  font-weight: 700;
}}
.file-pill.ready {{ display:inline-flex; }}
.result-topbar {{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:14px;
  flex-wrap:wrap;
}}
.link-inline {{ color: var(--primary); font-weight: 700; }}
.subtle-divider {{ height:1px; background: linear-gradient(90deg, transparent, rgba(123,145,194,0.25), transparent); margin: 8px 0 4px; }}
mark {{
  background: rgba(255, 213, 79, 0.28);
  color: inherit;
  border-radius: 6px;
  padding: 1px 3px;
}}
@media (max-width: 1100px) {{
  .grid, .grid3, .hero-grid {{ grid-template-columns: 1fr; }}
}}
@media (max-width: 840px) {{
  .container {{ padding: 18px 14px 32px; }}
  .hero {{ padding: 24px 20px; border-radius: 22px; }}
  .card {{ padding: 18px; border-radius: 20px; }}
  .span-6, .span-4, .span-8 {{ grid-column: span 12; }}
}}
/* interactive graph */
.mm-wrap {{ border:1px solid #e6e6e6; border-radius:10px; background:#fff; }}
.mm-toolbar {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; padding:10px; border-bottom:1px solid #eee; }}
.mm-toolbar input, .mm-toolbar select {{ min-width: unset; }}
.mm-layout {{ display:grid; grid-template-columns: minmax(600px,1fr); gap: 0; }}
.mm-layout.with-selection {{ grid-template-columns: minmax(600px,1fr) 380px; }}
@media (max-width: 1200px) {{ .mm-layout, .mm-layout.with-selection {{ grid-template-columns: 1fr; }} }}
.mm-canvas {{ overflow:auto; background:#fcfcfc; }}
.mm-layout.with-selection .mm-canvas {{ border-right:1px solid #eee; }}
.mm-side {{ padding:12px; display:none; }}
.mm-layout.with-selection .mm-side {{ display:block; }}
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
svg.mm-svg .type-prach rect {{ fill:#fde7f3; stroke:#c2185b; }}
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
<div class="page-stack">
  <section class="hero">
    <div class="hero-grid">
      <div>
        <div class="eyebrow">⚡ RL1 PD US EngSupport &amp; PoC</div>
        <h1>User Plane Configuration Analyzer</h1>
        <p>업로드한 M-Plane NETCONF 로그를 빠르게 파싱하고, Link → Endpoint → Carrier → PE → Transport Flow 체인을 시각적으로 확인할 수 있도록 설계된 웹 분석기입니다.</p>
        <div class="chip-row" style="margin-top:16px;">
          <span class="chip">📡 Nokia trace friendly</span>
          <span class="chip">🧭 Chain map explorer</span>
          <span class="chip">🧪 Validation &amp; warnings</span>
        </div>
      </div>
      <div class="hero-stats">
        <span class="hero-stat"><strong>TXT / XML / LOG</strong> 업로드 지원</span>
        <span class="hero-stat"><strong>JSON + TXT</strong> 결과 다운로드</span>
        <span class="hero-stat"><strong>SVG / vis-network</strong> 그래프 뷰</span>
      </div>
    </div>
  </section>

  {msg_html}

  <div class="grid3">
    <section class="card">
      <div class="card-title">
        <div>
          <div class="eyebrow">Analyze</div>
          <h3>로그 업로드</h3>
          <p>드래그 앤 드롭 또는 파일 선택으로 분석을 시작하세요.</p>
        </div>
        <span class="badge">No external deps</span>
      </div>
      <form method="post" action="/analyze" enctype="multipart/form-data" id="uploadForm">
        <div class="form-grid">
          <div class="span-12 row">
            <label for="mplaneFile">Input file</label>
            <div class="dropzone" id="dropzone">
              <input id="mplaneFile" type="file" name="mplane_file" accept=".txt,.xml,.log,text/plain,application/xml,text/xml" required>
              <div class="dropzone-main">
                <div class="dropzone-icon">📁</div>
                <div>
                  <strong style="display:block; font-size:18px;">M-Plane 로그 파일을 여기로 드롭</strong>
                  <div class="muted">또는 클릭해서 <code>.txt</code>, <code>.xml</code>, <code>.log</code> 파일을 선택하세요.</div>
                </div>
                <div id="selectedFilePill" class="file-pill">✅ <span id="selectedFileName">No file selected</span></div>
              </div>
            </div>
          </div>
          <div class="span-6 row">
            <label for="showMode">Report section</label>
            <select id="showMode" name="show">
              <option value="all" selected>all</option>
              <option value="chain">chain</option>
              <option value="endpoint">endpoint</option>
              <option value="validate">validate</option>
              <option value="warnings">warnings</option>
              <option value="history">history</option>
            </select>
          </div>
          <div class="span-6 row">
            <label for="jobLabel">Job label (optional)</label>
            <input id="jobLabel" type="text" name="job_label" placeholder="e.g. nokia_rmod">
          </div>
          <div class="span-12 row toolbar">
            <button type="submit" id="analyzeBtn">🚀 Analyze &amp; Show Result</button>
            <span class="muted">업로드 후 결과 화면에서 TXT / JSON 다운로드와 interactive chain map 탐색이 가능합니다.</span>
          </div>
        </div>
      </form>
    </section>

    <aside class="card">
      <div class="card-title">
        <div>
          <div class="eyebrow">Highlights</div>
          <h3>지원 기능</h3>
          <p>실무 분석에 필요한 핵심 포인트를 빠르게 볼 수 있습니다.</p>
        </div>
      </div>
      <div class="feature-list">
        <div class="feature-item">
          <strong>NETCONF trace parsing</strong>
          <div class="muted">semicolon 로그와 Nokia <code>Sending message:/Received message:</code> 포맷을 모두 처리합니다.</div>
        </div>
        <div class="feature-item">
          <strong>Topology-style chain view</strong>
          <div class="muted">Link, Endpoint, Carrier, PRACH, PE, TF 관계를 연결 그래프로 탐색할 수 있습니다.</div>
        </div>
        <div class="feature-item">
          <strong>Downloadable artifacts</strong>
          <div class="muted">리포트 텍스트와 JSON 상태 덤프를 모두 저장/다운로드할 수 있습니다.</div>
        </div>
      </div>
    </aside>
  </div>
</div>
<script>
(function() {{
  const form = document.getElementById('uploadForm');
  const fileInput = document.getElementById('mplaneFile');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const dropzone = document.getElementById('dropzone');
  const pill = document.getElementById('selectedFilePill');
  const fileName = document.getElementById('selectedFileName');

  function updateFileName() {{
    const file = fileInput && fileInput.files && fileInput.files[0];
    if (!file) {{
      pill.classList.remove('ready');
      fileName.textContent = 'No file selected';
      return;
    }}
    pill.classList.add('ready');
    fileName.textContent = `${{file.name}} · ${{Math.max(1, Math.round(file.size / 1024))}} KB`;
  }}

  if (fileInput) fileInput.addEventListener('change', updateFileName);
  if (dropzone && fileInput) {{
    ['dragenter', 'dragover'].forEach(evt => dropzone.addEventListener(evt, (e) => {{
      e.preventDefault();
      dropzone.classList.add('dragover');
    }}));
    ['dragleave', 'drop'].forEach(evt => dropzone.addEventListener(evt, (e) => {{
      e.preventDefault();
      dropzone.classList.remove('dragover');
    }}));
    dropzone.addEventListener('drop', (e) => {{
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {{
        fileInput.files = e.dataTransfer.files;
        updateFileName();
      }}
    }});
  }}
  if (form && analyzeBtn) {{
    form.addEventListener('submit', () => {{
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = '⏳ Analyzing...';
    }});
  }}
}})();
</script>
"""
    return html_page("User plane config Analyzer", body)


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
    Adds explicit PRACH config nodes and PE/Transport Flow chains.
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
    edge_seen = set()

    def add_node(nid: str, ntype: str, label: str, lane: int, data: dict | None = None, meta: dict | None = None):
        if not nid:
            return
        if nid in node_index:
            idx = node_index[nid]
            if data and not nodes[idx].get("data"):
                nodes[idx]["data"] = data
            if meta:
                nodes[idx].setdefault("meta", {}).update(meta)
            return
        node_index[nid] = len(nodes)
        nodes.append({
            "id": nid,
            "type": ntype,
            "label": str(label)[:120],
            "lane": lane,
            "data": data or {},
            "meta": meta or {},
        })

    def add_edge(src: str, dst: str, etype: str, label: str = ""):
        if not src or not dst:
            return
        key = (src, dst, etype, label)
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append({"source": src, "target": dst, "type": etype, "label": label})

    def ep_key_for(direction: str) -> str:
        return "low-level-tx-endpoint" if direction == "TX" else "low-level-rx-endpoint"

    def car_key_for(direction: str) -> str:
        return "tx-array-carrier" if direction == "TX" else "rx-array-carrier"

    def jump_terms_for(kind: str, name: str, direction: str | None = None) -> list[str]:
        terms = []
        if name and name != "N/A":
            terms.append(str(name))
        if kind == "link":
            if direction == "TX":
                terms += [f"TX Link: {name}", f"[TX Link] {name}", f"Link={name}"]
            elif direction == "RX":
                terms += [f"RX Link: {name}", f"[RX Link] {name}", f"Link={name}"]
        elif kind == "endpoint":
            terms += [f"Endpoint: {name}", f"  - {name}:"]
        elif kind == "carrier":
            terms += [f"Carrier: {name}", f"  - {name}:"]
        elif kind == "pe":
            terms += [f"Processing Element: {name}", f"PE={name}", name]
        elif kind == "prach":
            terms += [f"PRACH {name}", f"static-prach-config-id>{name}<", name]
        return list(dict.fromkeys([t for t in terms if t]))

    def add_prach_node_and_edge(ep_id: str, ep_name: str, ep: dict, direction: str):
        if direction != "RX" or not isinstance(ep, dict):
            return
        prach_key = None
        for keyname in ("static-prach-configuration", "prach-group"):
            v = ep.get(keyname)
            if v not in (None, "", []):
                prach_key = str(v)
                break
        if not prach_key:
            return
        pcfg = prach_configs.get(prach_key) or {}
        prid = f"PRACH:{prach_key}"
        add_node(
            prid, "prach", f"PRACH: {prach_key}", 4, data=pcfg,
            meta={"direction": direction, "prach_id": prach_key, "jump_terms": jump_terms_for("prach", prach_key, direction)}
        )
        add_edge(ep_id, prid, "endpoint-prach", "PRACH")
        # back-reference metadata on endpoint
        idx = node_index.get(ep_id)
        if idx is not None:
            nodes[idx].setdefault("meta", {})["prach_ref"] = {
                "key": prach_key,
                "exists": prach_key in prach_configs,
            }

    def add_pe_and_tfs(link_id: str, pe_name: str, pe: dict, direction: str):
        pid = f"PE:{pe_name}"
        add_node(
            pid, "pe", f"PE: {pe_name}", 3, data=pe,
            meta={"direction": direction, "jump_terms": jump_terms_for("pe", pe_name, direction)}
        )
        add_edge(link_id, pid, "link-pe", "PE")
        tf_list = _coerce_list(pe.get("transport-flow", {}) if isinstance(pe, dict) else {})
        for idx, flow in enumerate(tf_list, 1):
            tfid = f"{pid}:TF:{idx}"
            if isinstance(flow, dict):
                label = f"TF[{idx}] {flow.get('interface-name') or flow.get('name') or '-'}"
            else:
                label = f"TF[{idx}]"
            add_node(
                tfid, "tf", label, 5,
                data=flow if isinstance(flow, dict) else {"value": flow},
                meta={"direction": direction, "pe": pe_name, "tf_index": idx}
            )
            add_edge(pid, tfid, "pe-tf", "TF")

    def build_for(direction: str, links: dict, eps: dict, cars: dict):
        for link_name, link in sorted((links or {}).items()):
            link = link or {}
            ep_name = str(link.get(ep_key_for(direction), "N/A"))
            car_name = str(link.get(car_key_for(direction), "N/A"))
            pe_name = str(link.get("processing-element", "") or "N/A")

            lid = f"{direction}:LINK:{link_name}"
            eid = f"{direction}:EP:{ep_name}"
            cid = f"{direction}:CAR:{car_name}"

            ep = (eps or {}).get(ep_name) or {}
            car = (cars or {}).get(car_name) or {}
            pe = (pes or {}).get(pe_name) or {}

            add_node(lid, "link", f"{direction} Link: {link_name}", 0, data=link,
                     meta={"direction": direction, "name": link_name, "jump_terms": jump_terms_for("link", link_name, direction)})
            add_node(eid, "endpoint", f"{direction} EP: {ep_name}", 1, data=ep,
                     meta={"direction": direction, "name": ep_name, "jump_terms": jump_terms_for("endpoint", ep_name, direction)})
            add_node(cid, "carrier", f"{direction} CAR: {car_name}", 2, data=car,
                     meta={"direction": direction, "name": car_name, "jump_terms": jump_terms_for("carrier", car_name, direction)})

            add_edge(lid, eid, "link-endpoint", "EP")
            add_edge(lid, cid, "link-carrier", "CAR")

            add_prach_node_and_edge(eid, ep_name, ep if isinstance(ep, dict) else {}, direction)
            add_pe_and_tfs(lid, pe_name, pe if isinstance(pe, dict) else {}, direction)

    build_for("TX", links_tx, endpoints_tx, carriers_tx)
    build_for("RX", links_rx, endpoints_rx, carriers_rx)

    # Orphan PRACH configs
    for prach_id, pcfg in sorted((prach_configs or {}).items()):
        prid = f"PRACH:{prach_id}"
        add_node(prid, "prach", f"PRACH: {prach_id}", 4, data=pcfg if isinstance(pcfg, dict) else {"value": pcfg},
                 meta={"orphan": True, "jump_terms": jump_terms_for("prach", str(prach_id))})

    # Orphan PEs and TFs (not linked via links)
    for pe_name, pe in sorted((pes or {}).items()):
        pid = f"PE:{pe_name}"
        pre_edges = len(edges)
        add_node(pid, "pe", f"PE: {pe_name}", 3, data=pe if isinstance(pe, dict) else {"value": pe},
                 meta={"orphan": True, "jump_terms": jump_terms_for("pe", str(pe_name))})
        tf_list = _coerce_list((pe or {}).get("transport-flow", {}) if isinstance(pe, dict) else {})
        for idx, flow in enumerate(tf_list, 1):
            tfid = f"{pid}:TF:{idx}"
            label = f"TF[{idx}] {flow.get('interface-name') or flow.get('name') or '-'}" if isinstance(flow, dict) else f"TF[{idx}]"
            add_node(tfid, "tf", label, 5, data=flow if isinstance(flow, dict) else {"value": flow}, meta={"pe": pe_name, "tf_index": idx})
            add_edge(pid, tfid, "pe-tf", "TF")
        # mark as linked if any edge references it
        if any(e["source"] == pid or e["target"] == pid for e in edges):
            idxn = node_index.get(pid)
            if idxn is not None:
                nodes[idxn].setdefault("meta", {})["orphan"] = False

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "links_tx": len(links_tx),
            "links_rx": len(links_rx),
            "pe": len(pes),
            "prach": len(prach_configs),
        },
    }



def render_chain_map_card(graph: dict) -> str:
    graph_json = _json_for_html_script(graph)
    return f"""
<div class="card">
  <h3>Interactive Chain Map (Advanced)</h3>
  <p class="muted">Features: click details, <b>double-click node → jump to report preview</b>, improved auto layout (SVG), explicit PRACH nodes, Graph JSON download, and optional <b>vis-network</b> renderer.</p>
  <div class="mm-wrap">
    <div class="mm-toolbar">
      <label style="min-width:auto;">Filter</label>
      <input id="mmFilter" type="text" placeholder="Search name / interface / vlan / mac..." style="width:260px;">
      <label style="min-width:auto;">Direction</label>
      <select id="mmDir">
        <option value="ALL">ALL</option>
        <option value="TX">TX</option>
        <option value="RX">RX</option>
      </select>
      <label style="min-width:auto;">Renderer</label>
      <select id="mmRenderer">
        <option value="svg" selected>SVG (builtin)</option>
        <option value="vis">vis-network (advanced)</option>
      </select>
      <button type="button" id="mmDownloadGraphBtn">⬇ Graph JSON</button>
      <span class="mm-legend">
        <span style="background:#e8f0fe;">Link</span>
        <span style="background:#e8f5e9;">Endpoint</span>
        <span style="background:#fff3e0;">Carrier</span>
        <span style="background:#f3e5f5;">PE</span>
        <span style="background:#fce4ec;">PRACH</span>
        <span style="background:#e0f7fa;">TF</span>
      </span>
      <small class="kv" id="mmStats"></small>
    </div>
    <div class="mm-layout" id="mmLayout">
      <div class="mm-canvas">
        <div id="mmCanvasSvgWrap">
          <svg id="mmSvg" class="mm-svg" width="1700" height="900" viewBox="0 0 1700 900"></svg>
        </div>
        <div id="mmCanvasVisWrap" style="display:none; width:100%; height:900px; background:#fff;">
          <div id="mmVis" style="width:100%; height:100%;"></div>
        </div>
      </div>
      <div class="mm-side">
        <div class="mm-side-head"><b>Selected Node</b><button type="button" id="mmHideSelBtn">close</button></div>
        <div id="mmSelMeta" class="muted" style="margin:6px 0 10px;">(click an object to show details)</div>
        <pre id="mmSelJson" style="max-height:560px; overflow:auto;"></pre>
        <div id="mmJumpStatus" class="muted" style="margin-top:8px;">Tip: double-click graph node to jump in report preview.</div>
      </div>
    </div>
  </div>
  <details style="margin-top:8px;"><summary>Graph debug JSON</summary><pre id="mmGraphDebug" style="max-height:220px; overflow:auto;"></pre></details>
  <script id="mmGraphData" type="application/json">{graph_json}</script>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <script>
  (function(){{
    const graph = JSON.parse(document.getElementById('mmGraphData').textContent || '{{}}');
    const svg = document.getElementById('mmSvg');
    const svgWrap = document.getElementById('mmCanvasSvgWrap');
    const visWrap = document.getElementById('mmCanvasVisWrap');
    const visDiv = document.getElementById('mmVis');
    const filterEl = document.getElementById('mmFilter');
    const dirEl = document.getElementById('mmDir');
    const rendererEl = document.getElementById('mmRenderer');
    const dlBtn = document.getElementById('mmDownloadGraphBtn');
    const statsEl = document.getElementById('mmStats');
    const mmLayout = document.getElementById('mmLayout');
    const selMeta = document.getElementById('mmSelMeta');
    const selJson = document.getElementById('mmSelJson');
    const hideSelBtn = document.getElementById('mmHideSelBtn');
    const prachPanel = document.getElementById('mmPrachPanel');
    const prachSummary = document.getElementById('mmPrachSummary');
    const prachOccTbody = document.querySelector('#mmPrachOccTable tbody');
    const jumpStatus = document.getElementById('mmJumpStatus');
    const graphDebug = document.getElementById('mmGraphDebug');
    if (graphDebug) graphDebug.textContent = JSON.stringify(graph, null, 2);

    let activeId = null;
    let visNetwork = null;
    let visNodes = null;
    let visEdges = null;

    function norm(v) {{ return (v == null ? '' : String(v)).toLowerCase(); }}
    function escHtml(s) {{
      return String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
    }}
    function nodeSearchText(n) {{
      return norm((n.label||'') + ' ' + JSON.stringify(n.data || {{}}) + ' ' + JSON.stringify(n.meta || {{}}));
    }}
    function getNodeDirection(n) {{
      return (n.meta && n.meta.direction) ? String(n.meta.direction) : '';
    }}
    function directionCompatible(n, dir) {{
      if (dir === 'ALL') return true;
      const nd = getNodeDirection(n);
      if (!nd) return true; // keep neutral nodes unless edge filtering removes them
      return nd === dir;
    }}

    function passes(n, q, dir) {{
      if (!directionCompatible(n, dir)) return false;
      if (!q) return true;
      return nodeSearchText(n).includes(q);
    }}

    function filteredGraph() {{
      const nodes = graph.nodes || [];
      const edges = graph.edges || [];
      const q = norm(filterEl.value.trim());
      const dir = dirEl.value;
      const byId = new Map(nodes.map(n => [n.id, n]));
      const passMap = new Map(nodes.map(n => [n.id, passes(n, q, dir)]));
      const neighborKeep = new Set();

      // Only expand neighbors that are direction-compatible with current filter.
      edges.forEach(e => {{
        const s = byId.get(e.source), t = byId.get(e.target);
        if (!s || !t) return;
        const sPass = passMap.get(e.source), tPass = passMap.get(e.target);
        if (!(sPass || tPass)) return;
        if (directionCompatible(s, dir) && directionCompatible(t, dir)) {{
          neighborKeep.add(e.source); neighborKeep.add(e.target);
        }} else {{
          // If only one side is compatible, keep only the compatible side (prevents TX bleed into RX)
          if (directionCompatible(s, dir)) neighborKeep.add(e.source);
          if (directionCompatible(t, dir)) neighborKeep.add(e.target);
        }}
      }});

      const keepNodes = nodes.filter(n => (passMap.get(n.id) || neighborKeep.has(n.id)) && directionCompatible(n, dir));
      const keepSet = new Set(keepNodes.map(n => n.id));
      const keepEdges = edges.filter(e => {{
        if (!keepSet.has(e.source) || !keepSet.has(e.target)) return false;
        const s = byId.get(e.source), t = byId.get(e.target);
        // In TX/RX filtered view, suppress cross-direction edges entirely
        if (dir !== 'ALL') {{
          const sd = getNodeDirection(s), td = getNodeDirection(t);
          if ((sd && sd !== dir) || (td && td !== dir)) return false;
        }}
        return true;
      }});
      return {{nodes: keepNodes, edges: keepEdges}};
    }}

    function laneInfo(type) {{
      // lane ordering tuned to reduce crossing and make PRACH visible
      const map = {{
        // widened lane spacing to prevent PRACH/TF box overlap and improve readability
        link: [0, 60],
        endpoint: [1, 390],
        carrier: [2, 760],
        pe: [3, 1140],
        prach: [4, 1535],
        tf: [5, 1930],
      }};
      return map[type] || [6, 1600];
    }}

    function computeLayout(nodes, edges) {{
      // Sugiyama-ish layered layout with barycentric sorting and overlap resolution
      const laneBuckets = new Map();
      nodes.forEach(n => {{
        const [lane] = laneInfo(n.type);
        n._lane = lane;
        if (!laneBuckets.has(lane)) laneBuckets.set(lane, []);
        laneBuckets.get(lane).push(n);
      }});
      const lanes = [...laneBuckets.keys()].sort((a,b)=>a-b);
      lanes.forEach(l => laneBuckets.get(l).sort((a,b)=>String(a.label).localeCompare(String(b.label))));

      const inMap = new Map(), outMap = new Map();
      edges.forEach(e => {{
        if (!outMap.has(e.source)) outMap.set(e.source, []);
        if (!inMap.has(e.target)) inMap.set(e.target, []);
        outMap.get(e.source).push(e.target);
        inMap.get(e.target).push(e.source);
      }});

      // initial y by lane
      const pos = new Map();
      const nodeH = 44, gapY = 18, topPad = 54;
      lanes.forEach(l => {{
        const arr = laneBuckets.get(l) || [];
        arr.forEach((n, i) => {{
          const [,x] = laneInfo(n.type);
          pos.set(n.id, {{x, y: topPad + i * (nodeH + gapY)}});
        }});
      }});

      // barycentric reorder + local swap to reduce crossings
      function barycenter(ids, refMap) {{
        return ids.map(id => {{
          const refs = (refMap.get(id) || []).map(r => pos.get(r)).filter(Boolean);
          const b = refs.length ? refs.reduce((s,p)=>s+p.y,0)/refs.length : (pos.get(id)?.y || 0);
          return {{id, b}};
        }});
      }}
      for (let iter=0; iter<4; iter++) {{
        // left->right using incoming
        lanes.forEach((l, idx) => {{
          if (idx===0) return;
          const arr = laneBuckets.get(l) || [];
          const bc = barycenter(arr.map(n=>n.id), inMap).sort((a,b)=>a.b-b.b);
          laneBuckets.set(l, bc.map(x => arr.find(n=>n.id===x.id)));
          let y = 48;
          (laneBuckets.get(l)||[]).forEach(n => {{ pos.get(n.id).y = y; y += nodeH + gapY; }});
        }});
        // right->left using outgoing
        [...lanes].reverse().forEach((l, revIdx) => {{
          if (revIdx===0) return;
          const arr = laneBuckets.get(l) || [];
          const bc = barycenter(arr.map(n=>n.id), outMap).sort((a,b)=>a.b-b.b);
          laneBuckets.set(l, bc.map(x => arr.find(n=>n.id===x.id)));
          let y = 48;
          (laneBuckets.get(l)||[]).forEach(n => {{ pos.get(n.id).y = y; y += nodeH + gapY; }});
        }});
      }}

      // weighted vertical relaxation and collision resolution
      for (let iter=0; iter<8; iter++) {{
        lanes.forEach((l, idx) => {{
          const arr = laneBuckets.get(l) || [];
          arr.forEach(n => {{
            const refs = [...(inMap.get(n.id)||[]), ...(outMap.get(n.id)||[])].map(id => pos.get(id)).filter(Boolean);
            if (!refs.length) return;
            const avg = refs.reduce((s,p)=>s+p.y,0)/refs.length;
            pos.get(n.id).y = pos.get(n.id).y * 0.45 + avg * 0.55;
          }});
          const sorted = arr.slice().sort((a,b)=>pos.get(a.id).y - pos.get(b.id).y);
          let yCursor = 48;
          sorted.forEach(n => {{
            const p = pos.get(n.id);
            p.y = Math.max(p.y, yCursor);
            yCursor = p.y + nodeH + 8;
          }});
        }});
      }}

      // slight lane alignment to center by connected lanes
      lanes.forEach(l => {{
        const arr = laneBuckets.get(l) || [];
        if (!arr.length) return;
        const minY = Math.min(...arr.map(n => pos.get(n.id).y));
        if (minY < 40) {{
          const delta = 40 - minY;
          arr.forEach(n => pos.get(n.id).y += delta);
        }}
      }});

      const maxY = Math.max(700, ...nodes.map(n => (pos.get(n.id)?.y || 0) + 70));
      const maxX = Math.max(2200, ...nodes.map(n => (pos.get(n.id)?.x || 0) + 300));
      return {{pos, width:maxX+40, height:maxY+40, nodeW:260, nodeH:42}};
    }}

    function clearSvg() {{ while (svg.firstChild) svg.removeChild(svg.firstChild); }}
    function el(name, attrs={{}}, text=null) {{
      const e = document.createElementNS('http://www.w3.org/2000/svg', name);
      for (const [k,v] of Object.entries(attrs)) e.setAttribute(k, String(v));
      if (text != null) e.textContent = text;
      return e;
    }}

    function findNodeById(id) {{
      return (graph.nodes||[]).find(n => n.id === id) || null;
    }}
    function connectedEdges(id) {{
      return (graph.edges||[]).filter(e => e.source===id || e.target===id);
    }}
    function showNodeDetails(n) {{
      if (!n) return;
      if (mmLayout) mmLayout.classList.add('with-selection');
      selMeta.textContent = `${{n.label}} [${{n.type}}]${{getNodeDirection(n) ? ' / ' + getNodeDirection(n) : ''}}`;
      selJson.textContent = JSON.stringify({{
        id: n.id, type: n.type, label: n.label, lane: n.lane,
        meta: n.meta || {{}},
        data: n.data || {{}},
        connected_to: connectedEdges(n.id)
      }}, null, 2);
    }}

    function clearSelection() {{
      activeId = null;
      if (mmLayout) mmLayout.classList.remove('with-selection');
      selMeta.textContent = '(click an object to show details)';
      selJson.textContent = '';
      jumpStatus.textContent = 'Tip: double-click graph node to jump in report preview.';
      render();
    }}

    function candidateJumpTerms(n) {{
      const out = [];
      if (n.meta && Array.isArray(n.meta.jump_terms)) out.push(...n.meta.jump_terms);
      if (n.meta && n.meta.name) out.push(String(n.meta.name));
      if (n.data && n.data.name) out.push(String(n.data.name));
      if (n.label) {{
        out.push(n.label);
        const m = String(n.label).match(/:\s*(.+)$/);
        if (m) out.push(m[1]);
      }}
      return [...new Set(out.filter(Boolean).map(String))].sort((a,b)=>b.length-a.length);
    }}

    function jumpToReportNode(n) {{
      const reportPre = document.getElementById('reportPreview');
      if (!reportPre) {{
        jumpStatus.textContent = 'Report preview not found.';
        return;
      }}
      const raw = reportPre.dataset.rawText || reportPre.textContent || '';
      if (!raw) {{
        jumpStatus.textContent = 'Report preview is empty.';
        return;
      }}
      const terms = candidateJumpTerms(n);
      let hit = null;
      for (const term of terms) {{
        const idx = raw.indexOf(term);
        if (idx >= 0) {{ hit = {{term, idx}}; break; }}
      }}
      if (!hit) {{
        jumpStatus.textContent = `No report match found for ${{n.label}}`;
        return;
      }}

      const start = hit.idx;
      const end = hit.idx + hit.term.length;
      const before = raw.slice(0, start);
      const match = raw.slice(start, end);
      const after = raw.slice(end);

      reportPre.innerHTML = escHtml(before) + '<mark id="reportJumpMark">' + escHtml(match) + '</mark>' + escHtml(after);
      const mark = document.getElementById('reportJumpMark');
      if (mark) {{
        mark.scrollIntoView({{behavior:'smooth', block:'center'}});
      }}
      jumpStatus.textContent = `Jumped to report match: "${{hit.term}}"`;
    }}

    function drawSvg() {{
      const fg = filteredGraph();
      const nodes = fg.nodes, edges = fg.edges;
      const layout = computeLayout(nodes, edges);
      const pos = layout.pos;
      const nodeW = layout.nodeW, nodeH = layout.nodeH;
      svg.setAttribute('width', layout.width);
      svg.setAttribute('height', layout.height);
      svg.setAttribute('viewBox', `0 0 ${{layout.width}} ${{layout.height}}`);
      clearSvg();

      statsEl.textContent = `visible nodes: ${{nodes.length}} / ${{(graph.nodes||[]).length}}, edges: ${{edges.length}} / ${{(graph.edges||[]).length}}`;

      const defs = el('defs');
      const marker = el('marker', {{id:'arrow', markerWidth:'8', markerHeight:'8', refX:'7', refY:'4', orient:'auto'}});
      marker.appendChild(el('path', {{d:'M0,0 L8,4 L0,8 z', fill:'#b8bcc4'}}));
      defs.appendChild(marker); svg.appendChild(defs);

      const laneTitles = [ ['LINK',0], ['ENDPOINT',1], ['CARRIER',2], ['PE',3], ['PRACH',4], ['TF',5] ];
      laneTitles.forEach(([t,l]) => {{
        const x = [60,390,760,1140,1535,1930][l];
        svg.appendChild(el('text', {{x, y:20, fill:'#555', 'font-weight':'700'}}, t));
      }});

      const adj = new Map();
      (graph.edges||[]).forEach(e => {{
        if (!adj.has(e.source)) adj.set(e.source, new Set());
        if (!adj.has(e.target)) adj.set(e.target, new Set());
        adj.get(e.source).add(e.target); adj.get(e.target).add(e.source);
      }});

      edges.forEach(e => {{
        const s = pos.get(e.source), t = pos.get(e.target);
        if (!s || !t) return;
        const x1 = s.x + nodeW, y1 = s.y + nodeH/2, x2 = t.x, y2 = t.y + nodeH/2;
        const dx = Math.max(50, (x2-x1)*0.45);
        const d = `M ${{x1}} ${{y1}} C ${{x1+dx}} ${{y1}}, ${{x2-dx}} ${{y2}}, ${{x2}} ${{y2}}`;
        const cls = (activeId && (e.source===activeId || e.target===activeId)) ? 'edge highlight' : 'edge';
        const p = el('path', {{d, class:cls, 'marker-end':'url(#arrow)'}});
        p.addEventListener('click', () => {{
          jumpStatus.textContent = `Edge: ${{e.type}}  (${{e.source}} → ${{e.target}})`;
        }});
        svg.appendChild(p);
        if (e.label) {{
          const mx = (x1+x2)/2, my = (y1+y2)/2;
          svg.appendChild(el('text', {{x:mx, y:my-6, fill:'#777', 'font-size':'10', 'text-anchor':'middle'}}, e.label));
        }}
      }});

      nodes.forEach(n => {{
        const p = pos.get(n.id); if (!p) return;
        const cls = `node type-${{n.type}} ${{activeId===n.id ? 'active' : ''}}`;
        const g = el('g', {{class:cls, transform:`translate(${{p.x}},${{p.y}})`}});
        g.dataset.id = n.id;
        const rect = el('rect', {{x:0,y:0,width:nodeW,height:nodeH}});
        const labelText = (n.label||n.id);
        const label = el('text', {{x:10,y:17,fill:'#111'}}, labelText.length>40 ? labelText.slice(0,40)+'…' : labelText);
        const badgeParts = [String(n.type).toUpperCase()];
        if (getNodeDirection(n)) badgeParts.push(getNodeDirection(n));
        if (n.meta && n.meta.orphan) badgeParts.push('ORPHAN');
        const badge = el('text', {{x:10,y:32,class:'badge',fill:'#555'}}, badgeParts.join(' • '));
        g.appendChild(rect); g.appendChild(label); g.appendChild(badge);

        g.addEventListener('click', () => {{
          activeId = n.id;
          showNodeDetails(n);
          drawSvg();
        }});
        g.addEventListener('dblclick', (ev) => {{
          ev.preventDefault();
          activeId = n.id;
          showNodeDetails(n);
          drawSvg();
          jumpToReportNode(n);
        }});
        svg.appendChild(g);
      }});
    }}

    function visFilteredData() {{
      const fg = filteredGraph();
      return fg;
    }}

    function visColor(type) {{
      const m = {{
        link:'#e8f0fe', endpoint:'#e8f5e9', carrier:'#fff3e0',
        pe:'#f3e5f5', prach:'#fce4ec', tf:'#e0f7fa'
      }};
      return m[type] || '#f5f5f5';
    }}

    function renderVis() {{
      if (!(window.vis && window.vis.Network)) {{
        jumpStatus.textContent = 'vis-network library not loaded. Using SVG renderer.';
        rendererEl.value = 'svg';
        render();
        return;
      }}
      const fg = visFilteredData();
      const nodes = fg.nodes || [], edges = fg.edges || [];
      statsEl.textContent = `visible nodes: ${{nodes.length}} / ${{(graph.nodes||[]).length}}, edges: ${{edges.length}} / ${{(graph.edges||[]).length}} (vis)`;

      const visNodesArr = nodes.map(n => {{
        const dir = getNodeDirection(n);
        return {{
          id: n.id,
          label: n.label,
          shape: 'box',
          margin: 8,
          color: {{
            background: visColor(n.type),
            border: activeId===n.id ? '#ff9800' : '#8d99ae'
          }},
          font: {{face:'Arial', size:12}},
          group: n.type,
          title: `${{n.type}}${{dir ? ' / '+dir : ''}}`,
          level: (typeof n.lane === 'number') ? n.lane : (laneInfo(n.type)[0]),
          dataRef: n
        }};
      }});
      const visEdgesArr = edges.map((e,i) => {{
        return {{
          id: 'e'+i,
          from: e.source,
          to: e.target,
          label: e.label || '',
          arrows: 'to',
          color: (activeId && (e.source===activeId || e.target===activeId)) ? '#ff9800' : '#b8bcc4',
          smooth: {{type:'cubicBezier', forceDirection:'horizontal', roundness:0.4}},
          font: {{size:10, color:'#666'}}
        }};
      }});
      visNodes = new window.vis.DataSet(visNodesArr);
      visEdges = new window.vis.DataSet(visEdgesArr);
      const data = {{nodes: visNodes, edges: visEdges}};
      const options = {{
        layout: {{
          hierarchical: {{
            enabled: true,
            direction: 'LR',
            sortMethod: 'directed',
            nodeSpacing: 120,
            levelSeparation: 240,
            treeSpacing: 180,
            blockShifting: true,
            edgeMinimization: true,
            parentCentralization: true
          }}
        }},
        interaction: {{hover:true, navigationButtons:true, keyboard:true, multiselect:false}},
        physics: false,
        edges: {{smooth: {{enabled:true}}}}
      }};
      if (visNetwork) {{
        visNetwork.destroy();
        visNetwork = null;
      }}
      visNetwork = new window.vis.Network(visDiv, data, options);
      visNetwork.on('click', (params) => {{
        if (params.nodes && params.nodes.length) {{
          activeId = params.nodes[0];
          const n = findNodeById(activeId);
          showNodeDetails(n);
          render();
        }}
      }});
      visNetwork.on('doubleClick', (params) => {{
        if (params.nodes && params.nodes.length) {{
          activeId = params.nodes[0];
          const n = findNodeById(activeId);
          showNodeDetails(n);
          jumpToReportNode(n);
          render();
        }}
      }});
    }}

    function render() {{
      const mode = rendererEl.value;
      if (mode === 'vis') {{
        svgWrap.style.display = 'none';
        visWrap.style.display = 'block';
        renderVis();
      }} else {{
        if (visNetwork) {{ try {{ visNetwork.destroy(); }} catch(e){{}} visNetwork = null; }}
        visWrap.style.display = 'none';
        svgWrap.style.display = 'block';
        drawSvg();
      }}
    }}

    if (hideSelBtn) hideSelBtn.addEventListener('click', clearSelection);

    dlBtn.addEventListener('click', () => {{
      const blob = new Blob([JSON.stringify(graph, null, 2)], {{type:'application/json'}});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'chain_graph.json';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {{ URL.revokeObjectURL(a.href); a.remove(); }}, 1000);
    }});
    filterEl.addEventListener('input', render);
    dirEl.addEventListener('change', render);
    rendererEl.addEventListener('change', render);

    // Preserve raw report text for jump/highlight refreshes if preview pre exists
    const reportPre = document.getElementById('reportPreview');
    if (reportPre && !reportPre.dataset.rawText) {{
      reportPre.dataset.rawText = reportPre.textContent || '';
    }}

    render();
  }})();
  </script>
</div>
"""


def render_result(job_id: str, original_name: str, report_text: str, summary: dict, txt_url: str, json_url: str, chain_graph: dict | None = None) -> bytes:
    preview_limit = 120000
    truncated = len(report_text) > preview_limit
    preview = report_text[:preview_limit] + ("\n\n... [TRUNCATED IN BROWSER PREVIEW] ..." if truncated else "")
    counts = summary.get("counts", {})
    graph_card = render_chain_map_card(chain_graph or {"nodes": [], "edges": []})
    metric_cards = [
        ("TX carriers", counts.get("carriers_tx", 0)),
        ("RX carriers", counts.get("carriers_rx", 0)),
        ("TX endpoints", counts.get("endpoints_tx", 0)),
        ("RX endpoints", counts.get("endpoints_rx", 0)),
        ("TX links", counts.get("links_tx", 0)),
        ("RX links", counts.get("links_rx", 0)),
        ("PRACH configs", counts.get("prach_configs", 0)),
        ("Processing elements", counts.get("processing_elements", 0)),
        ("Validations", summary.get("validations_count", 0)),
        ("Parser warnings", summary.get("warnings_count", 0)),
    ]
    metrics_html = "".join(
        f'<div class="metric-card"><div class="metric-value">{html.escape(str(value))}</div><div class="metric-label">{html.escape(label)}</div></div>'
        for label, value in metric_cards
    )
    body = f"""
<div class="page-stack">
  <section class="hero">
    <div class="result-topbar">
      <a class="btn ghost" href="/">← Back to upload</a>
      <div class="chip-row">
        <span class="chip">🧠 Analyzer: {html.escape(summary.get('analyzer','-'))}</span>
        <span class="chip">🕒 {html.escape(summary.get('analyzed_at','-'))}</span>
      </div>
    </div>
    <div style="margin-top:18px;">
      <div class="eyebrow">Analysis Result</div>
      <h2 style="margin-top:8px;">{html.escape(original_name)}</h2>
      <p>Job ID <code>{html.escape(job_id)}</code> · 현재 표시 모드 <strong>{html.escape(summary.get('show','all'))}</strong> · 텍스트 리포트와 JSON 상태를 함께 내려받을 수 있습니다.</p>
    </div>
  </section>

  <section class="card">
    <div class="card-title">
      <div>
        <div class="eyebrow">Overview</div>
        <h3>분석 요약</h3>
        <p>오브젝트 수, 경고 수, 검증 수를 한눈에 볼 수 있도록 정리했습니다.</p>
      </div>
      <div class="toolbar">
        <a class="btn" href="{html.escape(txt_url)}">⬇ Download TXT</a>
        <a class="btn secondary" href="{html.escape(json_url)}">⬇ Download JSON</a>
      </div>
    </div>
    <div class="metric-grid">{metrics_html}</div>
    <div class="subtle-divider"></div>
    <div class="grid" style="margin-top:10px;">
      <div class="feature-item">
        <strong>Uploaded file</strong>
        <div class="muted">{html.escape(original_name)}</div>
      </div>
      <div class="feature-item">
        <strong>Show mode</strong>
        <div class="muted">{html.escape(summary.get('show','all'))}</div>
      </div>
    </div>
  </section>

  {graph_card}

  <section class="card">
    <div class="card-title">
      <div>
        <div class="eyebrow">Preview</div>
        <h3>Report Preview {"(truncated)" if truncated else ""}</h3>
        <p>그래프에서 노드를 더블 클릭하면 아래 리포트에서 해당 텍스트 위치로 점프합니다.</p>
      </div>
      <div class="toolbar">
        <button type="button" class="btn secondary" id="copyJobIdBtn" data-job-id="{html.escape(job_id)}">📋 Copy Job ID</button>
        <a class="link-inline" href="{html.escape(txt_url)}">open raw txt</a>
      </div>
    </div>
    <pre id="reportPreview">{html.escape(preview)}</pre>
  </section>
</div>
<script>
(function() {{
  const copyBtn = document.getElementById('copyJobIdBtn');
  if (!copyBtn) return;
  copyBtn.addEventListener('click', async () => {{
    const jobId = copyBtn.getAttribute('data-job-id') || '';
    try {{
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        await navigator.clipboard.writeText(jobId);
        copyBtn.textContent = '✅ Copied';
      }} else {{
        copyBtn.textContent = '⚠ Clipboard unavailable';
      }}
    }} catch (err) {{
      copyBtn.textContent = '⚠ Copy failed';
    }}
    setTimeout(() => {{ copyBtn.textContent = '📋 Copy Job ID'; }}, 1800);
  }});
}})();
</script>
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


def run_analysis(input_path: Path, show_mode: str):
    state = ANALYZER.parse_mplane_log(str(input_path))
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
        if parsed.path == "/download":
            return self.handle_download(parsed)
        if parsed.path == "/healthz":
            return self._send_text("ok")
        self._send_bytes(html_page("Not Found", "<h1>404</h1><p>Not found</p>"), status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/analyze":
            return self.handle_analyze()
        self._send_bytes(html_page("Not Found", "<h1>404</h1><p>Not found</p>"), status=404)

    def handle_download(self, parsed):
        qs = parse_qs(parsed.query)
        job_id = (qs.get("job", [""]) or [""])[0]
        kind = (qs.get("kind", [""]) or [""])[0]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{6,120}", job_id or ""):
            return self._send_text("Invalid job id", status=400)
        if kind not in {"txt", "json", "input"}:
            return self._send_text("Invalid kind", status=400)
        ext_map = {"txt": ".report.txt", "json": ".report.json", "input": ".input"}
        path = RESULT_DIR / f"{job_id}{ext_map[kind]}"
        if not path.exists() or not path.is_file():
            return self._send_text("File not found", status=404)
        ctype = "application/json; charset=utf-8" if kind == "json" else "text/plain; charset=utf-8"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.end_headers()
        self.wfile.write(data)

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

        input_path = RESULT_DIR / f"{job_id}.input"
        txt_path = RESULT_DIR / f"{job_id}.report.txt"
        json_path = RESULT_DIR / f"{job_id}.report.json"
        meta_path = RESULT_DIR / f"{job_id}.meta.json"

        try:
            input_path.write_text(text, encoding="utf-8")
            state, report, payload = run_analysis(input_path, show_mode)
            txt_path.write_text(report, encoding="utf-8")
            json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            summary = build_summary(state, show_mode)
            summary.update({"job_id": job_id, "original_name": original_name, "input_saved": input_path.name})

            chain_graph = build_chain_graph_from_payload(payload)
            summary["graph_stats"] = chain_graph.get("stats", {})

            meta_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
            self._send_bytes(render_result(
                job_id, original_name, report, summary,
                f"/download?job={job_id}&kind=txt",
                f"/download?job={job_id}&kind=json",
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
    print(f"     Results dir     : {RESULT_DIR}")
    print(f"     Max upload size : {MAX_UPLOAD_MB} MB")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
