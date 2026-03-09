#!/usr/bin/env python3
"""Simple web UI for enhanced M-Plane analyzer (Nokia-patched).

Features
- Upload .txt/.xml/.log NETCONF M-Plane logs/configs
- Runs patched analyzer (Nokia NETCONF trace supported)
- Shows HTML result preview
- Download TXT / JSON outputs

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
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.4; }}
.container {{ max-width: 1200px; margin: auto; }}
.card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
pre {{ background: #f7f7f7; border: 1px solid #eee; padding: 12px; overflow-x: auto; white-space: pre-wrap; }}
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
@media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class=\"container\">{body}</div>
</body>
</html>"""
    return page.encode("utf-8")


def render_index(message: str = "", error: bool = False) -> bytes:
    msg_html = f'<div class="alert {"err" if error else ""}">{html.escape(message)}</div>' if message else ''
    body = f"""
<h1>M-Plane Analyzer Web (TXT/XML Upload)</h1>
<p class=\"muted\">Uploads M-Plane NETCONF TXT/XML/LOG and analyzes with <code>{html.escape(ANALYZER_PATH.name)}</code> (Nokia trace supported in patched versions).</p>
{msg_html}
<div class=\"card\">
<form method=\"post\" action=\"/analyze\" enctype=\"multipart/form-data\">
  <div class=\"row\"><label>Input file</label><input type=\"file\" name=\"mplane_file\" accept=\".txt,.xml,.log,text/plain,application/xml,text/xml\" required></div>
  <div class=\"row\"><label>Report section</label>
    <select name=\"show\">
      <option value=\"all\" selected>all</option>
      <option value=\"chain\">chain</option>
      <option value=\"endpoint\">endpoint</option>
      <option value=\"validate\">validate</option>
      <option value=\"warnings\">warnings</option>
      <option value=\"history\">history</option>
    </select>
  </div>
  <div class=\"row\"><label>Job label (optional)</label><input type=\"text\" name=\"job_label\" placeholder=\"e.g. nokia_rmod\"></div>
  <div class=\"row\"><button type=\"submit\">Analyze &amp; Show Result</button></div>
</form>
</div>
<div class=\"card\">
  <b>Supported:</b> generic semicolon NETCONF traces, Nokia <code>Sending message:/Received message:</code> traces (patched analyzer), raw XML dumps.
</div>
"""
    return html_page("M-Plane Analyzer Web", body)


def render_result(job_id: str, original_name: str, report_text: str, summary: dict, txt_url: str, json_url: str) -> bytes:
    preview_limit = 120000
    truncated = len(report_text) > preview_limit
    preview = report_text[:preview_limit] + ("\n\n... [TRUNCATED IN BROWSER PREVIEW] ..." if truncated else "")
    counts = summary.get("counts", {})
    body = f"""
<h1>Analysis Result</h1>
<p><a href=\"/\">← Back to upload</a></p>
<div class=\"card\">
  <div class=\"grid\">
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
  <p>
    <a href=\"{html.escape(txt_url)}\">⬇ Download TXT report</a> &nbsp; | &nbsp;
    <a href=\"{html.escape(json_url)}\">⬇ Download JSON report</a>
  </p>
</div>
<div class=\"card\"><h3>Report Preview {"(truncated)" if truncated else ""}</h3><pre>{html.escape(preview)}</pre></div>
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
    server_version = "MPlaneAnalyzerWeb/1.2"

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
            meta_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
            self._send_bytes(render_result(job_id, original_name, report, summary,
                                           f"/download?job={job_id}&kind=txt",
                                           f"/download?job={job_id}&kind=json"))
        except Exception as e:
            tb = traceback.format_exc()
            body_html = f"""
<h1>Analysis Failed</h1>
<p><a href=\"/\">← Back to upload</a></p>
<div class=\"card\"><div class=\"alert err\">{html.escape(str(e))}</div>
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
