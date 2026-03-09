#!/usr/bin/env python3
"""Windows-friendly launcher/wrapper for M-Plane web analyzer (Nokia-patched aware)."""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
import importlib.util

BASE_DIR = Path(__file__).resolve().parent
SERVER_PATH = BASE_DIR / "mplane_web_server.py"


def load_server_module(path: Path):
    spec = importlib.util.spec_from_file_location("mplane_web_server", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load web server module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def detect_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    parser = argparse.ArgumentParser(description="Run M-Plane Analyzer Web on Windows")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (use 0.0.0.0 for remote access)")
    parser.add_argument("--port", type=int, default=8080, help="Port number")
    parser.add_argument("--max-upload-mb", type=int, default=50, help="Max upload size in MB")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--remote", action="store_true", help="Shortcut for --host 0.0.0.0")
    args = parser.parse_args()

    if args.remote:
        args.host = "0.0.0.0"

    if not SERVER_PATH.exists():
        print(f"[ERROR] Missing server file: {SERVER_PATH}")
        print("Place this file in the same folder as mplane_web_server.py and analyzer files.")
        sys.exit(1)

    mod = load_server_module(SERVER_PATH)
    mod.MAX_UPLOAD_MB = int(args.max_upload_mb)
    if hasattr(mod, "RESULT_DIR"):
        mod.RESULT_DIR.mkdir(parents=True, exist_ok=True)
    if hasattr(mod, "UPLOAD_DIR"):
        mod.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    server = mod.ThreadingHTTPServer((args.host, args.port), mod.MPlaneWebHandler)

    local_url = f"http://127.0.0.1:{args.port}"
    lan_ip = detect_local_ip()
    lan_url = f"http://{lan_ip}:{args.port}"
    analyzer_name = getattr(mod, "ANALYZER_PATH", Path("(unknown)"))

    print("=" * 76)
    print("M-Plane Analyzer Web Server (Windows)")
    print("=" * 76)
    print(f"Bind host        : {args.host}")
    print(f"Port             : {args.port}")
    print(f"Max upload size  : {args.max_upload_mb} MB")
    print(f"Analyzer         : {analyzer_name}")
    print(f"Local URL        : {local_url}")
    if args.host == "0.0.0.0":
        print(f"Remote URL (LAN) : {lan_url}")
        print("Note: Allow Python through Windows Defender Firewall if remote access is blocked.")
    print("Stop server      : Ctrl+C")
    print("Supports         : TXT/XML/LOG uploads, Nokia 'Sending/Received message' traces (patched analyzer)")
    print("=" * 76)

    if not args.no_browser:
        def _open_browser():
            time.sleep(1.0)
            try:
                webbrowser.open(local_url)
            except Exception:
                pass
        threading.Thread(target=_open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Stopping server...")
    finally:
        try:
            server.server_close()
        except Exception:
            pass
        print("[INFO] Server stopped.")


if __name__ == "__main__":
    if os.name == "nt":
        try:
            os.system("title M-Plane Analyzer Web Server")
        except Exception:
            pass
    main()
