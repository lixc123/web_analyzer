"""
Proxy Capture 回归自检脚本（本地、离线）。

用途：
- 验证 mitmproxy 代理抓包链路可用（request/response 回调）
- 验证大响应体会落盘为 artifact，并可通过 artifact_id 访问文件

运行：
  python scripts/proxy_capture_regression.py
"""

from __future__ import annotations

import sys
import http.server
import json
import socketserver
import threading
import time
from typing import Any, Dict, List

import httpx

from pathlib import Path

# Ensure repo root is on sys.path when running as `python scripts/...`
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.proxy.proxy_server import ProxyServer
from backend.proxy.artifacts import ProxyArtifactStore


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/large"):
            payload = ("X" * 25000).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        payload = json.dumps({"ok": True, "path": self.path}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        payload = json.dumps({"ok": True, "received": len(body)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A003
        # silence
        return


def main() -> int:
    # 1) Start local HTTP server
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    server_port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    # 2) Start proxy server
    captured_requests: List[Dict[str, Any]] = []
    captured_responses: List[Dict[str, Any]] = []

    def on_request(req: Dict[str, Any]):
        captured_requests.append(req)

    def on_response(resp: Dict[str, Any]):
        captured_responses.append(resp)

    proxy = ProxyServer(host="127.0.0.1", port=8899, on_request=on_request, on_response=on_response)
    proxy_port = proxy.start()

    # 3) Send traffic through proxy
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    # httpx 0.28+ uses `proxy=`; older versions used `proxies=`
    try:
        client = httpx.Client(proxy=proxy_url, timeout=10)
    except TypeError:
        client = httpx.Client(proxies={"http://": proxy_url, "https://": proxy_url}, timeout=10)

    with client:
        r1 = client.get(f"http://127.0.0.1:{server_port}/ping")
        r1.raise_for_status()
        r2 = client.post(f"http://127.0.0.1:{server_port}/post", content=b"hello world")
        r2.raise_for_status()
        r3 = client.get(f"http://127.0.0.1:{server_port}/large")
        r3.raise_for_status()

    # 4) Wait a bit for callbacks
    time.sleep(1.0)

    # 5) Assertions (print-based)
    print(f"[OK] HTTP server port: {server_port}")
    print(f"[OK] Proxy port: {proxy_port}")
    print(f"[OK] Captured requests: {len(captured_requests)}")
    print(f"[OK] Captured responses: {len(captured_responses)}")

    large_resp = None
    for resp in captured_responses:
        if str(resp.get("url", "")).endswith("/large"):
            large_resp = resp
            break

    if not large_resp:
        print("[FAIL] Did not capture /large response")
        return 2

    artifact = large_resp.get("body_artifact")
    if not artifact or not artifact.get("artifact_id"):
        print("[FAIL] /large did not create body_artifact (check proxy_body_inline_limit settings)")
        return 3

    store = ProxyArtifactStore()
    path = store.resolve_artifact_path(artifact["artifact_id"])
    if not path.exists():
        print(f"[FAIL] artifact file not found: {path}")
        return 4

    print(f"[OK] /large artifact: {artifact['artifact_id']} -> {path}")

    # 6) Cleanup
    proxy.stop()
    httpd.shutdown()
    httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
