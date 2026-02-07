"""
Crawler 录制 smoke 脚本（best-effort）。

验证项（对应 AI分析_全端数据抓取方案任务清单.md Phase 6）：
- 启动后端
- 启动 crawler 会话录制一个本地站点
- 等待完成/停止
- 下载 session zip 并校验：
  - requests.json / trace.har / metadata.json 存在
  - request_bodies/ 落盘引用存在（大 body）
  - screenshots/ 落盘在 session 内（zip 自包含）
  - requests.json 中存在 requestfailed 记录（best-effort）

运行示例：
  python3 scripts/crawler_smoke.py

注意：
  - 需要已安装 Playwright 及浏览器（Chromium）。若环境缺失会失败。
"""

from __future__ import annotations

import json
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


class _SiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/":
            html = f"""
<!doctype html>
<html><head><meta charset="utf-8"><title>crawler-smoke</title></head>
<body>
  <h1>crawler smoke</h1>
  <a href="/page1">page1</a>
  <a href="/redirect">redirect</a>
  <script>
    // large POST -> trigger request_body_artifact spill
    fetch('/api/large', {{
      method: 'POST',
      headers: {{'Content-Type': 'text/plain'}},
      body: 'X'.repeat(6000),
    }}).catch(() => {{}});

    // connection refused -> trigger requestfailed best-effort
    fetch('http://127.0.0.1:9/fail').catch(() => {{}});
  </script>
</body></html>
"""
            payload = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if self.path == "/page1":
            html = """
<!doctype html>
<html><head><meta charset="utf-8"><title>page1</title></head>
<body>
  <h2>page1</h2>
  <a href="/page2">page2</a>
</body></html>
"""
            payload = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if self.path == "/page2":
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/page1")
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path == "/api/large":
            length = int(self.headers.get("Content-Length", "0") or "0")
            _body = self.rfile.read(length) if length > 0 else b""
            payload = json.dumps({"ok": True, "received": length}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):  # noqa: A003
        return


def _start_site() -> Tuple[HTTPServer, int]:
    httpd = HTTPServer(("127.0.0.1", 0), _SiteHandler)
    port = int(httpd.server_address[1])
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _start_backend(api_port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env.setdefault("BACKEND_PORT", str(api_port))
    env.setdefault("LOG_LEVEL", "WARNING")
    cmd = [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(api_port), "--log-level", "warning"]
    return subprocess.Popen(cmd, cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _http_json(method: str, url: str, payload: Dict[str, Any] | None = None, timeout: float = 30.0) -> Dict[str, Any]:
    try:
        import requests  # type: ignore

        if method.upper() == "GET":
            r = requests.get(url, timeout=timeout)
        elif method.upper() == "POST":
            r = requests.post(url, json=payload or {}, timeout=timeout)
        else:
            raise ValueError("unsupported_method")
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise RuntimeError(f"http_call_failed: {method} {url} ({e})") from e


def _http_get_bytes(url: str, timeout: float = 60.0) -> bytes:
    try:
        import requests  # type: ignore

        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return bytes(r.content or b"")
    except Exception as e:
        raise RuntimeError(f"download_failed: {url} ({e})") from e


def _wait_backend(api_port: int, timeout: float = 25.0) -> None:
    base = f"http://127.0.0.1:{api_port}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http_json("GET", f"{base}/api/v1/health", timeout=5.0)
            return
        except Exception:
            time.sleep(0.4)
    raise RuntimeError("backend_not_ready")


def _detect_zip_root(names: list[str]) -> str:
    tops = {n.split("/", 1)[0] for n in names if "/" in n and n.strip()}
    if len(tops) == 1:
        return list(tops)[0]
    # fallback: choose shortest top-level folder
    return sorted(list(tops), key=len)[0] if tops else ""


def main() -> int:
    api_port = _find_free_port()
    proc = _start_backend(api_port)
    base = f"http://127.0.0.1:{api_port}"

    httpd = None
    try:
        _wait_backend(api_port)
        print(f"[OK] Backend started: {base}")

        httpd, site_port = _start_site()
        start_url = f"http://127.0.0.1:{site_port}/"
        print(f"[OK] Local site: {start_url}")

        # Start crawler
        payload = {
            "config": {
                "url": start_url,
                "max_depth": 2,
                "follow_redirects": True,
                "capture_screenshots": True,
                "headless": True,
                "timeout": 30,
                "manual_recording": False,
                "hook_options": {
                    "network": True,
                    "storage": False,
                    "userInteraction": False,
                    "form": False,
                    "dom": False,
                    "navigation": False,
                    "console": False,
                    "performance": False,
                    "websocket": False,
                    "crypto": False,
                    "storageExport": False,
                    "stateManagement": False,
                },
                "use_system_chrome": False,
            },
            "session_name": "crawler_smoke",
        }
        resp = _http_json("POST", f"{base}/api/v1/crawler/start", payload, timeout=60.0)
        session_id = str(resp.get("session_id") or "")
        if not session_id:
            raise RuntimeError(f"invalid_start_response: {resp}")
        print(f"[OK] Crawler started: session={session_id}")

        # Wait for completion
        deadline = time.time() + 120.0
        status = "unknown"
        last_status: Dict[str, Any] | None = None
        while time.time() < deadline:
            st = _http_json("GET", f"{base}/api/v1/crawler/status/{session_id}", timeout=20.0)
            last_status = st
            status = str(st.get("status") or "unknown")
            if status in {"completed", "failed", "stopped"}:
                break
            time.sleep(1.2)
        if status not in {"completed", "stopped"}:
            errs = []
            try:
                errs = list((last_status or {}).get("errors") or [])
            except Exception:
                errs = []
            if errs:
                print("[FAIL] Crawler errors (top):")
                for e in errs[:6]:
                    print(f"  - {e}")
            raise RuntimeError(f"crawler_not_completed: status={status}")
        print(f"[OK] Crawler finished: status={status}")

        # Download zip
        zip_bytes = _http_get_bytes(f"{base}/api/v1/crawler/download/{session_id}", timeout=120.0)
        assert len(zip_bytes) > 200, "session_zip_empty"
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        names = zf.namelist()
        root = _detect_zip_root(names)
        assert root, "zip_root_not_found"

        required = {f"{root}/requests.json", f"{root}/trace.har", f"{root}/metadata.json"}
        missing = [p for p in required if p not in set(names)]
        assert not missing, f"missing_files:{missing}"

        # Self-contained screenshots: must be under root/screenshots/
        has_screens = any(n.startswith(f"{root}/screenshots/") for n in names)
        assert has_screens, "screenshots_missing"
        assert not any(n.startswith("screenshots/") for n in names), "screenshots_not_under_session_dir"

        # Parse requests.json to verify request_body_artifact + requestfailed
        req_raw = zf.read(f"{root}/requests.json").decode("utf-8", errors="replace")
        reqs = json.loads(req_raw or "[]")
        if not isinstance(reqs, list):
            raise RuntimeError("requests_json_invalid")

        has_body_artifact = False
        has_failed = False
        for r in reqs:
            if not isinstance(r, dict):
                continue
            if isinstance(r.get("request_body_artifact"), dict) and r["request_body_artifact"].get("relative_path"):
                has_body_artifact = True
            if r.get("failed") or r.get("failure_text") or r.get("error"):
                has_failed = True
        assert has_body_artifact, "request_body_artifact_missing"
        assert has_failed, "requestfailed_missing"

        # request_bodies file exists in zip (best-effort)
        has_request_bodies_dir = any(n.startswith(f"{root}/request_bodies/") for n in names)
        assert has_request_bodies_dir, "request_bodies_dir_missing"

        print("[OK] Crawler smoke OK")
        return 0

    except AssertionError as e:
        print(f"[FAIL] {e}")
        return 2
    except Exception as e:
        print(f"[FAIL] {e}")
        return 3
    finally:
        if httpd:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass
        try:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except Exception:
                proc.kill()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
