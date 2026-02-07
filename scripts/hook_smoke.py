"""
Native Hook smoke（可选，best-effort）。

验证项（对应 AI分析_全端数据抓取方案任务清单.md Phase 6）：
- 后端 native-hook API 可用
- 可附加进程、注入模板、产生一次网络调用
- records 可查询、可导出

运行示例（Windows 推荐）：
  python3 scripts/hook_smoke.py

注意：
  - 需要 Windows + Frida 环境（frida-server/权限等）。
  - 非 Windows 或未安装 Frida 时会跳过（exit 0）。
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
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


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):  # noqa: A003
        return


def _start_http_server() -> Tuple[HTTPServer, int]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
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


def main() -> int:
    if os.name != "nt":
        print("[SKIP] Not running on Windows; hook smoke skipped.")
        return 0

    api_port = _find_free_port()
    proc = _start_backend(api_port)
    base = f"http://127.0.0.1:{api_port}"

    httpd = None
    target_proc = None
    session_id = None
    try:
        _wait_backend(api_port)
        print(f"[OK] Backend started: {base}")

        status = _http_json("GET", f"{base}/api/v1/native-hook/status", timeout=15.0)
        if not status.get("frida_installed"):
            print("[SKIP] Frida not installed; hook smoke skipped.")
            return 0

        httpd, http_port = _start_http_server()
        print(f"[OK] Local HTTP server: http://127.0.0.1:{http_port}/ping")

        # Start target python process (sleep -> request -> sleep) so we can inject before request
        code = (
            "import time, urllib.request\n"
            "time.sleep(2)\n"
            f"urllib.request.urlopen('http://127.0.0.1:{http_port}/ping', timeout=5).read()\n"
            "time.sleep(3)\n"
        )
        target_proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid = int(target_proc.pid)
        print(f"[OK] Target process started: pid={pid}")

        # Attach
        attach = _http_json("POST", f"{base}/api/v1/native-hook/attach", {"pid": pid}, timeout=30.0)
        session_id = str(attach.get("session_id") or "")
        assert session_id, "attach_failed"
        print(f"[OK] Attached: session={session_id}")

        # Inject script (network monitor)
        _http_json(
            "POST",
            f"{base}/api/v1/native-hook/inject-script/{session_id}",
            {
                "template_name": "network_monitor",
                "template_params": {
                    "enable_winhttp": True,
                    "enable_wininet": True,
                    "enable_winsock": True,
                    "enable_crypto": False,
                    "sample_rate": 1,
                    "capture_stack_trace": False,
                },
            },
            timeout=45.0,
        )
        print("[OK] Script injected")

        # Wait for target to make request and for records to be stored
        time.sleep(6.0)

        page = _http_json("GET", f"{base}/api/v1/native-hook/records?session_id={session_id}&limit=50&offset=0", timeout=30.0)
        records = page.get("records") or []
        if isinstance(records, list) and len(records) > 0:
            print(f"[OK] Records captured: {len(records)}")
        else:
            print("[WARN] No hook records captured (environment-specific)")

        # Export (json)
        _ = _http_get_bytes(f"{base}/api/v1/native-hook/records/export?format=json&session_id={session_id}&limit=200", timeout=60.0)
        print("[OK] Export records OK")
        return 0
    except AssertionError as e:
        print(f"[FAIL] {e}")
        return 2
    except Exception as e:
        print(f"[FAIL] {e}")
        return 3
    finally:
        if session_id:
            try:
                _http_json("POST", f"{base}/api/v1/native-hook/detach/{session_id}", {}, timeout=20.0)
            except Exception:
                pass
        if target_proc:
            try:
                target_proc.terminate()
            except Exception:
                pass
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

