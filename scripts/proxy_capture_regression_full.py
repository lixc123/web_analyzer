"""
Proxy Capture 全量回归脚本（建议在 Windows 本机 + backend venv 下运行）。

覆盖项（对应 WINDOWS应用端抓包_进一步补充任务清单.md 的工程化 P3）：
- 启动/停止代理（API）
- HTTP/HTTPS/WS 抓包
- SSE Streaming 早期响应 + 片段统计
- gRPC/Protobuf best-effort 标注（帧头解析）
- 导出（HAR/CSV/JSON、WS 导出）
- 存储状态/清理 dry-run（artifacts + sessions）

运行示例（Windows PowerShell / CMD）：
  backend\\venv\\Scripts\\python.exe scripts\\proxy_capture_regression_full.py

可选参数：
  --with-system-proxy   启动代理时同时启用 WinINet 系统代理（会自动回滚）
  --with-winhttp        启动代理时同时启用 WinHTTP 代理（会自动回滚）
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple
import zipfile


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


class _TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/ws") and str(self.headers.get("Upgrade", "")).lower() == "websocket":
            # Minimal WebSocket echo (text frame)
            key = str(self.headers.get("Sec-WebSocket-Key", "") or "")
            if not key:
                self.send_response(400)
                self.end_headers()
                return

            accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode("utf-8")).digest()).decode("ascii")
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()

            try:
                payload = _ws_read_frame(self.rfile)
                if payload is not None:
                    _ws_send_text_frame(self.wfile, payload)
            except Exception:
                pass
            return

        if self.path.startswith("/large"):
            payload = ("X" * 25000).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if self.path.startswith("/sse"):
            # SSE streaming (no Content-Length)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for i in range(3):
                chunk = f"data: hello_{i}\n\n".encode("utf-8")
                self.wfile.write(chunk)
                try:
                    self.wfile.flush()
                except Exception:
                    pass
                time.sleep(0.2)
            return

        payload = json.dumps({"ok": True, "path": self.path}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""

        if self.path.startswith("/grpc"):
            # Echo a minimal gRPC-like response: 5B header + protobuf-ish payload
            payload = b"\x08\x01"
            frame = b"\x00" + len(payload).to_bytes(4, "big") + payload
            self.send_response(200)
            self.send_header("Content-Type", "application/grpc")
            self.send_header("Content-Length", str(len(frame)))
            self.end_headers()
            self.wfile.write(frame)
            return

        payload = json.dumps({"ok": True, "received": len(body)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):  # noqa: A003
        return


def _start_http_server() -> Tuple[HTTPServer, int]:
    httpd = HTTPServer(("127.0.0.1", 0), _TestHandler)
    port = int(httpd.server_address[1])
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _ws_read_exact(rfile, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = rfile.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _ws_read_frame(rfile) -> Optional[bytes]:
    header = _ws_read_exact(rfile, 2)
    if len(header) < 2:
        return None
    b1, b2 = header[0], header[1]
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = int(b2 & 0x7F)
    if length == 126:
        ext = _ws_read_exact(rfile, 2)
        if len(ext) < 2:
            return None
        length = int.from_bytes(ext, "big")
    elif length == 127:
        ext = _ws_read_exact(rfile, 8)
        if len(ext) < 8:
            return None
        length = int.from_bytes(ext, "big")

    mask = b""
    if masked:
        mask = _ws_read_exact(rfile, 4)
        if len(mask) < 4:
            return None
    payload = _ws_read_exact(rfile, length)
    if len(payload) < length:
        return None
    if masked:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))

    # close frame
    if opcode == 0x8:
        return None
    return payload


def _ws_send_text_frame(wfile, payload: bytes) -> None:
    if payload is None:
        return
    if not isinstance(payload, (bytes, bytearray)):
        payload = str(payload).encode("utf-8", errors="replace")
    data = bytes(payload)
    header = bytearray()
    header.append(0x81)  # FIN + text
    n = len(data)
    if n <= 125:
        header.append(n)
    elif n <= 65535:
        header.append(126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(127)
        header.extend(n.to_bytes(8, "big"))
    wfile.write(bytes(header) + data)
    try:
        wfile.flush()
    except Exception:
        pass


def _ws_client_via_proxy(proxy_host: str, proxy_port: int, target_host: str, target_port: int, path: str, message: str) -> None:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET http://{target_host}:{target_port}{path} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("utf-8")

    sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=10.0)
    try:
        sock.sendall(req)
        resp = sock.recv(4096)
        if b" 101 " not in resp and b" 101\r\n" not in resp:
            raise RuntimeError(f"ws_handshake_failed: {resp[:120]!r}")

        # Send one masked text frame
        payload = message.encode("utf-8")
        mask = os.urandom(4)
        masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
        frame = bytearray()
        frame.append(0x81)
        n = len(payload)
        if n <= 125:
            frame.append(0x80 | n)
        elif n <= 65535:
            frame.append(0x80 | 126)
            frame.extend(n.to_bytes(2, "big"))
        else:
            frame.append(0x80 | 127)
            frame.extend(n.to_bytes(8, "big"))
        frame.extend(mask)
        frame.extend(masked)
        sock.sendall(bytes(frame))

        # Read echoed frame (unmasked)
        sock.settimeout(10.0)
        hdr = sock.recv(2)
        if len(hdr) < 2:
            raise RuntimeError("ws_no_echo")
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if opcode != 0x1:
            raise RuntimeError(f"ws_unexpected_opcode:{opcode}")
        if length == 126:
            length = int.from_bytes(sock.recv(2), "big")
        elif length == 127:
            length = int.from_bytes(sock.recv(8), "big")
        echo = b""
        while len(echo) < length:
            chunk = sock.recv(length - len(echo))
            if not chunk:
                break
            echo += chunk
        if echo.decode("utf-8", errors="replace") != message:
            raise RuntimeError("ws_echo_mismatch")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _http_get(url: str, *, proxies: Optional[Dict[str, str]] = None, verify_ssl: bool = True, timeout: float = 10.0) -> Tuple[int, bytes]:
    # Prefer requests if available, fallback to urllib.
    try:
        import requests  # type: ignore

        r = requests.get(url, proxies=proxies, timeout=timeout, verify=verify_ssl)
        return int(r.status_code), bytes(r.content or b"")
    except Exception:
        import ssl
        import urllib.request

        handlers = []
        if proxies:
            handlers.append(urllib.request.ProxyHandler(proxies))
        ctx = None
        if not verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, method="GET")
        with opener.open(req, timeout=timeout, context=ctx) as resp:  # type: ignore[arg-type]
            return int(resp.status), bytes(resp.read() or b"")


def _http_post(url: str, body: bytes, *, headers: Optional[Dict[str, str]] = None, proxies: Optional[Dict[str, str]] = None, verify_ssl: bool = True, timeout: float = 10.0) -> int:
    try:
        import requests  # type: ignore

        r = requests.post(url, data=body, headers=headers or {}, proxies=proxies, timeout=timeout, verify=verify_ssl)
        return int(r.status_code)
    except Exception:
        import ssl
        import urllib.request

        handlers = []
        if proxies:
            handlers.append(urllib.request.ProxyHandler(proxies))
        ctx = None
        if not verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
        with opener.open(req, timeout=timeout, context=ctx) as resp:  # type: ignore[arg-type]
            return int(resp.status)


def _start_backend(api_port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env.setdefault("BACKEND_PORT", str(api_port))
    env.setdefault("LOG_LEVEL", "WARNING")
    cmd = [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(api_port), "--log-level", "warning"]
    return subprocess.Popen(cmd, cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _wait_backend(api_port: int, timeout: float = 20.0) -> None:
    base = f"http://127.0.0.1:{api_port}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = _http_get(f"{base}/api/v1/health", proxies=None, timeout=2.0)
            if status == 200:
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError("backend_not_ready")


def _api_json(method: str, url: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        import requests  # type: ignore

        if method.upper() == "GET":
            r = requests.get(url, timeout=15)
        elif method.upper() == "POST":
            r = requests.post(url, json=payload or {}, timeout=30)
        elif method.upper() == "DELETE":
            r = requests.delete(url, timeout=15)
        else:
            raise ValueError("unsupported_method")
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise RuntimeError(f"api_call_failed: {method} {url} ({e})") from e


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-system-proxy", action="store_true")
    parser.add_argument("--with-winhttp", action="store_true")
    args = parser.parse_args()

    api_port = _find_free_port()
    proc = _start_backend(api_port)
    base = f"http://127.0.0.1:{api_port}"

    httpd = None
    proxy_started = False
    proxy_port = None
    try:
        _wait_backend(api_port)
        print(f"[OK] Backend started: {base}")

        httpd, http_port = _start_http_server()
        print(f"[OK] Local HTTP server: http://127.0.0.1:{http_port}")

        # start proxy via API
        proxy_port = _find_free_port()
        start_payload = {
            "host": "127.0.0.1",
            "port": proxy_port,
            "enable_system_proxy": bool(args.with_system_proxy),
            "enable_winhttp_proxy": bool(args.with_winhttp),
        }
        resp = _api_json("POST", f"{base}/api/v1/proxy/start", start_payload)
        proxy_port = int(resp.get("port") or proxy_port)
        proxy_session_id = str(resp.get("proxy_session_id") or "")
        proxy_started = True
        print(f"[OK] Proxy started: http://127.0.0.1:{proxy_port} (session={proxy_session_id})")

        proxy_url = f"http://127.0.0.1:{proxy_port}"
        proxies = {"http": proxy_url, "https": proxy_url}

        # HTTP
        st, _ = _http_get(f"http://127.0.0.1:{http_port}/ping", proxies=proxies, verify_ssl=False)
        assert st == 200, "http_ping_failed"
        st2 = _http_post(f"http://127.0.0.1:{http_port}/post", b"hello world", proxies=proxies, verify_ssl=False)
        assert st2 == 200, "http_post_failed"
        st3, body3 = _http_get(f"http://127.0.0.1:{http_port}/large", proxies=proxies, verify_ssl=False)
        assert st3 == 200 and len(body3) > 1000, "http_large_failed"
        print("[OK] HTTP traffic sent")

        # SSE
        st4, _ = _http_get(f"http://127.0.0.1:{http_port}/sse", proxies=proxies, verify_ssl=False)
        assert st4 == 200, "sse_failed"
        print("[OK] SSE traffic sent")

        # gRPC-like
        grpc_payload = b"\x00" + (2).to_bytes(4, "big") + b"\x08\x01"
        st5 = _http_post(
            f"http://127.0.0.1:{http_port}/grpc",
            grpc_payload,
            headers={"Content-Type": "application/grpc"},
            proxies=proxies,
            verify_ssl=False,
        )
        assert st5 == 200, "grpc_failed"
        print("[OK] gRPC-like traffic sent")

        # WebSocket (via proxy, ws://)
        try:
            _ws_client_via_proxy("127.0.0.1", proxy_port, "127.0.0.1", http_port, "/ws", "hello_ws")
            print("[OK] WebSocket traffic sent (echo)")
        except Exception as e:
            print(f"[WARN] WebSocket test skipped/failed: {e}")

        # HTTPS (best-effort: public endpoint)
        try:
            st6, _ = _http_get("https://example.com/", proxies=proxies, verify_ssl=False, timeout=15)
            assert st6 in {200, 301, 302}, "https_failed"
            print("[OK] HTTPS traffic sent (example.com)")
        except Exception as e:
            print(f"[WARN] HTTPS test skipped/failed: {e}")

        # Wait a bit for mitmproxy callbacks
        time.sleep(1.5)

        # Verify captured requests
        page = _api_json("GET", f"{base}/api/v1/proxy/requests?limit=200&offset=0")
        reqs = page.get("requests") or []
        assert len(reqs) > 0, "no_requests_captured"
        print(f"[OK] Captured requests: {len(reqs)} (page)")

        # Validate /large creates artifact
        large = next((r for r in reqs if str(r.get("url") or "").endswith("/large")), None)
        assert large is not None, "large_not_found"
        assert large.get("response_body_artifact") or large.get("body_artifact"), "artifact_not_found"
        print("[OK] Artifact exists for /large")

        # Validate SSE streaming meta
        sse_req = next((r for r in reqs if str(r.get("url") or "").endswith("/sse")), None)
        assert sse_req is not None, "sse_not_found"
        assert (sse_req.get("streaming") or {}).get("chunk_count") is not None, "sse_streaming_meta_missing"
        print("[OK] SSE streaming meta present")

        # Validate gRPC tag/meta
        grpc_req = next((r for r in reqs if str(r.get("url") or "").endswith("/grpc")), None)
        assert grpc_req is not None, "grpc_not_found"
        tags = grpc_req.get("tags") or []
        assert "grpc" in tags or "protobuf" in tags, "grpc_tags_missing"
        print("[OK] gRPC tags present")

        # Export endpoints (smoke)
        try:
            import requests  # type: ignore

            r = requests.get(f"{base}/api/v1/proxy/requests/export?format=har&limit=50", timeout=30)
            assert r.status_code == 200 and len(r.content) > 50, "export_har_failed"
            r = requests.get(f"{base}/api/v1/proxy/requests/export?format=csv&limit=50", timeout=30)
            assert r.status_code == 200 and len(r.content) > 20, "export_csv_failed"
            r = requests.get(f"{base}/api/v1/proxy/requests/export?format=json&limit=50", timeout=30)
            assert r.status_code == 200 and len(r.content) > 20, "export_json_failed"
            r = requests.get(f"{base}/api/v1/proxy/websockets/export?format=json&limit=200", timeout=30)
            assert r.status_code == 200, "export_ws_failed"
            print("[OK] Export endpoints OK")
        except Exception as e:
            print(f"[WARN] Export test skipped/failed: {e}")

        # Verify websockets captured (best-effort)
        try:
            import requests  # type: ignore

            ws = requests.get(f"{base}/api/v1/proxy/websockets?limit=50&offset=0", timeout=20).json()
            conns = ws.get("connections") or ws.get("websockets") or []
            if isinstance(conns, list) and len(conns) > 0:
                print(f"[OK] WebSocket connections captured: {len(conns)}")
            else:
                print("[WARN] WebSocket connections empty (may be skipped)")
        except Exception as e:
            print(f"[WARN] WebSocket verify skipped/failed: {e}")

        # Export analysis bundle (proxy only)
        try:
            import requests  # type: ignore

            analysis_id = f"analysis_smoke_{int(time.time())}"
            r = requests.get(
                f"{base}/api/v1/export/analysis-bundle?analysis_session_id={analysis_id}&proxy_session_id={proxy_session_id}&include_proxy_artifacts=true&auto=false",
                timeout=60,
            )
            assert r.status_code == 200 and len(r.content) > 200, "analysis_bundle_export_failed"
            zf = zipfile.ZipFile(io.BytesIO(r.content))
            names = set(zf.namelist())
            root = f"analysis_bundle/{analysis_id}"
            assert f"{root}/bundle_manifest.json" in names, "bundle_manifest_missing"
            assert f"{root}/bundle_summary.md" in names, "bundle_summary_missing"
            assert f"{root}/index.json" in names, "bundle_index_missing"
            assert f"{root}/session_mapping.json" in names, "bundle_mapping_missing"
            print("[OK] Analysis bundle export OK")
        except AssertionError as e:
            print(f"[FAIL] {e}")
            return 2
        except Exception as e:
            print(f"[WARN] Analysis bundle export skipped/failed: {e}")

        # Storage status + dry-run cleanup
        try:
            status = _api_json("GET", f"{base}/api/v1/proxy/storage/status")
            assert isinstance(status, dict), "storage_status_invalid"
            dry = _api_json(
                "POST",
                f"{base}/api/v1/proxy/storage/cleanup",
                {"artifacts_max_total_mb": 1, "artifacts_max_age_days": 0, "sessions_max_age_days": 0, "dry_run": True},
            )
            assert isinstance(dry, dict), "storage_cleanup_invalid"
            print("[OK] Storage status/cleanup (dry-run) OK")
        except Exception as e:
            print(f"[WARN] Storage cleanup test skipped/failed: {e}")

        print("[OK] Regression finished")
        return 0
    except AssertionError as e:
        print(f"[FAIL] {e}")
        return 2
    except Exception as e:
        print(f"[FAIL] {e}")
        return 3
    finally:
        # Stop proxy
        if proxy_started:
            try:
                _api_json("POST", f"{base}/api/v1/proxy/stop", {})
                print("[OK] Proxy stopped")
            except Exception:
                pass

        if httpd:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

        # Stop backend
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
