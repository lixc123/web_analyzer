from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import websockets  # type: ignore
except Exception:  # pragma: no cover
    websockets = None  # type: ignore

logger = logging.getLogger(__name__)


class JsInjectionDependencyError(RuntimeError):
    pass


def _ensure_deps() -> None:
    missing = []
    if httpx is None:
        missing.append("httpx")
    if websockets is None:
        missing.append("websockets")
    if missing:
        raise JsInjectionDependencyError(
            f"JS 注入需要依赖: {', '.join(missing)}。请在 backend 的 venv 中安装：pip install -r backend/requirements.txt"
        )


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _safe_float(v: Any, default: float) -> float:
    try:
        return float(v)
    except Exception:
        return float(default)


def _generate_session_id() -> str:
    import datetime

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"js_injection_{ts}"


def generate_js_injection_script(
    *,
    sample_rate: float,
    capture_stack: bool,
    max_stack_lines: int,
    max_body_length: int,
    enable_ws_messages: bool,
) -> str:
    cfg = {
        "sampleRate": max(0.0, min(1.0, float(sample_rate))),
        "captureStack": bool(capture_stack),
        "maxStackLines": max(1, min(int(max_stack_lines), 120)),
        "maxBodyLength": max(0, min(int(max_body_length), 20000)),
        "enableWsMessages": bool(enable_ws_messages),
    }

    cfg_json = json.dumps(cfg, ensure_ascii=False)

    # NOTE: Keep this script self-contained and idempotent.
    return f"""
(function() {{
  'use strict';
  try {{
    if (window.__WEB_ANALYZER_JS_INJECTED__) return;
    window.__WEB_ANALYZER_JS_INJECTED__ = true;
  }} catch (e) {{}}

  const CONFIG = {cfg_json};
  const now = () => Date.now();
  const rnd = () => Math.random();
  const shouldSample = () => {{
    const r = CONFIG.sampleRate;
    if (r >= 1) return true;
    if (r <= 0) return false;
    return rnd() < r;
  }};

  const safeTrunc = (val, maxLen) => {{
    try {{
      if (val === undefined || val === null) return val;
      const s = typeof val === 'string' ? val : (() => {{
        if (val instanceof ArrayBuffer) return `[ArrayBuffer ${val.byteLength}]`;
        if (ArrayBuffer.isView(val)) return `[TypedArray ${val.byteLength}]`;
        if (val instanceof Blob) return `[Blob ${val.size}]`;
        if (val instanceof FormData) {{
          const keys = [];
          for (const [k] of val.entries()) keys.push(k);
          return `[FormData keys=${keys.slice(0, 50).join(',')}${{keys.length > 50 ? '...' : ''}}]`;
        }}
        if (typeof val === 'object') {{
          try {{
            return JSON.stringify(val);
          }} catch (e) {{
            return Object.prototype.toString.call(val);
          }}
        }}
        return String(val);
      }})();
      if (typeof s !== 'string') return s;
      if (!maxLen || maxLen <= 0) return '';
      return s.length > maxLen ? s.slice(0, maxLen) + '...[truncated]' : s;
    }} catch (e) {{
      return '[unavailable]';
    }}
  }};

  const getStack = () => {{
    try {{
      if (!CONFIG.captureStack) return '';
      const stack = (new Error()).stack || '';
      const lines = String(stack).split('\\n').slice(0, CONFIG.maxStackLines);
      return lines.join('\\n');
    }} catch (e) {{
      return '';
    }}
  }};

  const normalizeUrl = (u) => {{
    try {{
      if (!u) return '';
      const s = String(u);
      return new URL(s, location.href).href;
    }} catch (e) {{
      try {{ return String(u || ''); }} catch (_) {{ return ''; }}
    }}
  }};

  const emit = (type, data) => {{
    try {{
      console.log('[WEB_ANALYZER_JS_EVENT]', JSON.stringify({{
        id: 'js_' + Math.random().toString(16).slice(2) + '_' + now(),
        type,
        timestamp_ms: now(),
        ...data
      }}));
    }} catch (e) {{}}
  }};

  // Fetch
  try {{
    const originalFetch = window.fetch;
    if (originalFetch) {{
      window.fetch = async function(...args) {{
        const start = now();
        const sampled = shouldSample();
        const stack = sampled ? getStack() : '';
        const input = args[0];
        const init = args[1] || {{}};
        const url = normalizeUrl(typeof input === 'string' ? input : (input && input.url));
        const method = (init && init.method) || (input && input.method) || 'GET';
        if (sampled) {{
          emit('FETCH_START', {{
            url, method,
            headers: init && init.headers ? safeTrunc(init.headers, CONFIG.maxBodyLength) : undefined,
            body: init && init.body ? safeTrunc(init.body, CONFIG.maxBodyLength) : undefined,
            stack
          }});
        }}
        try {{
          const resp = await originalFetch.apply(this, args);
          if (sampled) {{
            emit('FETCH_RESPONSE', {{
              url, method,
              status: resp.status,
              duration_ms: now() - start
            }});
          }}
          return resp;
        }} catch (err) {{
          if (sampled) {{
            emit('FETCH_ERROR', {{
              url, method,
              error: safeTrunc(err && (err.message || String(err)), CONFIG.maxBodyLength),
              duration_ms: now() - start
            }});
          }}
          throw err;
        }}
      }};
    }}
  }} catch (e) {{}}

  // XHR
  try {{
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    const originalSetHeader = XMLHttpRequest.prototype.setRequestHeader;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {{
      this.__wa = {{
        method: method || 'GET',
        url: normalizeUrl(url),
        start: now(),
        stack: getStack(),
        headers: {{}},
        sampled: shouldSample()
      }};
      return originalOpen.call(this, method, url, ...rest);
    }};

    XMLHttpRequest.prototype.setRequestHeader = function(k, v) {{
      try {{
        if (this.__wa && this.__wa.headers) this.__wa.headers[k] = v;
      }} catch (e) {{}}
      return originalSetHeader.call(this, k, v);
    }};

    XMLHttpRequest.prototype.send = function(body) {{
      try {{
        const meta = this.__wa;
        if (meta && meta.sampled) {{
          emit('XHR_START', {{
            url: meta.url,
            method: meta.method,
            headers: meta.headers,
            body: body ? safeTrunc(body, CONFIG.maxBodyLength) : undefined,
            stack: meta.stack
          }});
          this.addEventListener('load', () => {{
            emit('XHR_RESPONSE', {{
              url: meta.url,
              method: meta.method,
              status: this.status,
              duration_ms: now() - meta.start
            }});
          }});
          this.addEventListener('error', () => {{
            emit('XHR_ERROR', {{
              url: meta.url,
              method: meta.method,
              duration_ms: now() - meta.start
            }});
          }});
        }}
      }} catch (e) {{}}
      return originalSend.call(this, body);
    }};
  }} catch (e) {{}}

  // WebSocket (constructor + optional message sizes)
  try {{
    const OriginalWebSocket = window.WebSocket;
    if (OriginalWebSocket) {{
      const WrappedWebSocket = function(url, protocols) {{
        const sampled = shouldSample();
        const absUrl = normalizeUrl(url);
        const stack = sampled ? getStack() : '';
        if (sampled) {{
          emit('WS_CREATE', {{ url: absUrl, protocols, stack }});
        }}
        const ws = protocols !== undefined ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
        try {{
          if (CONFIG.enableWsMessages && sampled) {{
            const originalSendWs = ws.send;
            ws.send = function(data) {{
              try {{ emit('WS_SEND', {{ url: absUrl, size: (typeof data === 'string') ? data.length : (data && data.byteLength) }}); }} catch (e) {{}}
              return originalSendWs.call(this, data);
            }};
            ws.addEventListener('message', (ev) => {{
              try {{
                const d = ev && ev.data;
                const size = (typeof d === 'string') ? d.length : (d && d.byteLength);
                emit('WS_MESSAGE', {{ url: absUrl, size }});
              }} catch (e) {{}}
            }});
          }}
        }} catch (e) {{}}
        return ws;
      }};

      WrappedWebSocket.prototype = OriginalWebSocket.prototype;
      WrappedWebSocket.OPEN = OriginalWebSocket.OPEN;
      WrappedWebSocket.CLOSED = OriginalWebSocket.CLOSED;
      WrappedWebSocket.CLOSING = OriginalWebSocket.CLOSING;
      WrappedWebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
      window.WebSocket = WrappedWebSocket;
    }}
  }} catch (e) {{}}

  try {{
    emit('READY', {{ href: location.href, userAgent: navigator.userAgent }});
  }} catch (e) {{}}
}})();
""".strip()


class CdpClient:
    def __init__(self, ws, *, on_event):
        self.ws = ws
        self._on_event = on_event
        self._id = 0
        self._pending: Dict[int, asyncio.Future] = {}
        self._receiver: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self._receiver and not self._receiver.done():
            return
        self._receiver = asyncio.create_task(self._run_receiver())

    async def close(self) -> None:
        if self._receiver and not self._receiver.done():
            self._receiver.cancel()
            try:
                await self._receiver
            except asyncio.CancelledError:
                pass
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.cancel()
        self._pending = {}
        try:
            await self.ws.close()
        except Exception:
            pass

    async def send(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._id += 1
        msg_id = self._id
        fut = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = fut
        payload = {"id": msg_id, "method": str(method), "params": params or {}}
        await self.ws.send(json.dumps(payload))
        resp = await asyncio.wait_for(fut, timeout=10)
        if isinstance(resp, dict):
            return resp
        return {"id": msg_id, "result": resp}

    async def _run_receiver(self) -> None:
        async for raw in self.ws:
            try:
                msg = json.loads(raw)
            except Exception:
                continue

            if "id" in msg:
                fut = self._pending.pop(int(msg.get("id") or 0), None)
                if fut and not fut.done():
                    fut.set_result(msg)
                continue

            method = msg.get("method")
            params = msg.get("params")
            if method:
                try:
                    await self._on_event(str(method), params or {})
                except Exception:
                    continue


@dataclass
class JsInjectionConfig:
    endpoint: str
    target_url_contains: Optional[str] = None
    sample_rate: float = 0.2
    capture_stack: bool = True
    max_stack_lines: int = 25
    max_body_length: int = 1200
    enable_ws_messages: bool = False
    proxy_session_id: Optional[str] = None


@dataclass
class JsInjectionSession:
    session_id: str
    config: JsInjectionConfig
    created_at_ms: int = field(default_factory=_now_ms)
    status: str = "running"
    attached_targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    event_count: int = 0

    # in-memory tail (UI usage)
    events: Deque[Dict[str, Any]] = field(default_factory=lambda: __import__("collections").deque(maxlen=5000))

    _poll_task: Optional[asyncio.Task] = None
    _target_tasks: Dict[str, asyncio.Task] = field(default_factory=dict)


class JsInjectionManager:
    """Manage JS injection sessions via Chrome DevTools Protocol (remote debugging port)."""

    _instance = None

    def __init__(self):
        self._sessions: Dict[str, JsInjectionSession] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "JsInjectionManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def list_sessions(self) -> List[Dict[str, Any]]:
        async with self._lock:
            return [self._session_to_dict(s) for s in self._sessions.values()]

    async def get_session(self, session_id: str) -> Optional[JsInjectionSession]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def start_session(self, config: JsInjectionConfig) -> Dict[str, Any]:
        _ensure_deps()
        session_id = _generate_session_id()
        session = JsInjectionSession(session_id=session_id, config=config)

        async with self._lock:
            self._sessions[session_id] = session

        session._poll_task = asyncio.create_task(self._poll_targets_loop(session))
        return {"session_id": session_id, "status": "running"}

    async def stop_session(self, session_id: str) -> Dict[str, Any]:
        async with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            return {"session_id": session_id, "status": "not_found"}

        session.status = "stopping"
        if session._poll_task and not session._poll_task.done():
            session._poll_task.cancel()
            try:
                await session._poll_task
            except asyncio.CancelledError:
                pass

        for t in list(session._target_tasks.values()):
            if not t.done():
                t.cancel()
        for t in list(session._target_tasks.values()):
            try:
                await t
            except asyncio.CancelledError:
                pass

        session.status = "stopped"
        return {"session_id": session_id, "status": "stopped"}

    def _session_to_dict(self, session: JsInjectionSession) -> Dict[str, Any]:
        return {
            "session_id": session.session_id,
            "status": session.status,
            "created_at_ms": session.created_at_ms,
            "endpoint": session.config.endpoint,
            "target_url_contains": session.config.target_url_contains,
            "sample_rate": session.config.sample_rate,
            "capture_stack": session.config.capture_stack,
            "max_stack_lines": session.config.max_stack_lines,
            "max_body_length": session.config.max_body_length,
            "enable_ws_messages": session.config.enable_ws_messages,
            "proxy_session_id": session.config.proxy_session_id,
            "attached_targets": list(session.attached_targets.values()),
            "event_count": session.event_count,
            "errors": session.errors[-10:],
        }

    async def _poll_targets_loop(self, session: JsInjectionSession) -> None:
        endpoint = session.config.endpoint.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                while session.status == "running":
                    try:
                        resp = await client.get(f"{endpoint}/json")
                        targets = resp.json() if resp.status_code == 200 else []
                        if not isinstance(targets, list):
                            targets = []
                    except Exception as e:
                        session.errors.append(f"list_targets_failed: {e}")
                        await asyncio.sleep(2)
                        continue

                    for t in targets:
                        try:
                            if not isinstance(t, dict):
                                continue
                            if str(t.get("type") or "") != "page":
                                continue
                            ws_url = str(t.get("webSocketDebuggerUrl") or "")
                            tid = str(t.get("id") or "")
                            url = str(t.get("url") or "")
                            title = str(t.get("title") or "")
                            if not ws_url or not tid:
                                continue

                            if session.config.target_url_contains and session.config.target_url_contains not in url:
                                continue

                            if tid in session._target_tasks and not session._target_tasks[tid].done():
                                continue

                            session.attached_targets[tid] = {"id": tid, "url": url, "title": title, "ws_url": ws_url}
                            session._target_tasks[tid] = asyncio.create_task(self._run_target(session, tid, ws_url, title, url))
                        except Exception:
                            continue

                    await asyncio.sleep(2)
        except asyncio.CancelledError:
            return
        except Exception as e:
            session.status = "error"
            session.errors.append(f"poll_loop_error: {e}")

    async def _run_target(self, session: JsInjectionSession, target_id: str, ws_url: str, title: str, target_url: str) -> None:
        script = generate_js_injection_script(
            sample_rate=session.config.sample_rate,
            capture_stack=session.config.capture_stack,
            max_stack_lines=session.config.max_stack_lines,
            max_body_length=session.config.max_body_length,
            enable_ws_messages=session.config.enable_ws_messages,
        )

        async def on_event(method: str, params: Dict[str, Any]) -> None:
            if method == "Runtime.consoleAPICalled":
                await self._handle_console_event(session, target_id, title, target_url, params)
                return
            if method == "Runtime.exceptionThrown":
                try:
                    txt = str((params or {}).get("exceptionDetails", {}).get("text") or "")
                    if txt:
                        session.errors.append(f"exception[{target_id}]: {txt}")
                except Exception:
                    pass

        try:
            async with websockets.connect(ws_url, ping_interval=20, ping_timeout=20, max_size=10 * 1024 * 1024) as ws:
                client = CdpClient(ws, on_event=on_event)
                await client.start()

                await client.send("Runtime.enable")
                await client.send("Page.enable")

                # Inject on new documents + current page (best-effort)
                try:
                    await client.send("Page.addScriptToEvaluateOnNewDocument", {"source": script})
                except Exception:
                    pass
                try:
                    await client.send("Runtime.evaluate", {"expression": script, "includeCommandLineAPI": False, "awaitPromise": False})
                except Exception:
                    pass

                # Keep connection alive until cancelled
                while session.status == "running":
                    await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            return
        except Exception as e:
            session.errors.append(f"target[{target_id}] error: {e}")

    async def _handle_console_event(self, session: JsInjectionSession, target_id: str, title: str, target_url: str, params: Dict[str, Any]) -> None:
        try:
            args = (params or {}).get("args") or []
            if not isinstance(args, list) or not args:
                return

            def _get_arg_value(i: int) -> Any:
                try:
                    obj = args[i]
                    if isinstance(obj, dict) and "value" in obj:
                        return obj.get("value")
                    return None
                except Exception:
                    return None

            prefix = _get_arg_value(0)
            if prefix != "[WEB_ANALYZER_JS_EVENT]":
                return

            payload_text = _get_arg_value(1)
            if not isinstance(payload_text, str) or not payload_text:
                return

            payload = json.loads(payload_text)
            if not isinstance(payload, dict):
                return

            event_id = str(payload.get("id") or f"js_{uuid.uuid4().hex}")
            event_type = str(payload.get("type") or "")
            ts_ms = int(payload.get("timestamp_ms") or _now_ms())

            url = str(payload.get("url") or payload.get("href") or "")
            method = str(payload.get("method") or ("GET" if event_type.startswith("WS_") else "")).upper() or None

            record: Dict[str, Any] = {
                "id": event_id,
                "event_type": event_type,
                "timestamp_ms": ts_ms,
                "timestamp": ts_ms / 1000.0,
                "url": url,
                "method": method,
                "stack": payload.get("stack"),
                "data": {k: v for k, v in payload.items() if k not in {"stack"}},
                "target": {"id": target_id, "title": title, "url": target_url},
                "proxy_session_id": session.config.proxy_session_id,
            }

            # Correlate with proxy request_id (best-effort)
            correlated = None
            if url and method:
                try:
                    from backend.proxy.service_manager import ProxyServiceManager

                    manager = ProxyServiceManager.get_instance()
                    storage = manager.get_storage()
                    correlated = storage.find_recent_request_id(url, method, window_seconds=5.0, base_timestamp=float(record["timestamp"]))
                    if correlated:
                        record["correlated_request_id"] = correlated
                        try:
                            storage.attach_js_event(str(correlated), {"id": event_id, "event_type": event_type, "timestamp": record["timestamp"], "stack": record.get("stack"), "url": url, "method": method})
                        except Exception:
                            pass
                except Exception:
                    correlated = None

            session.events.append(record)
            session.event_count += 1

            # Persist into proxy capture session (best-effort)
            try:
                if session.config.proxy_session_id:
                    from backend.proxy.service_manager import ProxyServiceManager

                    manager = ProxyServiceManager.get_instance()
                    recorder = manager.get_proxy_session_recorder()
                    if recorder:
                        recorder.record_js_event(record)
            except Exception:
                pass

            # Broadcast to frontend (reuse proxy WS channel)
            try:
                from backend.app.websocket.proxy_events import broadcaster

                await broadcaster.broadcast_js_event(record)
            except Exception:
                pass
        except Exception:
            return
