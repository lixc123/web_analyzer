"""Proxy Capture 会话落盘（JSONL + 元信息）。

目标：
- 代理抓包 start/stop 形成 proxy_session_id
- 采集到的 HTTP/WS/诊断快照/产物索引落到 data/sessions/<proxy_session_id> 下
- 重启后仍可查询/导出，并可通过 request_id 快速定位会话
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from backend.app.config import settings
from backend.app.database import SessionLocal
from backend.models.proxy_capture_db import ProxySessionModel, ProxyRequestIndexModel

logger = logging.getLogger(__name__)


def generate_proxy_session_id(now: Optional[datetime] = None) -> str:
    dt = now or datetime.now()
    return f"proxy_session_{dt.strftime('%Y%m%d_%H%M%S')}"


@dataclass(frozen=True)
class _WriteItem:
    kind: str
    payload: Dict[str, Any]


class ProxySessionRecorder:
    """将代理抓包数据增量写入 session 目录。

    采用单写线程 + 队列，避免在抓包线程中频繁 IO。
    """

    def __init__(self, *, session_id: str, host: str, port: int):
        self.session_id = str(session_id)
        self.host = str(host)
        self.port = int(port)

        self.session_dir = (Path(settings.data_dir) / "sessions" / self.session_id).resolve()
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self._queue: "queue.Queue[Optional[_WriteItem]]" = queue.Queue(maxsize=8000)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"ProxySessionRecorder[{self.session_id}]", daemon=True)

        self._started_at = datetime.utcnow()
        self._ended_at: Optional[datetime] = None

        # counters maintained in writer thread
        self._request_count = 0
        self._response_count = 0
        self._ws_message_count = 0
        self._js_event_count = 0
        self._artifact_ids: Set[str] = set()

        self._files: Dict[str, Any] = {}

        self._init_db_session_row()
        self._write_meta(status="active")
        self._thread.start()

    # ------------------------
    # Public API
    # ------------------------

    def record_request(self, record: Dict[str, Any]) -> None:
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        self._enqueue("request", data)

        # DB index for quick lookup (best-effort; do not block capture)
        try:
            req_id = str(data.get("id") or "")
            if req_id:
                self._upsert_request_index(req_id=req_id, method=str(data.get("method") or ""), url=str(data.get("url") or ""), ts=float(data.get("timestamp") or 0))
        except Exception:
            pass

    def record_response(self, request_id: str, record: Dict[str, Any]) -> None:
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        data["request_id"] = str(request_id)
        self._enqueue("response", data)

    def record_error(self, request_id: str, record: Dict[str, Any]) -> None:
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        data["request_id"] = str(request_id)
        self._enqueue("error", data)

    def record_ws_connection_event(self, record: Dict[str, Any]) -> None:
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        self._enqueue("ws_event", data)

    def record_ws_message(self, record: Dict[str, Any]) -> None:
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        self._enqueue("ws_message", data)

    def record_diagnostics(self, record: Dict[str, Any]) -> None:
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        data.setdefault("timestamp", datetime.utcnow().isoformat())
        self._enqueue("diagnostics", data)

    def record_js_event(self, record: Dict[str, Any]) -> None:
        """记录 JS 注入侧采集到的事件（fetch/xhr/ws 等）。"""
        data = dict(record or {})
        data["proxy_session_id"] = self.session_id
        self._enqueue("js_event", data)

    def record_artifact(self, artifact: Dict[str, Any]) -> None:
        if not artifact:
            return
        artifact_id = str(artifact.get("artifact_id") or "")
        if not artifact_id:
            return
        self._enqueue("artifact", dict(artifact))

    def update_notes(self, notes: str) -> None:
        # meta file updated synchronously to reflect immediately in list UI
        self._write_meta(status="active", notes=notes)
        try:
            with SessionLocal() as db:
                row = db.get(ProxySessionModel, self.session_id)
                if row:
                    row.notes = str(notes or "")
                    db.commit()
        except Exception:
            pass

    def finalize(self, status: str = "stopped") -> None:
        if self._ended_at is not None:
            return
        self._ended_at = datetime.utcnow()

        # stop writer thread
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except Exception:
            pass

        self._thread.join(timeout=8)
        try:
            self._close_files()
        except Exception:
            pass

        self._write_meta(status=status)
        self._update_db_session_row(status=status)

        # build merged convenience files
        try:
            self._build_merged_requests()
        except Exception as exc:
            logger.warning("build merged requests failed: %s", exc)
        try:
            self._build_merged_websockets()
        except Exception as exc:
            logger.warning("build merged websockets failed: %s", exc)
        try:
            self._build_merged_js_events()
        except Exception as exc:
            logger.warning("build merged js events failed: %s", exc)

    # ------------------------
    # Internal
    # ------------------------

    def _enqueue(self, kind: str, payload: Dict[str, Any]) -> None:
        item = _WriteItem(kind=kind, payload=payload)
        try:
            self._queue.put(item, timeout=0.2)
        except queue.Full:
            # 极端情况下避免阻塞抓包线程：记录告警并丢弃
            logger.warning("ProxySessionRecorder queue full, dropping %s", kind)

    def _open_file(self, key: str, filename: str):
        f = self._files.get(key)
        if f:
            return f
        path = self.session_dir / filename
        f = open(path, "a", encoding="utf-8")
        self._files[key] = f
        return f

    def _close_files(self):
        for f in list(self._files.values()):
            try:
                f.close()
            except Exception:
                pass
        self._files = {}

    def _append_jsonl(self, key: str, filename: str, obj: Dict[str, Any]) -> None:
        f = self._open_file(key, filename)
        f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        f.flush()

    def _run(self):
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break

            try:
                if item.kind == "request":
                    self._request_count += 1
                    self._append_jsonl("requests", "proxy_requests.jsonl", item.payload)
                elif item.kind == "response":
                    self._response_count += 1
                    self._append_jsonl("responses", "proxy_responses.jsonl", item.payload)
                elif item.kind == "error":
                    self._append_jsonl("errors", "proxy_errors.jsonl", item.payload)
                elif item.kind == "ws_event":
                    self._append_jsonl("ws_events", "proxy_ws_events.jsonl", item.payload)
                elif item.kind == "ws_message":
                    self._ws_message_count += 1
                    self._append_jsonl("ws_messages", "proxy_ws_messages.jsonl", item.payload)
                elif item.kind == "diagnostics":
                    self._append_jsonl("diagnostics", "proxy_diagnostics.jsonl", item.payload)
                elif item.kind == "js_event":
                    self._js_event_count += 1
                    self._append_jsonl("js_events", "proxy_js_events.jsonl", item.payload)
                elif item.kind == "artifact":
                    artifact_id = str(item.payload.get("artifact_id") or "")
                    if artifact_id and artifact_id not in self._artifact_ids:
                        self._artifact_ids.add(artifact_id)
                        self._append_jsonl("artifacts", "proxy_artifacts.jsonl", item.payload)
            except Exception as exc:
                logger.debug("proxy session write failed: %s", exc)

        # best-effort flush
        try:
            self._close_files()
        except Exception:
            pass

    def _meta_path(self) -> Path:
        return self.session_dir / "proxy_meta.json"

    def _write_meta(self, *, status: str, notes: Optional[str] = None):
        try:
            path = self._meta_path()
            existing: Dict[str, Any] = {}
            if path.exists():
                try:
                    existing = json.loads(path.read_text(encoding="utf-8") or "{}")
                except Exception:
                    existing = {}

            data = {
                "kind": "proxy_capture",
                "session_id": self.session_id,
                "status": str(status),
                "host": self.host,
                "port": self.port,
                "started_at": existing.get("started_at") or self._started_at.isoformat(),
                "ended_at": self._ended_at.isoformat() if self._ended_at else existing.get("ended_at"),
                "request_count": int(existing.get("request_count") or self._request_count),
                "response_count": int(existing.get("response_count") or self._response_count),
                "ws_message_count": int(existing.get("ws_message_count") or self._ws_message_count),
                "js_event_count": int(existing.get("js_event_count") or self._js_event_count),
                "artifact_count": int(existing.get("artifact_count") or len(self._artifact_ids)),
                "notes": str(notes if notes is not None else existing.get("notes") or ""),
            }
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        except Exception as exc:
            logger.debug("write meta failed: %s", exc)

    def _init_db_session_row(self) -> None:
        try:
            with SessionLocal() as db:
                row = db.get(ProxySessionModel, self.session_id)
                if row:
                    # overwrite (rare)
                    row.status = "active"
                    row.host = self.host
                    row.port = self.port
                    row.started_at = self._started_at
                    row.ended_at = None
                else:
                    row = ProxySessionModel(
                        session_id=self.session_id,
                        status="active",
                        host=self.host,
                        port=self.port,
                        started_at=self._started_at,
                        ended_at=None,
                        notes="",
                        request_count=0,
                        ws_message_count=0,
                        artifact_count=0,
                    )
                    db.add(row)
                db.commit()
        except Exception as exc:
            logger.debug("init db proxy session row failed: %s", exc)

    def _update_db_session_row(self, status: str) -> None:
        try:
            with SessionLocal() as db:
                row = db.get(ProxySessionModel, self.session_id)
                if not row:
                    return
                row.status = str(status)
                row.ended_at = self._ended_at
                row.request_count = int(self._request_count)
                row.ws_message_count = int(self._ws_message_count)
                row.artifact_count = int(len(self._artifact_ids))
                db.commit()
        except Exception:
            pass

    def _upsert_request_index(self, *, req_id: str, method: str, url: str, ts: float) -> None:
        if not req_id:
            return
        try:
            dt = datetime.utcfromtimestamp(ts) if ts else datetime.utcnow()
        except Exception:
            dt = datetime.utcnow()

        try:
            with SessionLocal() as db:
                row = db.get(ProxyRequestIndexModel, req_id)
                if row:
                    row.session_id = self.session_id
                    row.method = method
                    row.url = url
                    row.timestamp = dt
                else:
                    db.add(
                        ProxyRequestIndexModel(
                            request_id=req_id,
                            session_id=self.session_id,
                            method=method,
                            url=url,
                            timestamp=dt,
                        )
                    )
                db.commit()
        except Exception:
            # index is best-effort
            pass

    def _load_jsonl(self, path: Path) -> list[Dict[str, Any]]:
        if not path.exists():
            return []
        items: list[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except Exception:
                continue
        return items

    def _build_merged_requests(self) -> None:
        """生成 proxy_requests.json（将 response/error 合并到 request）。"""
        reqs = self._load_jsonl(self.session_dir / "proxy_requests.jsonl")
        resps = self._load_jsonl(self.session_dir / "proxy_responses.jsonl")
        errs = self._load_jsonl(self.session_dir / "proxy_errors.jsonl")
        js_events = self._load_jsonl(self.session_dir / "proxy_js_events.jsonl")

        resp_map: Dict[str, Dict[str, Any]] = {}
        for r in resps:
            rid = str(r.get("request_id") or "")
            if rid:
                resp_map[rid] = r

        err_map: Dict[str, Dict[str, Any]] = {}
        for e in errs:
            rid = str(e.get("request_id") or "")
            if rid:
                err_map[rid] = e

        js_map: Dict[str, list[Dict[str, Any]]] = {}
        for ev in js_events:
            rid = str(ev.get("correlated_request_id") or "")
            if not rid:
                continue
            js_map.setdefault(rid, []).append(ev)
        for rid, lst in list(js_map.items()):
            try:
                lst.sort(key=lambda x: float(x.get("timestamp", 0) or 0))
                js_map[rid] = lst[-20:]
            except Exception:
                js_map[rid] = lst[-20:]

        merged: list[Dict[str, Any]] = []
        for req in reqs:
            rid = str(req.get("id") or "")
            out = dict(req)
            resp = resp_map.get(rid)
            if resp:
                out.update(
                    {
                        "status_code": resp.get("status_code"),
                        "response_headers": resp.get("response_headers"),
                        "response_body": resp.get("response_body"),
                        "response_body_artifact": resp.get("response_body_artifact"),
                        "response_body_preview_hex": resp.get("response_body_preview_hex"),
                        "response_size": resp.get("response_size"),
                        "response_time": resp.get("response_time"),
                        "content_type": resp.get("content_type") or out.get("content_type"),
                        "streaming": resp.get("streaming"),
                    }
                )
                if isinstance(resp.get("grpc"), dict):
                    existing = out.get("grpc")
                    if isinstance(existing, dict):
                        merged_grpc = dict(existing)
                        merged_grpc.update(resp.get("grpc") or {})
                        out["grpc"] = merged_grpc
                    else:
                        out["grpc"] = resp.get("grpc")
            err = err_map.get(rid)
            if err:
                out["error"] = err.get("error") or err
            if rid in js_map:
                out["js_events"] = js_map.get(rid)
            merged.append(out)

        # 最新在前（与 API 一致）
        try:
            merged.sort(key=lambda x: float(x.get("timestamp", 0) or 0), reverse=True)
        except Exception:
            pass

        (self.session_dir / "proxy_requests.json").write_text(json.dumps(merged, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    def _build_merged_websockets(self) -> None:
        """生成 proxy_ws_connections.json / proxy_ws_messages.json。"""
        events = self._load_jsonl(self.session_dir / "proxy_ws_events.jsonl")
        messages = self._load_jsonl(self.session_dir / "proxy_ws_messages.jsonl")

        conns: Dict[str, Dict[str, Any]] = {}
        for e in events:
            cid = str(e.get("connection_id") or e.get("id") or "")
            if not cid:
                continue
            event_type = str(e.get("event") or "")
            url = str(e.get("url") or "")
            ts = e.get("timestamp")
            conn = conns.get(cid) or {"id": cid, "url": url, "started_at": None, "ended_at": None, "status": "open", "message_count": 0, "last_seen": None}
            if url and not conn.get("url"):
                conn["url"] = url
            if event_type == "ws_start":
                conn["started_at"] = conn.get("started_at") or ts
                conn["status"] = "open"
            if event_type == "ws_end":
                conn["ended_at"] = ts
                conn["status"] = "closed"
            conn["last_seen"] = ts or conn.get("last_seen")
            conns[cid] = conn

        # message counts
        for m in messages:
            cid = str(m.get("connection_id") or "")
            if not cid:
                continue
            conn = conns.get(cid) or {"id": cid, "url": str(m.get("url") or ""), "started_at": None, "ended_at": None, "status": "open", "message_count": 0, "last_seen": None}
            conn["message_count"] = int(conn.get("message_count", 0) or 0) + 1
            conn["last_seen"] = m.get("timestamp") or conn.get("last_seen")
            conns[cid] = conn

        connections_list = sorted(list(conns.values()), key=lambda x: (x.get("last_seen") or 0), reverse=True)
        (self.session_dir / "proxy_ws_connections.json").write_text(json.dumps(connections_list, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

        # messages: keep chronological in file, but UI may sort
        (self.session_dir / "proxy_ws_messages.json").write_text(json.dumps(messages, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    def _build_merged_js_events(self) -> None:
        """将 JS 注入事件从 JSONL 合并为 JSON（便于前端/导出读取）。"""
        path = self.session_dir / "proxy_js_events.jsonl"
        if not path.exists():
            return
        items: list[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except Exception:
                continue
        try:
            items.sort(key=lambda x: float(x.get("timestamp", 0) or 0))
        except Exception:
            pass
        (self.session_dir / "proxy_js_events.json").write_text(json.dumps(items, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def find_session_dir(session_id: str) -> Path:
    return (Path(settings.data_dir) / "sessions" / str(session_id)).resolve()


def load_proxy_session_meta(session_id: str) -> Optional[Dict[str, Any]]:
    path = find_session_dir(session_id) / "proxy_meta.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        return None


def list_proxy_sessions(limit: int = 200, offset: int = 0) -> Dict[str, Any]:
    base = (Path(settings.data_dir) / "sessions").resolve()
    if not base.exists():
        return {"sessions": [], "total": 0, "limit": limit, "offset": offset}

    metas: list[Dict[str, Any]] = []
    for d in base.iterdir():
        if not d.is_dir():
            continue
        meta_path = d / "proxy_meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8") or "{}")
            if meta.get("kind") != "proxy_capture":
                continue
            metas.append(meta)
        except Exception:
            continue

    def _sort_key(m: Dict[str, Any]) -> str:
        return str(m.get("started_at") or "")

    metas.sort(key=_sort_key, reverse=True)
    total = len(metas)
    sliced = metas[int(offset) : int(offset) + int(limit)]
    return {"sessions": sliced, "total": total, "limit": limit, "offset": offset}


def _load_jsonl(path: Path) -> list[Dict[str, Any]]:
    if not path.exists():
        return []
    items: list[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            continue
    return items


def load_proxy_session_requests(session_id: str) -> list[Dict[str, Any]]:
    """加载某个会话的合并请求列表。"""
    session_dir = find_session_dir(session_id)
    merged_path = session_dir / "proxy_requests.json"
    if merged_path.exists():
        try:
            data = json.loads(merged_path.read_text(encoding="utf-8") or "[]")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    reqs = _load_jsonl(session_dir / "proxy_requests.jsonl")
    resps = _load_jsonl(session_dir / "proxy_responses.jsonl")
    errs = _load_jsonl(session_dir / "proxy_errors.jsonl")
    js_events = _load_jsonl(session_dir / "proxy_js_events.jsonl")

    resp_map: Dict[str, Dict[str, Any]] = {}
    for r in resps:
        rid = str(r.get("request_id") or "")
        if rid:
            resp_map[rid] = r

    err_map: Dict[str, Dict[str, Any]] = {}
    for e in errs:
        rid = str(e.get("request_id") or "")
        if rid:
            err_map[rid] = e

    js_map: Dict[str, list[Dict[str, Any]]] = {}
    for ev in js_events:
        rid = str(ev.get("correlated_request_id") or "")
        if not rid:
            continue
        js_map.setdefault(rid, []).append(ev)
    for rid, lst in list(js_map.items()):
        try:
            lst.sort(key=lambda x: float(x.get("timestamp", 0) or 0))
            js_map[rid] = lst[-20:]
        except Exception:
            js_map[rid] = lst[-20:]

    merged: list[Dict[str, Any]] = []
    for req in reqs:
        rid = str(req.get("id") or "")
        out = dict(req)
        resp = resp_map.get(rid)
        if resp:
            out.update(
                {
                    "status_code": resp.get("status_code"),
                    "response_headers": resp.get("response_headers"),
                    "response_body": resp.get("response_body"),
                    "response_body_artifact": resp.get("response_body_artifact"),
                    "response_body_preview_hex": resp.get("response_body_preview_hex"),
                    "response_size": resp.get("response_size"),
                    "response_time": resp.get("response_time"),
                    "content_type": resp.get("content_type") or out.get("content_type"),
                    "streaming": resp.get("streaming"),
                }
            )
            # gRPC meta merge（request 侧可能已写入 method/service 等）
            if isinstance(resp.get("grpc"), dict):
                existing = out.get("grpc")
                if isinstance(existing, dict):
                    merged_grpc = dict(existing)
                    merged_grpc.update(resp.get("grpc") or {})
                    out["grpc"] = merged_grpc
                else:
                    out["grpc"] = resp.get("grpc")
        err = err_map.get(rid)
        if err:
            out["error"] = err.get("error") or err
        if rid in js_map:
            out["js_events"] = js_map.get(rid)
        merged.append(out)

    try:
        merged.sort(key=lambda x: float(x.get("timestamp", 0) or 0), reverse=True)
    except Exception:
        pass
    return merged


def load_proxy_session_ws_connections(session_id: str) -> list[Dict[str, Any]]:
    session_dir = find_session_dir(session_id)
    path = session_dir / "proxy_ws_connections.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "[]")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    # fallback from jsonl
    events = _load_jsonl(session_dir / "proxy_ws_events.jsonl")
    messages = _load_jsonl(session_dir / "proxy_ws_messages.jsonl")

    conns: Dict[str, Dict[str, Any]] = {}
    for e in events:
        cid = str(e.get("connection_id") or "")
        if not cid:
            continue
        event_type = str(e.get("event") or "")
        url = str(e.get("url") or "")
        ts = e.get("timestamp")
        conn = conns.get(cid) or {"id": cid, "url": url, "started_at": None, "ended_at": None, "status": "open", "message_count": 0, "last_seen": None}
        if url and not conn.get("url"):
            conn["url"] = url
        if event_type == "ws_start":
            conn["started_at"] = conn.get("started_at") or ts
            conn["status"] = "open"
        if event_type == "ws_end":
            conn["ended_at"] = ts
            conn["status"] = "closed"
        conn["last_seen"] = ts or conn.get("last_seen")
        conns[cid] = conn

    for m in messages:
        cid = str(m.get("connection_id") or "")
        if not cid:
            continue
        conn = conns.get(cid) or {"id": cid, "url": str(m.get("url") or ""), "started_at": None, "ended_at": None, "status": "open", "message_count": 0, "last_seen": None}
        conn["message_count"] = int(conn.get("message_count", 0) or 0) + 1
        conn["last_seen"] = m.get("timestamp") or conn.get("last_seen")
        conns[cid] = conn

    return sorted(list(conns.values()), key=lambda x: (x.get("last_seen") or 0), reverse=True)


def load_proxy_session_ws_messages(session_id: str) -> list[Dict[str, Any]]:
    session_dir = find_session_dir(session_id)
    path = session_dir / "proxy_ws_messages.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "[]")
            return data if isinstance(data, list) else []
        except Exception:
            return []
    return _load_jsonl(session_dir / "proxy_ws_messages.jsonl")


def load_proxy_session_js_events(session_id: str) -> list[Dict[str, Any]]:
    """加载 JS 注入事件（fetch/xhr/ws stack 等）。"""
    session_dir = find_session_dir(session_id)
    path = session_dir / "proxy_js_events.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "[]")
            return data if isinstance(data, list) else []
        except Exception:
            return []
    return _load_jsonl(session_dir / "proxy_js_events.jsonl")


def delete_proxy_session(session_id: str) -> Dict[str, Any]:
    """删除会话目录、DB 索引，并清理该会话引用的 artifacts（best-effort）。"""
    from backend.app.config import settings as _settings
    from backend.app.database import SessionLocal
    from backend.models.proxy_capture_db import ProxySessionModel, ProxyRequestIndexModel
    from sqlalchemy import delete as _sqla_delete
    import shutil
    import json

    session_dir = find_session_dir(session_id)
    if not session_dir.exists() or not session_dir.is_dir():
        raise FileNotFoundError("session_not_found")

    deleted_artifacts = 0
    artifacts_path = session_dir / "proxy_artifacts.jsonl"
    if artifacts_path.exists():
        try:
            artifacts_dir = Path(_settings.proxy_artifacts_dir).resolve()
            for line in artifacts_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                aid = str((obj or {}).get("artifact_id") or "")
                if not aid:
                    continue
                try:
                    p = (artifacts_dir / aid).resolve()
                    if p.exists() and p.is_file() and artifacts_dir in p.parents:
                        p.unlink(missing_ok=True)
                        deleted_artifacts += 1
                except Exception:
                    continue
        except Exception:
            pass

    # delete dir
    shutil.rmtree(session_dir)

    # delete db rows (best-effort)
    try:
        with SessionLocal() as db:
            db.execute(_sqla_delete(ProxyRequestIndexModel).where(ProxyRequestIndexModel.session_id == session_id))
            db.execute(_sqla_delete(ProxySessionModel).where(ProxySessionModel.session_id == session_id))
            db.commit()
    except Exception:
        pass

    return {"deleted_artifacts": deleted_artifacts, "deleted_session_dir": str(session_dir)}
