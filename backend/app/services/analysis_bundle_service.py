from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from backend.app.config import settings
from backend.app.services.hook_storage import HookStorage


_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _validate_safe_name(value: str, *, field: str) -> str:
    v = str(value or "").strip()
    if not v or not _SAFE_NAME_RE.match(v) or ".." in v or "/" in v or "\\" in v:
        raise ValueError(f"invalid_{field}")
    return v


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_analysis_session_id(now: Optional[datetime] = None) -> str:
    dt = now or datetime.now()
    return f"analysis_{dt.strftime('%Y%m%d_%H%M%S')}"


def _safe_relpath(path: Path) -> str:
    return str(path).replace("\\", "/")


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(str(url or ""))
        return parsed.netloc or ""
    except Exception:
        return ""


def _extract_path(url: str) -> str:
    try:
        parsed = urlparse(str(url or ""))
        p = parsed.path or "/"
        return p
    except Exception:
        return "/"


def _top_n(counter: Dict[str, int], n: int = 10) -> List[Dict[str, Any]]:
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)[: int(n)]
    return [{"key": k, "count": v} for k, v in items]


@dataclass(frozen=True)
class BundleSource:
    kind: str  # proxy|crawler|native_hook
    session_id: str
    root_in_bundle: str
    stats: Dict[str, Any]


class AnalysisBundleBuilder:
    def __init__(self) -> None:
        self._hook_storage = HookStorage()

    def build_zip(
        self,
        *,
        analysis_session_id: str,
        proxy_session_ids: List[str],
        crawler_session_ids: List[str],
        hook_session_ids: List[str],
        include_proxy_artifacts: bool = True,
    ) -> Path:
        """生成分析包 zip，并返回临时文件路径。"""
        safe_analysis_id = Path(analysis_session_id).name
        if safe_analysis_id != analysis_session_id:
            raise ValueError("invalid_analysis_session_id")

        # Validate session ids (prevent path traversal / unexpected inputs)
        proxy_session_ids = [_validate_safe_name(sid, field="proxy_session_id") for sid in (proxy_session_ids or [])]
        crawler_session_ids = [_validate_safe_name(sid, field="crawler_session_id") for sid in (crawler_session_ids or [])]
        hook_session_ids = [_validate_safe_name(sid, field="hook_session_id") for sid in (hook_session_ids or [])]

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{safe_analysis_id}.zip")
        tmp_path = Path(tmp.name)
        tmp.close()

        root_prefix = f"analysis_bundle/{safe_analysis_id}"

        sources: List[BundleSource] = []
        files: List[Dict[str, Any]] = []

        # Collect sources first (for manifest/index/summary)
        proxy_sources: List[BundleSource] = []
        for sid in proxy_session_ids:
            proxy_sources.append(self._collect_proxy_source(root_prefix, sid))
        crawler_sources: List[BundleSource] = []
        for sid in crawler_session_ids:
            crawler_sources.append(self._collect_crawler_source(root_prefix, sid))
        hook_sources: List[BundleSource] = []
        for sid in hook_session_ids:
            hook_sources.append(self._collect_hook_source(root_prefix, sid))

        sources.extend(proxy_sources)
        sources.extend(crawler_sources)
        sources.extend(hook_sources)

        proxy_artifacts: List[Dict[str, Any]] = []
        if include_proxy_artifacts:
            for src in proxy_sources:
                proxy_artifacts.extend(self._collect_proxy_artifacts(src.session_id))

        hook_artifacts: List[Dict[str, Any]] = []
        for src in hook_sources:
            hook_artifacts.extend(self._collect_hook_artifacts(src))

        index = self._build_index(root_prefix=root_prefix, sources=sources)
        mapping = self._build_mapping(
            analysis_session_id=safe_analysis_id,
            proxy_session_ids=proxy_session_ids,
            crawler_session_ids=crawler_session_ids,
            hook_session_ids=hook_session_ids,
        )
        index_bytes = json.dumps(index, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        mapping_bytes = json.dumps(mapping, ensure_ascii=False, indent=2, default=str).encode("utf-8")

        # Index/mapping file meta（summary/manifest 稍后生成）
        files.extend(
            [
                {"path": f"{root_prefix}/index.json", "size": len(index_bytes), "sha256": _sha256_bytes(index_bytes), "generated": True},
                {"path": f"{root_prefix}/session_mapping.json", "size": len(mapping_bytes), "sha256": _sha256_bytes(mapping_bytes), "generated": True},
            ]
        )

        # Build zip
        try:
            with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                # Add source directories / files
                for src in sources:
                    if src.kind in {"proxy", "crawler"}:
                        session_dir = Path(settings.data_dir) / "sessions" / src.session_id
                        self._zip_add_tree(zf, session_dir, f"{root_prefix}/{src.root_in_bundle}", file_entries=files)
                    elif src.kind == "native_hook":
                        # Hook sources are generated (json) rather than copied from disk.
                        hook_dir = f"{root_prefix}/{src.root_in_bundle}"
                        hook_payload = src.stats.get("hook_export") or {}
                        hook_session_bytes = json.dumps(hook_payload.get("session") or {}, ensure_ascii=False, indent=2, default=str).encode("utf-8")
                        hook_records_bytes = json.dumps(hook_payload.get("records") or [], ensure_ascii=False, indent=2, default=str).encode("utf-8")
                        zf.writestr(f"{hook_dir}/hook_session.json", hook_session_bytes)
                        zf.writestr(f"{hook_dir}/hook_records.json", hook_records_bytes)
                        # Optional: per-correlated mapping for convenience
                        hook_by_corr_bytes = json.dumps(hook_payload.get("records_by_correlated_request_id") or {}, ensure_ascii=False, indent=2, default=str).encode("utf-8")
                        zf.writestr(f"{hook_dir}/hook_records_by_correlated_request_id.json", hook_by_corr_bytes)

                        files.extend(
                            [
                                {"path": f"{hook_dir}/hook_session.json", "size": len(hook_session_bytes), "sha256": _sha256_bytes(hook_session_bytes), "generated": True},
                                {"path": f"{hook_dir}/hook_records.json", "size": len(hook_records_bytes), "sha256": _sha256_bytes(hook_records_bytes), "generated": True},
                                {"path": f"{hook_dir}/hook_records_by_correlated_request_id.json", "size": len(hook_by_corr_bytes), "sha256": _sha256_bytes(hook_by_corr_bytes), "generated": True},
                            ]
                        )

                # Add proxy artifacts (external store)
                if include_proxy_artifacts and proxy_artifacts:
                    from backend.proxy.artifacts import ProxyArtifactStore

                    proxy_store = ProxyArtifactStore()
                    for art in proxy_artifacts:
                        aid = str(art.get("artifact_id") or "")
                        if not aid:
                            continue
                        try:
                            src_path = proxy_store.resolve_artifact_path(aid)
                        except Exception:
                            continue
                        if not src_path.exists() or not src_path.is_file():
                            continue
                        arcname = f"{root_prefix}/artifacts/proxy/{aid}"
                        zf.write(src_path, arcname=arcname)
                        try:
                            files.append({"path": arcname, "size": int(src_path.stat().st_size), "sha256": _sha256_file(src_path), "generated": False})
                        except Exception:
                            pass

                # Add hook artifacts (raw buffers)
                if hook_artifacts:
                    from backend.app.services.hook_artifacts import HookArtifactStore

                    hook_store = HookArtifactStore()
                    for art in hook_artifacts:
                        aid = str(art.get("artifact_id") or "")
                        if not aid:
                            continue
                        try:
                            src_path = hook_store.resolve_artifact_path(aid)
                        except Exception:
                            continue
                        if not src_path.exists() or not src_path.is_file():
                            continue
                        arcname = f"{root_prefix}/artifacts/hook/{aid}"
                        try:
                            zf.write(src_path, arcname=arcname)
                        except Exception:
                            continue
                        try:
                            files.append({"path": arcname, "size": int(src_path.stat().st_size), "sha256": _sha256_file(src_path), "generated": False})
                        except Exception:
                            pass

                # Build summary/manifest with final file list
                _manifest0, summary_md = self._build_manifest_and_summary(
                    root_prefix=root_prefix,
                    analysis_session_id=safe_analysis_id,
                    sources=sources,
                    proxy_artifacts=proxy_artifacts,
                    hook_artifacts=hook_artifacts,
                    index=index,
                    files=list(files),
                )
                summary_bytes = (summary_md or "").encode("utf-8")
                files.append({"path": f"{root_prefix}/bundle_summary.md", "size": len(summary_bytes), "sha256": _sha256_bytes(summary_bytes), "generated": True})

                # Build manifest (include summary + manifest itself in files list; best-effort stable size)
                manifest_entry: Dict[str, Any] = {"path": f"{root_prefix}/bundle_manifest.json", "size": 0, "generated": True}
                files_for_manifest = list(files) + [manifest_entry]
                manifest: Dict[str, Any] = {}
                manifest_bytes = b""
                for _i in range(3):
                    manifest, _summary_md2 = self._build_manifest_and_summary(
                        root_prefix=root_prefix,
                        analysis_session_id=safe_analysis_id,
                        sources=sources,
                        proxy_artifacts=proxy_artifacts,
                        hook_artifacts=hook_artifacts,
                        index=index,
                        files=list(files_for_manifest),
                    )
                    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, default=str).encode("utf-8")
                    new_size = len(manifest_bytes)
                    if int(manifest_entry.get("size") or 0) == new_size:
                        break
                    manifest_entry["size"] = new_size

                # Write metadata files last (so manifest includes full file list)
                zf.writestr(f"{root_prefix}/index.json", index_bytes)
                zf.writestr(f"{root_prefix}/session_mapping.json", mapping_bytes)
                zf.writestr(f"{root_prefix}/bundle_summary.md", summary_bytes)
                zf.writestr(f"{root_prefix}/bundle_manifest.json", manifest_bytes)
        except Exception:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            raise

        return tmp_path

    # ------------------------
    # Collect sources
    # ------------------------

    def _collect_proxy_source(self, root_prefix: str, session_id: str) -> BundleSource:
        session_dir = (Path(settings.data_dir) / "sessions" / str(session_id)).resolve()
        meta_path = session_dir / "proxy_meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"proxy_session_not_found: {session_id}")

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8") or "{}")
        except Exception:
            meta = {}

        stats: Dict[str, Any] = {"meta": meta}
        # Load merged requests for summary/index if present
        merged_path = session_dir / "proxy_requests.json"
        requests: List[Dict[str, Any]] = []
        if merged_path.exists():
            try:
                obj = json.loads(merged_path.read_text(encoding="utf-8") or "[]")
                if isinstance(obj, list):
                    requests = [r for r in obj if isinstance(r, dict)]
            except Exception:
                requests = []

        domain_counter: Dict[str, int] = {}
        api_counter: Dict[str, int] = {}
        for r in requests:
            d = _extract_domain(r.get("url") or "")
            if d:
                domain_counter[d] = domain_counter.get(d, 0) + 1
            p = _extract_path(r.get("url") or "")
            if p:
                api_counter[p] = api_counter.get(p, 0) + 1

        # Errors (proxy_errors.jsonl)
        error_counter: Dict[str, int] = {}
        errors_path = session_dir / "proxy_errors.jsonl"
        if errors_path.exists():
            for line in errors_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                et = str(obj.get("type") or obj.get("error", {}).get("type") or "unknown")
                error_counter[et] = error_counter.get(et, 0) + 1

        # WS Top (proxy_ws_connections.json preferred; fallback to ws_start events)
        ws_counter: Dict[str, int] = {}
        conns_path = session_dir / "proxy_ws_connections.json"
        if conns_path.exists():
            try:
                conns_obj = json.loads(conns_path.read_text(encoding="utf-8") or "[]")
            except Exception:
                conns_obj = []
            if isinstance(conns_obj, list):
                for c in conns_obj:
                    if not isinstance(c, dict):
                        continue
                    url = str(c.get("url") or "")
                    if not url:
                        continue
                    mc = int(c.get("message_count") or 0)
                    ws_counter[url] = ws_counter.get(url, 0) + (mc if mc > 0 else 1)
        if not ws_counter:
            ws_events_path = session_dir / "proxy_ws_events.jsonl"
            if ws_events_path.exists():
                for line in ws_events_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("event") or "") != "ws_start":
                        continue
                    url = str(obj.get("url") or "")
                    if url:
                        ws_counter[url] = ws_counter.get(url, 0) + 1

        # App-layer encryption suspect ratio (reuse diagnostics helper if available)
        payload_hint: Dict[str, Any] = {}
        try:
            from backend.proxy.diagnostics import analyze_app_layer_encryption_suspect

            payload_hint = analyze_app_layer_encryption_suspect(recent_requests=requests[-80:])
        except Exception:
            payload_hint = {}

        stats.update(
            {
                "counts": {
                    "requests": int(meta.get("request_count") or len(requests)),
                    "responses": int(meta.get("response_count") or 0),
                    "ws_messages": int(meta.get("ws_message_count") or 0),
                    "js_events": int(meta.get("js_event_count") or 0),
                    "artifacts": int(meta.get("artifact_count") or 0),
                },
                "time_range": {"start": meta.get("started_at"), "end": meta.get("ended_at")},
                "top_domains": _top_n(domain_counter, 12),
                "top_paths": _top_n(api_counter, 12),
                "top_ws": _top_n(ws_counter, 12),
                "error_types": _top_n(error_counter, 10),
                "payload_hint": payload_hint,
            }
        )

        return BundleSource(
            kind="proxy",
            session_id=str(session_id),
            root_in_bundle=f"sources/proxy/{session_id}",
            stats=stats,
        )

    def _collect_crawler_source(self, root_prefix: str, session_id: str) -> BundleSource:
        session_dir = (Path(settings.data_dir) / "sessions" / str(session_id)).resolve()
        if not session_dir.exists() or not session_dir.is_dir():
            raise FileNotFoundError(f"crawler_session_not_found: {session_id}")

        meta_path = session_dir / "metadata.json"
        meta: Dict[str, Any] = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8") or "{}")
            except Exception:
                meta = {}

        requests_path = session_dir / "requests.json"
        requests: List[Dict[str, Any]] = []
        if requests_path.exists():
            try:
                obj = json.loads(requests_path.read_text(encoding="utf-8") or "[]")
                if isinstance(obj, list):
                    requests = [r for r in obj if isinstance(r, dict)]
            except Exception:
                requests = []

        domain_counter: Dict[str, int] = {}
        api_counter: Dict[str, int] = {}
        failure_counter: Dict[str, int] = {}
        failed = 0
        for r in requests:
            d = _extract_domain(r.get("url") or "")
            if d:
                domain_counter[d] = domain_counter.get(d, 0) + 1
            p = _extract_path(r.get("url") or "")
            if p:
                api_counter[p] = api_counter.get(p, 0) + 1
            if r.get("failed") or r.get("failure_text") or r.get("error"):
                failed += 1
                reason = str(r.get("failure_text") or r.get("error") or "").strip()
                if reason:
                    key = reason[:160] + ("…" if len(reason) > 160 else "")
                    failure_counter[key] = failure_counter.get(key, 0) + 1

        stats: Dict[str, Any] = {
            "meta": meta,
            "counts": {
                "requests": int(meta.get("total_requests") or len(requests)),
                "requests_with_call_stack": int(meta.get("requests_with_call_stack") or 0),
                "failed_requests": int(failed),
            },
            "time_range": {"start": meta.get("start_time"), "end": meta.get("end_time")},
            "top_domains": _top_n(domain_counter, 12),
            "top_paths": _top_n(api_counter, 12),
            "failure_reasons": _top_n(failure_counter, 10),
        }

        return BundleSource(
            kind="crawler",
            session_id=str(session_id),
            root_in_bundle=f"sources/crawler/{session_id}",
            stats=stats,
        )

    def _collect_hook_source(self, root_prefix: str, session_id: str) -> BundleSource:
        session = self._hook_storage.get_session(session_id)
        if not session:
            raise FileNotFoundError(f"hook_session_not_found: {session_id}")

        # Export all records (limit large but bounded)
        records, total = self._hook_storage.list_records(session_id=session_id, limit=200000, offset=0)
        by_corr: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            cid = str(r.get("correlated_request_id") or "")
            if not cid:
                continue
            by_corr.setdefault(cid, []).append(
                {
                    "hook_id": r.get("hook_id"),
                    "api_name": r.get("api_name"),
                    "hook_type": r.get("hook_type"),
                    "timestamp": r.get("timestamp"),
                }
            )

        stats: Dict[str, Any] = {
            "counts": {"records": int(total), "records_exported": int(len(records))},
            "time_range": {"start": session.get("started_at"), "end": session.get("ended_at")},
            "hook_export": {"session": session, "records": records, "records_by_correlated_request_id": by_corr},
        }

        return BundleSource(
            kind="native_hook",
            session_id=str(session_id),
            root_in_bundle=f"sources/native_hook/{session_id}",
            stats=stats,
        )

    def _collect_proxy_artifacts(self, proxy_session_id: str) -> List[Dict[str, Any]]:
        session_dir = (Path(settings.data_dir) / "sessions" / str(proxy_session_id)).resolve()
        jsonl = session_dir / "proxy_artifacts.jsonl"
        if not jsonl.exists():
            return []
        artifacts: Dict[str, Dict[str, Any]] = {}
        for line in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            aid = str(obj.get("artifact_id") or "")
            if not aid:
                continue
            artifacts[aid] = obj
        return list(artifacts.values())

    def _collect_hook_artifacts(self, hook_src: BundleSource) -> List[Dict[str, Any]]:
        """从 hook 导出的 records 中提取 raw buffer artifact 引用（best-effort）。"""
        try:
            export = hook_src.stats.get("hook_export") or {}
            records = export.get("records") or []
            out: Dict[str, Dict[str, Any]] = {}
            for r in records:
                if not isinstance(r, dict):
                    continue
                args = r.get("args") or {}
                if not isinstance(args, dict):
                    continue
                art = args.get("_raw_buffer_artifact") or {}
                if not isinstance(art, dict):
                    continue
                aid = str(art.get("artifact_id") or "")
                if not aid:
                    continue
                out[aid] = art
            return list(out.values())
        except Exception:
            return []

    # ------------------------
    # Build metadata files
    # ------------------------

    def _build_mapping(
        self,
        *,
        analysis_session_id: str,
        proxy_session_ids: List[str],
        crawler_session_ids: List[str],
        hook_session_ids: List[str],
    ) -> Dict[str, Any]:
        return {
            "analysis_session_id": analysis_session_id,
            "proxy_session_id": proxy_session_ids,
            "crawler_session_id": crawler_session_ids,
            "hook_session_id": hook_session_ids,
            "js_injection_session_id": [],  # JS 注入与 proxy_session 绑定，事件在 proxy 会话内
        }

    def _build_index(self, *, root_prefix: str, sources: List[BundleSource]) -> Dict[str, Any]:
        idx: Dict[str, Any] = {"generated_at": _utc_now_iso(), "sources": {}}

        for src in sources:
            if src.kind == "proxy":
                proxy_dir = Path(settings.data_dir) / "sessions" / src.session_id
                requests_path = proxy_dir / "proxy_requests.json"
                conns_path = proxy_dir / "proxy_ws_connections.json"
                msgs_path = proxy_dir / "proxy_ws_messages.json"
                js_path = proxy_dir / "proxy_js_events.json"

                reqs = []
                if requests_path.exists():
                    try:
                        reqs = json.loads(requests_path.read_text(encoding="utf-8") or "[]")
                    except Exception:
                        reqs = []
                if not isinstance(reqs, list):
                    reqs = []

                req_index: Dict[str, Any] = {}
                for i, r in enumerate(reqs):
                    if not isinstance(r, dict):
                        continue
                    rid = str(r.get("id") or "")
                    if not rid:
                        continue
                    req_index[rid] = {
                        "i": i,
                        "method": r.get("method"),
                        "url": r.get("url"),
                        "timestamp": r.get("timestamp"),
                        "status_code": r.get("status_code"),
                        "has_body_artifact": bool(r.get("body_artifact")),
                        "has_response_artifact": bool(r.get("response_body_artifact")),
                        "has_error": bool(r.get("error")),
                    }

                conn_index: Dict[str, Any] = {}
                if conns_path.exists():
                    try:
                        conns = json.loads(conns_path.read_text(encoding="utf-8") or "[]")
                    except Exception:
                        conns = []
                    if isinstance(conns, list):
                        for i, c in enumerate(conns):
                            if not isinstance(c, dict):
                                continue
                            cid = str(c.get("id") or "")
                            if cid:
                                conn_index[cid] = {"i": i, "url": c.get("url"), "status": c.get("status"), "message_count": c.get("message_count")}

                msg_index: Dict[str, Any] = {}
                if msgs_path.exists():
                    try:
                        msgs = json.loads(msgs_path.read_text(encoding="utf-8") or "[]")
                    except Exception:
                        msgs = []
                    if isinstance(msgs, list):
                        first_last: Dict[str, Tuple[int, int, int]] = {}
                        for i, m in enumerate(msgs):
                            if not isinstance(m, dict):
                                continue
                            cid = str(m.get("connection_id") or "")
                            if not cid:
                                continue
                            cur = first_last.get(cid)
                            if cur is None:
                                first_last[cid] = (i, i, 1)
                            else:
                                first_last[cid] = (cur[0], i, cur[2] + 1)
                        for cid, (first_i, last_i, count) in first_last.items():
                            msg_index[cid] = {"first_i": first_i, "last_i": last_i, "count": count, "file": f"{root_prefix}/sources/proxy/{src.session_id}/proxy_ws_messages.json"}

                js_by_request: Dict[str, List[Dict[str, Any]]] = {}
                if js_path.exists():
                    try:
                        js_events = json.loads(js_path.read_text(encoding="utf-8") or "[]")
                    except Exception:
                        js_events = []
                    if isinstance(js_events, list):
                        for e in js_events:
                            if not isinstance(e, dict):
                                continue
                            cid = str(e.get("correlated_request_id") or "")
                            if not cid:
                                continue
                            js_by_request.setdefault(cid, []).append(
                                {
                                    "id": e.get("id"),
                                    "event_type": e.get("event_type"),
                                    "timestamp": e.get("timestamp"),
                                    "url": e.get("url"),
                                    "method": e.get("method"),
                                }
                            )

                idx["sources"].setdefault("proxy", []).append(
                    {
                        "session_id": src.session_id,
                        "root": f"{root_prefix}/sources/proxy/{src.session_id}",
                        "requests_file": f"{root_prefix}/sources/proxy/{src.session_id}/proxy_requests.json",
                        "requests_index": req_index,
                        "ws_connections_file": f"{root_prefix}/sources/proxy/{src.session_id}/proxy_ws_connections.json",
                        "ws_connections_index": conn_index,
                        "ws_messages_file": f"{root_prefix}/sources/proxy/{src.session_id}/proxy_ws_messages.json",
                        "ws_messages_index": msg_index,
                        "js_events_file": f"{root_prefix}/sources/proxy/{src.session_id}/proxy_js_events.json",
                        "js_events_by_request_id": js_by_request,
                    }
                )

            if src.kind == "crawler":
                crawler_dir = Path(settings.data_dir) / "sessions" / src.session_id
                requests_path = crawler_dir / "requests.json"
                reqs = []
                if requests_path.exists():
                    try:
                        reqs = json.loads(requests_path.read_text(encoding="utf-8") or "[]")
                    except Exception:
                        reqs = []
                if not isinstance(reqs, list):
                    reqs = []
                req_index = {}
                for i, r in enumerate(reqs):
                    if not isinstance(r, dict):
                        continue
                    rid = str(r.get("id") or "")
                    if not rid:
                        continue
                    req_index[rid] = {
                        "i": i,
                        "method": r.get("method"),
                        "url": r.get("url"),
                        "timestamp": r.get("timestamp"),
                        "status": r.get("status"),
                        "resource_type": r.get("resource_type"),
                        "has_call_stack": bool(r.get("call_stack")),
                        "has_response_body": bool(r.get("response_body_path")),
                        "has_request_body_artifact": bool(r.get("request_body_artifact")),
                        "failed": bool(r.get("failed") or r.get("failure_text") or r.get("error")),
                    }
                idx["sources"].setdefault("crawler", []).append(
                    {
                        "session_id": src.session_id,
                        "root": f"{root_prefix}/sources/crawler/{src.session_id}",
                        "requests_file": f"{root_prefix}/sources/crawler/{src.session_id}/requests.json",
                        "requests_index": req_index,
                        "metadata_file": f"{root_prefix}/sources/crawler/{src.session_id}/metadata.json",
                        "har_file": f"{root_prefix}/sources/crawler/{src.session_id}/trace.har",
                    }
                )

            if src.kind == "native_hook":
                export = src.stats.get("hook_export") or {}
                idx["sources"].setdefault("native_hook", []).append(
                    {
                        "session_id": src.session_id,
                        "root": f"{root_prefix}/sources/native_hook/{src.session_id}",
                        "hook_session_file": f"{root_prefix}/sources/native_hook/{src.session_id}/hook_session.json",
                        "hook_records_file": f"{root_prefix}/sources/native_hook/{src.session_id}/hook_records.json",
                        "records_by_correlated_request_id_file": f"{root_prefix}/sources/native_hook/{src.session_id}/hook_records_by_correlated_request_id.json",
                        "records_count": len(export.get("records") or []),
                    }
                )

        return idx

    def _build_manifest_and_summary(
        self,
        *,
        root_prefix: str,
        analysis_session_id: str,
        sources: List[BundleSource],
        proxy_artifacts: List[Dict[str, Any]],
        hook_artifacts: List[Dict[str, Any]],
        index: Dict[str, Any],
        files: List[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], str]:
        # Time range merge
        start_candidates: List[str] = []
        end_candidates: List[str] = []
        counts: Dict[str, int] = {
            "proxy_requests": 0,
            "crawler_requests": 0,
            "crawler_failed_requests": 0,
            "hook_records": 0,
            "ws_messages": 0,
            "js_events": 0,
            "artifacts_proxy": 0,
            "artifacts_hook": 0,
        }

        top_domains: Dict[str, int] = {}
        top_paths: Dict[str, int] = {}
        top_ws: Dict[str, int] = {}
        proxy_error_types: Dict[str, int] = {}
        crawler_failure_reasons: Dict[str, int] = {}

        proxy_payload_hint: Optional[Dict[str, Any]] = None

        for src in sources:
            tr = src.stats.get("time_range") or {}
            if tr.get("start"):
                start_candidates.append(str(tr.get("start")))
            if tr.get("end"):
                end_candidates.append(str(tr.get("end")))

            if src.kind == "proxy":
                c = src.stats.get("counts") or {}
                counts["proxy_requests"] += int(c.get("requests") or 0)
                counts["ws_messages"] += int(c.get("ws_messages") or 0)
                counts["js_events"] += int(c.get("js_events") or 0)
                if proxy_payload_hint is None and isinstance(src.stats.get("payload_hint"), dict):
                    proxy_payload_hint = src.stats.get("payload_hint")
            if src.kind == "crawler":
                c = src.stats.get("counts") or {}
                counts["crawler_requests"] += int(c.get("requests") or 0)
                counts["crawler_failed_requests"] += int(c.get("failed_requests") or 0)
            if src.kind == "native_hook":
                c = src.stats.get("counts") or {}
                counts["hook_records"] += int(c.get("records") or 0)

            for item in (src.stats.get("top_domains") or []):
                try:
                    k = str(item.get("key") or "")
                    v = int(item.get("count") or 0)
                    if k:
                        top_domains[k] = top_domains.get(k, 0) + v
                except Exception:
                    continue
            for item in (src.stats.get("top_paths") or []):
                try:
                    k = str(item.get("key") or "")
                    v = int(item.get("count") or 0)
                    if k:
                        top_paths[k] = top_paths.get(k, 0) + v
                except Exception:
                    continue
            for item in (src.stats.get("top_ws") or []):
                try:
                    k = str(item.get("key") or "")
                    v = int(item.get("count") or 0)
                    if k:
                        top_ws[k] = top_ws.get(k, 0) + v
                except Exception:
                    continue

            # failure reason aggregates
            for item in (src.stats.get("error_types") or []):
                try:
                    k = str(item.get("key") or "")
                    v = int(item.get("count") or 0)
                    if k:
                        proxy_error_types[k] = proxy_error_types.get(k, 0) + v
                except Exception:
                    continue
            for item in (src.stats.get("failure_reasons") or []):
                try:
                    k = str(item.get("key") or "")
                    v = int(item.get("count") or 0)
                    if k:
                        crawler_failure_reasons[k] = crawler_failure_reasons.get(k, 0) + v
                except Exception:
                    continue

        # proxy artifacts
        counts["artifacts_proxy"] = len({str(a.get("artifact_id") or "") for a in proxy_artifacts if isinstance(a, dict)})
        counts["artifacts_hook"] = len({str(a.get("artifact_id") or "") for a in hook_artifacts if isinstance(a, dict)})

        manifest: Dict[str, Any] = {
            "analysis_session_id": analysis_session_id,
            "generated_at": _utc_now_iso(),
            "directory_structure": {
                "root": "analysis_bundle/<analysis_session_id>/",
                "meta_files": ["bundle_manifest.json", "bundle_summary.md", "index.json", "session_mapping.json"],
                "sources": {
                    "proxy": "sources/proxy/<proxy_session_id>/",
                    "crawler": "sources/crawler/<crawler_session_id>/",
                    "native_hook": "sources/native_hook/<hook_session_id>/",
                },
                "artifacts": {"proxy": "artifacts/proxy/<artifact_id>", "hook": "artifacts/hook/<artifact_id>"},
            },
            "sources": [{"kind": s.kind, "session_id": s.session_id, "root": f"{root_prefix}/{s.root_in_bundle}"} for s in sources],
            "time_range": {"start": min(start_candidates) if start_candidates else None, "end": max(end_candidates) if end_candidates else None},
            "counts": counts,
            "top": {"domains": _top_n(top_domains, 20), "paths": _top_n(top_paths, 20), "ws": _top_n(top_ws, 20)},
            "failures": {"proxy_error_types": _top_n(proxy_error_types, 20), "crawler_failure_reasons": _top_n(crawler_failure_reasons, 20)},
            "proxy_artifacts": proxy_artifacts,
            "hook_artifacts": hook_artifacts,
            "payload_hint": proxy_payload_hint or {},
            "files": files,
        }

        # Summary markdown
        lines: List[str] = []
        lines.append(f"# AI 分析包摘要：{analysis_session_id}")
        lines.append("")
        lines.append(f"- 生成时间(UTC)：`{manifest['generated_at']}`")
        lines.append(f"- 时间范围：`{manifest['time_range'].get('start')}` ~ `{manifest['time_range'].get('end')}`")
        sources_text = ", ".join([f"{s.kind}:{s.session_id}" for s in sources]) or "(none)"
        lines.append(f"- Sources：{sources_text}")
        lines.append("")
        lines.append("## 核心计数")
        lines.append("")
        for k in ["proxy_requests", "crawler_requests", "crawler_failed_requests", "ws_messages", "js_events", "hook_records", "artifacts_proxy"]:
            lines.append(f"- {k}: {counts.get(k, 0)}")
        lines.append(f"- artifacts_hook: {counts.get('artifacts_hook', 0)}")
        lines.append("")
        lines.append("## Top Domains")
        lines.append("")
        for item in manifest["top"]["domains"][:12]:
            lines.append(f"- {item['key']}: {item['count']}")
        lines.append("")
        lines.append("## Top Paths")
        lines.append("")
        for item in manifest["top"]["paths"][:12]:
            lines.append(f"- {item['key']}: {item['count']}")
        lines.append("")
        lines.append("## WS Top")
        lines.append("")
        ws_items = (manifest.get("top") or {}).get("ws") or []
        if ws_items:
            for item in ws_items[:12]:
                lines.append(f"- {item['key']}: {item['count']}")
        else:
            lines.append("- (no data)")
        lines.append("")
        lines.append("## 失败原因统计（best-effort）")
        lines.append("")
        pe = (manifest.get("failures") or {}).get("proxy_error_types") or []
        if pe:
            lines.append("- proxy error types:")
            for item in pe[:10]:
                lines.append(f"  - {item['key']}: {item['count']}")
        cf = (manifest.get("failures") or {}).get("crawler_failure_reasons") or []
        if cf:
            lines.append("- crawler failure reasons:")
            for item in cf[:10]:
                lines.append(f"  - {item['key']}: {item['count']}")
        if not pe and not cf:
            lines.append("- (no data)")
        lines.append("")
        lines.append("## 应用层加密/不可读 payload（best-effort）")
        lines.append("")
        ph = proxy_payload_hint or {}
        if ph:
            lines.append(f"- suspect/total: {ph.get('suspect')}/{ph.get('total')} (ratio={ph.get('ratio')})")
            ex = ph.get("examples") or []
            if ex:
                lines.append("- examples:")
                for e in ex:
                    lines.append(f"  - {e.get('method')} {e.get('url')} (ct={e.get('content_type')})")
        else:
            lines.append("- (no data)")
        lines.append("")
        lines.append("## 入口文件")
        lines.append("")
        lines.append(f"- `index.json`: 机器可读索引（按 request_id/connection_id/关联ID 定位）")
        lines.append(f"- `bundle_manifest.json`: 全量元信息（来源/计数/时间范围/产物引用）")
        lines.append("")

        return manifest, "\n".join(lines) + "\n"

    # ------------------------
    # Zip helpers
    # ------------------------

    def _zip_add_tree(
        self,
        zf: zipfile.ZipFile,
        root: Path,
        arc_root: str,
        *,
        file_entries: Optional[List[Dict[str, Any]]] = None,
        sha256_max_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        root = Path(root)
        if not root.exists() or not root.is_dir():
            return
        for cur_root, _dirs, filenames in os.walk(root):
            cur = Path(cur_root)
            rel_root = cur.relative_to(root)
            for fn in filenames:
                p = cur / fn
                if not p.is_file():
                    continue
                arcname = f"{arc_root}/{_safe_relpath(rel_root / fn)}"
                zf.write(p, arcname=arcname)
                if file_entries is not None:
                    try:
                        st = p.stat()
                        entry: Dict[str, Any] = {"path": arcname, "size": int(st.st_size), "generated": False}
                        if sha256_max_bytes and int(st.st_size) <= int(sha256_max_bytes):
                            entry["sha256"] = _sha256_file(p)
                        file_entries.append(entry)
                    except Exception:
                        pass
