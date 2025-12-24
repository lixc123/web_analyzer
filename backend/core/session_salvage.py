"""
Session salvage utilities.

Best-effort re-download of recorded resources for an existing session directory.
This is useful when a session has requests.json but resource folders are empty
(e.g. archiver was not attached during recording).

Notes:
- This module intentionally prefers robustness over strict fidelity.
- It will skip data:/blob: URLs.

"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Ensure backend root is importable (so `import core` / `import models` works)
_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from models.request_record import RequestRecord
from core.resource_archiver import ResourceArchiver


def salvage_session(
    session_dir: Path,
    *,
    timeout_seconds: int = 25,
    max_body_bytes: Optional[int] = None,
    overwrite_existing: bool = False,
    only_resource_types: Optional[List[str]] = None,
    log_callback=None,
) -> Dict[str, Any]:
    """Best-effort salvage for an existing session directory.

    It will:
    - Load session_dir/requests.json
    - For each request, try to re-request the URL and save response body
      into responses/scripts/styles/images based on inferred content type
    - Update requests.json with response_body_path/content_type/status/headers/size
    - Generate metadata.json / trace.har and replay_session.py

    Args:
        session_dir: Existing session folder (data/sessions/session_xxx).
        timeout_seconds: HTTP timeout for each request.
        max_body_bytes: If set, cap downloaded bytes (None means no cap).
        overwrite_existing: If True, re-download even if file exists.
        only_resource_types: If set, salvage only these resource_type values.
        log_callback: Optional callable(str)

    Returns:
        Stats dict.
    """

    log = log_callback or (lambda _msg: None)

    session_dir = Path(session_dir)
    if not session_dir.exists() or not session_dir.is_dir():
        raise FileNotFoundError(f"Session dir not found: {session_dir}")

    requests_path = session_dir / "requests.json"
    if not requests_path.exists():
        raise FileNotFoundError(f"requests.json not found: {requests_path}")

    # Make sure dirs exist (and reuse the same session dir name)
    archiver = ResourceArchiver(
        base_output_dir=session_dir.parent,
        session_id=session_dir.name,
        log_callback=log,
    )

    raw_items: List[Dict[str, Any]]
    with open(requests_path, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    # Normalize into RequestRecord list
    records: List[RequestRecord] = [RequestRecord.from_dict(it) for it in raw_items]

    sess = requests.Session()

    attempted = 0
    downloaded = 0
    skipped = 0
    failed = 0
    bytes_saved = 0

    for rec in records:
        if only_resource_types and (rec.resource_type or "") not in set(only_resource_types):
            skipped += 1
            continue

        url = rec.url or ""
        if not url or url.startswith("data:") or url.startswith("blob:"):
            skipped += 1
            continue

        # If already has response_body_path and file exists, skip by default
        if rec.response_body_path and not overwrite_existing:
            target = session_dir / rec.response_body_path
            if target.exists() and target.is_file() and target.stat().st_size > 0:
                skipped += 1
                continue

        attempted += 1

        method = (rec.method or "GET").upper()
        headers = dict(rec.headers or {})

        data = None
        json_data = None
        if rec.post_data and method in {"POST", "PUT", "PATCH"}:
            # Try JSON first
            try:
                json_data = json.loads(rec.post_data)
            except Exception:
                data = rec.post_data

        try:
            resp = sess.request(
                method=method,
                url=url,
                headers=headers if headers else None,
                data=data,
                json=json_data,
                timeout=timeout_seconds,
            )

            rec.status = resp.status_code
            rec.response_headers = dict(resp.headers)
            rec.response_timestamp = time.time()

            content = resp.content
            if max_body_bytes is not None and len(content) > max_body_bytes:
                content = content[:max_body_bytes]

            rec.response_size = len(content)

            # Save body and update path
            rel_path = archiver.save_response(rec, content)
            rec.response_body_path = rel_path

            downloaded += 1
            bytes_saved += len(content)

        except Exception as e:
            failed += 1
            log(f"salvage failed: {method} {url[:120]}... - {e}")

    # Persist updated requests.json + metadata/har
    try:
        archiver.save_requests(records)
        archiver.save_metadata(records)
        archiver.save_har(records)
    except Exception as e:
        log(f"finalize export failed: {e}")

    # Generate replay code
    try:
        from core.code_generator import generate_code_from_session

        replay_code = generate_code_from_session(session_dir)
        replay_path = session_dir / "replay_session.py"
        with open(replay_path, "w", encoding="utf-8") as f:
            f.write(replay_code)
    except Exception as e:
        log(f"generate replay code failed: {e}")

    return {
        "session": session_dir.name,
        "attempted": attempted,
        "downloaded": downloaded,
        "skipped": skipped,
        "failed": failed,
        "bytes_saved": bytes_saved,
        "max_body_bytes": max_body_bytes,
        "overwrite_existing": overwrite_existing,
    }

