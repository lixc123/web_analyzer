import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.request_record import RequestRecord


def _format_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def export_har(records: List[RequestRecord], output_path: Path) -> None:
    """将 RequestRecord 列表导出为一个简单的 HAR 文件。

    HAR 结构做了简化，只保留核心字段，方便在 Chrome DevTools 中查看。
    """
    entries = []

    for r in records:
        started = _format_iso(r.timestamp)

        if r.response_timestamp is not None:
            total_time_ms = int((r.response_timestamp - r.timestamp) * 1000)
        else:
            total_time_ms = 0
        request_headers = [
            {"name": k, "value": v}
            for k, v in (r.headers or {}).items()
        ]
        response_headers = [
            {"name": k, "value": v}
            for k, v in (r.response_headers or {}).items()
        ]

        mime_type = r.content_type or ""

        entry = {
            "startedDateTime": started,
            "time": total_time_ms,
            "request": {
                "method": r.method,
                "url": r.url,
                "httpVersion": "HTTP/1.1",
                "headers": request_headers,
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(r.post_data or "") if r.post_data else 0,
                "postData": {
                    "mimeType": "application/json",
                    "text": r.post_data or "",
                }
                if r.post_data
                else None,
            },
            "response": {
                "status": r.status or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": response_headers,
                "cookies": [],
                "content": {
                    "size": r.response_size or 0,
                    "mimeType": mime_type,
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": r.response_size or 0,
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": total_time_ms,
                "receive": 0,
            },
        }
        entries.append(entry)

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "WebRecorder", "version": "1.0"},
            "entries": entries,
        }
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(har, f, ensure_ascii=False, indent=2)
