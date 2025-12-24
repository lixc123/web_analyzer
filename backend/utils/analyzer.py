"""请求分析工具"""
from dataclasses import dataclass
from typing import List, Optional
from models.request_record import RequestRecord


# 敏感参数关键词列表
SENSITIVE_PARAMS = [
    "auth",
    "token",
    "sign",
    "signature",
    "key",
    "secret",
    "password",
    "pwd",
    "credential",
    "session",
    "cookie",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
]

CRYPTO_KEYWORDS = [
    "cryptojs",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "aes",
    "des",
    "rsa",
    "jsencrypt",
    "sm2",
    "sm3",
    "sm4",
]


@dataclass
class FieldInfo:
    """高熵字段信息，供签名/令牌分析使用。"""

    name: str
    location: str  # query/body/header
    entropy: float
    length: int
    is_suspicious: bool
    value_preview: str
    charset: Optional[str] = None  # hex/base64/other


def find_sensitive_requests(records: List[RequestRecord]) -> List[RequestRecord]:
    """查找包含敏感参数的请求。
    
    Args:
        records: 请求记录列表
        
    Returns:
        包含敏感参数的请求列表
    """
    results = []
    for req in records:
        if _has_sensitive_param(req):
            results.append(req)
    return results


def _shannon_entropy(text: str) -> float:
    import math

    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_encoded_token(value: str) -> bool:
    if not value or len(value) < 16:
        return False
    hex_chars = set("0123456789abcdefABCDEF")
    if all(c in hex_chars for c in value):
        return True

    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if all(c in base64_chars for c in value):
        return True

    entropy = _shannon_entropy(value)
    return entropy >= 3.5


def parse_hooks_console_lines(lines: List[str]) -> dict:
    """解析 hooks/console.log，建立 URL 到调用栈的映射表。

    期望的行格式：
    - "[FETCH_HOOK] {json}"
    - "[XHR_HOOK] {json}"
    其中 json 至少包含 `url` 和 `stack` 字段。
    """

    import json as _json

    mapping: dict = {}
    for line in lines:
        text = line.strip()
        if not text:
            continue

        if text.startswith("[FETCH_HOOK] "):
            json_str = text[len("[FETCH_HOOK] ") :]
        elif text.startswith("[XHR_HOOK] "):
            json_str = text[len("[XHR_HOOK] ") :]
        else:
            continue

        try:
            obj = _json.loads(json_str)
        except Exception:
            continue

        url = obj.get("url")
        stack = obj.get("stack")
        if not url or not stack:
            continue

        # 直接映射完整 URL；如需更复杂匹配可在调用方处理
        mapping[url] = stack

    return mapping


def _detect_charset(value: str) -> Optional[str]:
    """简单检测字符串的字符集类型。"""

    if not value:
        return None

    hex_chars = set("0123456789abcdefABCDEF")
    if all(c in hex_chars for c in value):
        return "hex"

    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if all(c in base64_chars for c in value):
        return "base64"

    return None


def scan_crypto_keywords_in_scripts(scripts_dir: "Optional[Path]") -> dict:
    if scripts_dir is None:
        return {}
    try:
        from pathlib import Path as _Path

        base = _Path(scripts_dir)
    except Exception:
        return {}

    if not base.exists() or not base.is_dir():
        return {}

    results: dict = {}
    for js_path in base.glob("*.js"):
        try:
            with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
        except Exception:
            continue

        hits = [kw for kw in CRYPTO_KEYWORDS if kw in content]
        if hits:
            results[js_path.name] = hits
    return results


def find_crypto_suspected_requests(
    records: List[RequestRecord],
    scripts_dir: "Optional[Path]" = None,
) -> List[RequestRecord]:
    from urllib.parse import parse_qsl, urlparse

    js_hits = scan_crypto_keywords_in_scripts(scripts_dir)
    js_files_with_hits = set(js_hits.keys())

    suspicious: List[RequestRecord] = []

    for r in records:
        flagged = False

        parsed = urlparse(r.url)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            v = value.strip()
            if not v:
                continue
            key_lower = (name or "").lower()
            if any(kw in key_lower for kw in CRYPTO_KEYWORDS):
                flagged = True
                break
            if _looks_like_encoded_token(v):
                flagged = True
                break

        if not flagged and r.post_data:
            body_text = r.post_data.strip()
            if _looks_like_encoded_token(body_text):
                flagged = True
            else:
                try:
                    import json as _json

                    obj = _json.loads(body_text)
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if not isinstance(v, str):
                                continue
                            key_lower = (k or "").lower()
                            if any(kw in key_lower for kw in CRYPTO_KEYWORDS):
                                flagged = True
                                break
                            if _looks_like_encoded_token(v):
                                flagged = True
                                break
                        if not flagged:
                            pass
                except Exception:
                    pass

        if not flagged and r.headers:
            for key, value in r.headers.items():
                key_lower = key.lower()
                if any(kw in key_lower for kw in CRYPTO_KEYWORDS):
                    flagged = True
                    break

        if not flagged and r.call_stack:
            stack_lower = r.call_stack.lower()
            if any(kw in stack_lower for kw in CRYPTO_KEYWORDS):
                flagged = True
            elif js_files_with_hits:
                for fname in js_files_with_hits:
                    if fname.lower() in stack_lower:
                        flagged = True
                        break

        if flagged:
            suspicious.append(r)

    return suspicious


def detect_high_entropy_fields(request: RequestRecord) -> List[FieldInfo]:
    """检测请求中的高熵字段（疑似签名/令牌）。

    结合熵值、字符集类型和 `_looks_like_encoded_token` 进行粗略判断。
    """

    from urllib.parse import parse_qsl, urlparse

    results: List[FieldInfo] = []

    # 查询参数
    try:
        parsed = urlparse(request.url)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if not value:
                continue
            entropy = _shannon_entropy(value)
            charset = _detect_charset(value)
            length = len(value)
            is_suspicious = _looks_like_encoded_token(value) or entropy >= 3.5
            if not is_suspicious:
                continue
            results.append(
                FieldInfo(
                    name=name or "query_param",
                    location="query",
                    entropy=entropy,
                    length=length,
                    is_suspicious=True,
                    value_preview=value[:80],
                    charset=charset,
                )
            )
    except Exception:
        pass

    # Body
    if request.post_data:
        body_text = request.post_data.strip()
        try:
            import json as _json

            obj = _json.loads(body_text)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if not isinstance(v, str) or not v:
                        continue
                    entropy = _shannon_entropy(v)
                    charset = _detect_charset(v)
                    length = len(v)
                    is_suspicious = _looks_like_encoded_token(v) or entropy >= 3.5
                    if not is_suspicious:
                        continue
                    results.append(
                        FieldInfo(
                            name=k or "body_field",
                            location="body",
                            entropy=entropy,
                            length=length,
                            is_suspicious=True,
                            value_preview=v[:80],
                            charset=charset,
                        )
                    )
        except Exception:
            # 非 JSON 情况：整体作为一个字段检查
            entropy = _shannon_entropy(body_text)
            charset = _detect_charset(body_text)
            length = len(body_text)
            is_suspicious = _looks_like_encoded_token(body_text) or entropy >= 3.5
            if is_suspicious:
                results.append(
                    FieldInfo(
                        name="body",
                        location="body",
                        entropy=entropy,
                        length=length,
                        is_suspicious=True,
                        value_preview=body_text[:80],
                        charset=charset,
                    )
                )

    # Headers
    if request.headers:
        for key, value in request.headers.items():
            if not value:
                continue
            entropy = _shannon_entropy(value)
            charset = _detect_charset(value)
            length = len(value)
            is_suspicious = _looks_like_encoded_token(value) or entropy >= 3.5
            if not is_suspicious:
                continue
            results.append(
                FieldInfo(
                    name=key,
                    location="header",
                    entropy=entropy,
                    length=length,
                    is_suspicious=True,
                    value_preview=value[:80],
                    charset=charset,
                )
            )

    return results


def _has_sensitive_param(req: RequestRecord) -> bool:
    """检查请求是否包含敏感参数。"""
    # 检查 URL
    url_lower = req.url.lower()
    for param in SENSITIVE_PARAMS:
        if param in url_lower:
            return True
    
    # 检查 POST 数据
    if req.post_data:
        post_lower = req.post_data.lower()
        for param in SENSITIVE_PARAMS:
            if param in post_lower:
                return True
    
    # 检查请求头
    if req.headers:
        for key, value in req.headers.items():
            key_lower = key.lower()
            for param in SENSITIVE_PARAMS:
                if param in key_lower:
                    return True
    
    return False


def find_requests_with_call_stack(records: List[RequestRecord]) -> List[RequestRecord]:
    """查找有调用栈信息的请求（便于逆向分析）。
    
    Args:
        records: 请求记录列表
        
    Returns:
        有调用栈的请求列表
    """
    return [r for r in records if r.call_stack]


def find_api_requests(records: List[RequestRecord]) -> List[RequestRecord]:
    """查找 API 请求（XHR/Fetch）。
    
    Args:
        records: 请求记录列表
        
    Returns:
        API 请求列表
    """
    api_types = {"xhr", "fetch"}
    return [r for r in records if r.resource_type and r.resource_type.lower() in api_types]


def summarize_requests(records: List[RequestRecord]) -> dict:
    """生成请求摘要报告。
    
    Args:
        records: 请求记录列表
        
    Returns:
        摘要字典
    """
    sensitive = find_sensitive_requests(records)
    with_stack = find_requests_with_call_stack(records)
    api_reqs = find_api_requests(records)
    
    return {
        "total": len(records),
        "sensitive_count": len(sensitive),
        "with_call_stack": len(with_stack),
        "api_requests": len(api_reqs),
        "sensitive_urls": [r.url for r in sensitive[:10]],  # 最多显示 10 条
    }


def _normalize_url_for_diff(url: str) -> str:
    from urllib.parse import parse_qsl, urlparse

    parsed = urlparse(url)
    path = parsed.path or "/"

    params = parse_qsl(parsed.query, keep_blank_values=True)
    names = sorted({name for name, _ in params})

    base = f"{parsed.scheme}://{parsed.netloc}{path}" if parsed.netloc else path
    if names:
        query_part = "&".join(names)
        return f"{base}?{query_part}"
    return base


def _group_by_method_and_url(records: List[RequestRecord]) -> dict:
    groups = {}
    for r in records:
        method = (r.method or "").upper()
        norm_url = _normalize_url_for_diff(r.url)
        key = f"{method} {norm_url}"
        groups.setdefault(key, []).append(r)
    return groups


def _summarize_group(records: List[RequestRecord]) -> dict:
    from urllib.parse import parse_qsl, urlparse

    statuses = set()
    param_names = set()
    body_samples = set()

    for r in records:
        if r.status is not None:
            statuses.add(r.status)

        parsed = urlparse(r.url)
        for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
            param_names.add(name)

        if r.post_data:
            body_samples.add(r.post_data[:200])

    return {
        "statuses": statuses,
        "param_names": param_names,
        "body_samples": body_samples,
    }


def _groups_equal(left: List[RequestRecord], right: List[RequestRecord]) -> bool:
    left_summary = _summarize_group(left)
    right_summary = _summarize_group(right)
    return left_summary == right_summary


def diff_sessions(left_records: List[RequestRecord], right_records: List[RequestRecord]) -> List[dict]:
    """对比两次录制的请求列表，按 method + 标准化 URL 聚合。"""
    left_map = _group_by_method_and_url(left_records)
    right_map = _group_by_method_and_url(right_records)

    all_keys = set(left_map.keys()) | set(right_map.keys())
    results: List[dict] = []

    for key in sorted(all_keys):
        left_group = left_map.get(key)
        right_group = right_map.get(key)

        try:
            method, norm_url = key.split(" ", 1)
        except ValueError:
            method, norm_url = "", key

        if left_group is None:
            change_type = "added"
        elif right_group is None:
            change_type = "removed"
        else:
            if _groups_equal(left_group, right_group):
                change_type = "unchanged"
            else:
                change_type = "changed"

        results.append(
            {
                "key": key,
                "method": method,
                "normalized_url": norm_url,
                "change_type": change_type,
                "left_count": len(left_group) if left_group else 0,
                "right_count": len(right_group) if right_group else 0,
                "left_example": left_group[0] if left_group else None,
                "right_example": right_group[0] if right_group else None,
            }
        )

    return results
