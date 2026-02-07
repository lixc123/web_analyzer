"""代理抓包环境诊断（Windows 优先）。

该模块用于输出抓包必备状态与常见失败原因建议，供前端向导/错误页直接展示。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import os
import re
import socket
import logging
import time

logger = logging.getLogger(__name__)


def _is_windows() -> bool:
    return os.name == "nt"


def _safe_get(mapping: Optional[Dict[str, Any]], key: str, default=None):
    if not mapping:
        return default
    return mapping.get(key, default)


def _extract_proxy_targets(proxy_server_value: str) -> List[str]:
    """解析 WinINet ProxyServer 字符串。

    可能形态：
    - "127.0.0.1:8888"
    - "http=127.0.0.1:8888;https=127.0.0.1:8888"
    """
    if not proxy_server_value:
        return []

    raw = str(proxy_server_value).strip()
    if not raw:
        return []

    parts = [p.strip() for p in raw.split(";") if p.strip()]
    targets: List[str] = []
    for p in parts:
        if "=" in p:
            _, v = p.split("=", 1)
            v = v.strip()
            if v:
                targets.append(v)
        else:
            targets.append(p)
    return targets


def _parse_proxy_server_map(proxy_server_value: str) -> Dict[str, str]:
    """将 WinINet ProxyServer 解析为 {scheme: host:port} 的映射。

    - global: {"all": "127.0.0.1:8888"}
    - per-protocol: {"http": "...", "https": "..."}
    """
    raw = str(proxy_server_value or "").strip()
    if not raw:
        return {}

    out: Dict[str, str] = {}
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k and v:
                out[k] = v
        else:
            out["all"] = p
    return out


def _proxy_matches_host_port(proxy_server_value: str, host: str, port: int) -> bool:
    target = f"{host}:{int(port)}"
    targets = _extract_proxy_targets(proxy_server_value)
    if not targets:
        return False
    return any(t.strip() == target for t in targets)


_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{160,}")
_LONG_HEX_RE = re.compile(r"[0-9a-fA-F]{160,}")


def _normalize_ct(ct: str) -> str:
    try:
        return str(ct or "").split(";", 1)[0].strip().lower()
    except Exception:
        return ""


def _is_text_like_ct(ct: str) -> bool:
    c = _normalize_ct(ct)
    return bool(
        c.startswith("text/")
        or ("application/json" in c)
        or ("javascript" in c)
        or ("xml" in c)
        or (c in {"application/x-www-form-urlencoded"})
    )


def _is_known_binary_protocol(ct: str, tags: List[str]) -> bool:
    c = _normalize_ct(ct)
    if any(t in {"grpc", "protobuf"} for t in (tags or [])):
        return True
    if c.startswith("application/grpc"):
        return True
    if c in {"application/x-protobuf", "application/protobuf"}:
        return True
    return False


def _artifact_is_binary(obj: Any) -> bool:
    try:
        return bool(isinstance(obj, dict) and obj.get("is_binary") is True)
    except Exception:
        return False


def _looks_like_opaque_text(text: str) -> bool:
    """best-effort 判断文本预览是否“不可读/疑似加密/序列化”。"""
    if not text:
        return False
    s = str(text).strip()
    if not s:
        return False
    if s.startswith("[二进制数据]"):
        return True

    # 预览里包含很长的 base64/hex token：常见于应用层加密/签名/序列化
    compact = re.sub(r"\s+", "", s)
    if _LONG_BASE64_RE.search(compact):
        return True
    if _LONG_HEX_RE.search(compact):
        return True
    return False


def analyze_app_layer_encryption_suspect(recent_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """分析最近请求是否存在“抓到了但 payload 不可读”的情况（best-effort）。"""
    samples: List[Dict[str, Any]] = []
    for r in recent_requests or []:
        if not isinstance(r, dict):
            continue
        # 排除 WS 握手请求（payload 意义不大）
        if bool(r.get("is_websocket_handshake")):
            continue
        samples.append(r)

    total = len(samples)
    if total <= 0:
        return {"total": 0, "suspect": 0, "ratio": 0.0, "examples": []}

    suspect = 0
    examples: List[Dict[str, Any]] = []

    for r in samples[-80:]:
        try:
            tags = r.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            ct = r.get("content_type") or ""
            if not ct:
                # fallback: request/response headers
                ct = (r.get("response_headers") or {}).get("Content-Type") or (r.get("headers") or {}).get("Content-Type") or ""

            ct_norm = _normalize_ct(ct)
            if _is_known_binary_protocol(ct_norm, tags):
                continue
            if ct_norm.startswith(("image/", "video/", "audio/")):
                continue

            body_opaque = _artifact_is_binary(r.get("body_artifact")) or _looks_like_opaque_text(r.get("body") or "")
            resp_opaque = _artifact_is_binary(r.get("response_body_artifact")) or _looks_like_opaque_text(r.get("response_body") or "")

            # text-like 协议里出现二进制/opaque 预览更可疑；unknown/binary 也纳入统计
            if (body_opaque or resp_opaque) and (_is_text_like_ct(ct_norm) or ct_norm in {"", "application/octet-stream"}):
                suspect += 1
                if len(examples) < 3:
                    examples.append(
                        {
                            "url": r.get("url"),
                            "method": r.get("method"),
                            "content_type": ct_norm,
                            "has_body_artifact": bool(r.get("body_artifact")),
                            "has_response_artifact": bool(r.get("response_body_artifact")),
                        }
                    )
        except Exception:
            continue

    ratio = float(suspect) / float(total) if total else 0.0
    return {"total": total, "suspect": suspect, "ratio": ratio, "examples": examples}


def get_port_listen_status(host: str, port: int, timeout: float = 0.3) -> Dict[str, Any]:
    """检查本机端口是否可连接（用于判断服务是否已监听）。

    注意：这不是防火墙的完整判断，仅用于“端口是否在监听”的快速信号。
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"reachable": True}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


def get_wininet_proxy_settings() -> Dict[str, Any]:
    if not _is_windows():
        return {"supported": False}

    import winreg

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    result: Dict[str, Any] = {"supported": True}

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
    except Exception as exc:
        return {"supported": True, "error": f"open_registry_failed: {exc}"}

    def _read(name: str):
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return value
        except Exception:
            return None

    try:
        proxy_enable = _read("ProxyEnable")
        proxy_server = _read("ProxyServer")
        proxy_override = _read("ProxyOverride")
        auto_config_url = _read("AutoConfigURL")
        auto_detect = _read("AutoDetect")
    finally:
        try:
            winreg.CloseKey(key)
        except Exception:
            pass

    result.update(
        {
            "proxy_enabled": bool(proxy_enable) if proxy_enable is not None else False,
            "proxy_server": proxy_server or "",
            "proxy_server_map": _parse_proxy_server_map(proxy_server or ""),
            "proxy_override": proxy_override or "",
            "auto_config_url": auto_config_url or "",
            "auto_detect": bool(auto_detect) if auto_detect is not None else False,
        }
    )
    return result


def get_quic_policy_status() -> Dict[str, Any]:
    """best-effort 检测 Chromium 系浏览器 QUIC/HTTP3 策略状态（Windows）。"""
    if not _is_windows():
        return {"supported": False}

    try:
        import winreg

        candidates = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome", "QuicAllowed"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Google\Chrome", "QuicAllowed"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "QuicAllowed"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Edge", "QuicAllowed"),
        ]

        findings = []
        for root, path, name in candidates:
            try:
                key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
            except Exception:
                continue
            try:
                value, _t = winreg.QueryValueEx(key, name)
                findings.append(
                    {
                        "root": "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                        "path": path,
                        "name": name,
                        "value": int(value),
                    }
                )
            except Exception:
                pass
            finally:
                try:
                    winreg.CloseKey(key)
                except Exception:
                    pass

        # 若存在任一策略且为 0，则认为已禁用
        disabled = any(f.get("value") == 0 for f in findings)
        enabled = any(f.get("value") == 1 for f in findings)
        return {
            "supported": True,
            "disabled": disabled,
            "enabled": enabled,
            "policies": findings,
        }
    except Exception as exc:
        return {"supported": True, "error": str(exc)}


def get_udp_443_activity(sample_limit: int = 8) -> Dict[str, Any]:
    """best-effort 检测近期 UDP 443 活动（QUIC 常用端口）。"""
    if not _is_windows():
        return {"supported": False}

    try:
        import psutil

        hits = []
        count = 0
        for c in psutil.net_connections(kind="udp"):
            try:
                r = getattr(c, "raddr", None)
                if not r:
                    continue
                rport = int(getattr(r, "port", 0) or 0)
                if rport != 443:
                    continue
                count += 1
                if len(hits) < int(sample_limit):
                    pid = getattr(c, "pid", None)
                    name = None
                    try:
                        if pid:
                            name = psutil.Process(pid).name()
                    except Exception:
                        name = None
                    hits.append(
                        {
                            "laddr": {"ip": getattr(c.laddr, "ip", None), "port": getattr(c.laddr, "port", None)} if getattr(c, "laddr", None) else None,
                            "raddr": {"ip": getattr(r, "ip", None), "port": rport},
                            "pid": pid,
                            "process": name,
                        }
                    )
            except Exception:
                continue

        return {"supported": True, "count": count, "samples": hits}
    except Exception as exc:
        return {"supported": True, "error": str(exc)}


def build_issues_summary(
    *,
    proxy_running: bool,
    proxy_host: str,
    proxy_port: int,
    wininet: Dict[str, Any],
    winhttp: Dict[str, Any],
    cert_status: Dict[str, Any],
    firewall_status: Optional[Dict[str, Any]] = None,
    recent_requests: int = 0,
    recent_errors: Optional[List[Dict[str, Any]]] = None,
    quic_policy: Optional[Dict[str, Any]] = None,
    udp_443: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []

    def add(code: str, level: str, message: str, action: Optional[str] = None, command: Optional[str] = None):
        issues.append(
            {
                "code": code,
                "level": level,  # info|warning|error
                "message": message,
                "action": action,
                "command": command,
            }
        )

    if not proxy_running:
        add("PROXY_NOT_RUNNING", "error", "代理服务未运行", "启动代理服务后再配置系统代理/WinHTTP 代理")
        return issues

    # 端口是否可连接（本机）
    port_status = get_port_listen_status("127.0.0.1", proxy_port)
    if not port_status.get("reachable"):
        add("PORT_NOT_LISTENING", "error", f"代理端口不可达: 127.0.0.1:{proxy_port}", "检查服务是否正常启动/端口是否被占用")

    # 证书
    if _is_windows():
        installed = bool(_safe_get(cert_status, "installed_windows"))
        exists = bool(_safe_get(cert_status, "exists"))
        if not exists:
            add("CERT_NOT_FOUND", "error", "mitmproxy CA 证书文件不存在", "先启动一次代理服务或在证书管理中生成/重置证书")
        if exists and not installed:
            add("CERT_NOT_INSTALLED", "warning", "Windows 未安装 CA 证书（HTTPS 可能抓不到/会报错）", "在证书管理中点击“Windows 安装证书”")
        if _safe_get(cert_status, "is_expired"):
            add("CERT_EXPIRED", "error", f"证书已过期: {_safe_get(cert_status,'expiry_date','')}", "重新生成证书并重新安装")
        elif _safe_get(cert_status, "is_expiring_soon"):
            add("CERT_EXPIRING_SOON", "warning", f"证书即将过期: {_safe_get(cert_status,'expiry_date','')}", "建议尽快重新生成证书并重新安装")

    # 系统代理（WinINet）
    if _is_windows():
        proxy_enabled = bool(_safe_get(wininet, "proxy_enabled"))
        wininet_proxy_server = str(_safe_get(wininet, "proxy_server", "") or "")
        if not proxy_enabled:
            add(
                "WININET_PROXY_DISABLED",
                "warning",
                "WinINet(系统/IE)代理未启用（部分应用不会走代理）",
                "在代理控制中开启“WinINet 系统代理”，或对目标应用单独设置代理",
            )
        else:
            if wininet_proxy_server and not _proxy_matches_host_port(wininet_proxy_server, "127.0.0.1", proxy_port):
                add(
                    "WININET_PROXY_MISMATCH",
                    "warning",
                    f"WinINet 代理已启用，但未指向当前代理端口（当前: {wininet_proxy_server}）",
                    "可能与其它代理软件冲突；建议临时切换为本代理端口",
                )
        if _safe_get(wininet, "auto_config_url"):
            add(
                "WININET_PAC_ENABLED",
                "info",
                "检测到 PAC/自动代理脚本：可能导致代理规则不一致",
                "若抓包异常，可暂时关闭 PAC，或确保 PAC 将目标域名导向本代理",
            )

    # WinHTTP
    if _is_windows():
        winhttp_mode = _safe_get(winhttp, "mode")
        winhttp_proxy_server = str(_safe_get(winhttp, "proxy_server", "") or "")
        if winhttp_mode == "proxy" and winhttp_proxy_server and winhttp_proxy_server.strip() != f"127.0.0.1:{proxy_port}":
            add(
                "WINHTTP_PROXY_MISMATCH",
                "warning",
                f"WinHTTP 代理已设置，但未指向当前代理端口（当前: {winhttp_proxy_server}）",
                "可能与其它代理配置冲突；建议切换为本代理端口或在 UI 中重设 WinHTTP",
                command=f'netsh winhttp set proxy 127.0.0.1:{proxy_port} "localhost;127.*;192.168.*;<local>"',
            )
        if winhttp_mode in {"direct", "unknown"}:
            add(
                "WINHTTP_PROXY_NOT_SET",
                "warning",
                "WinHTTP 代理未设置（部分桌面应用会绕过 WinINet）",
                "在代理控制中开启“WinHTTP 代理”，或运行 netsh 命令设置",
                command=f'netsh winhttp set proxy 127.0.0.1:{proxy_port} "localhost;127.*;192.168.*;<local>"',
            )

    # 防火墙
    if firewall_status and firewall_status.get("supported") and firewall_status.get("enabled"):
        add(
            "FIREWALL_ENABLED",
            "info",
            "Windows 防火墙处于启用状态",
            f"若设备无法连接，请确认允许端口 {proxy_port} 入站规则",
        )

    # 经验提示：HTTP3/QUIC
    quic_disabled = bool(_safe_get(quic_policy, "disabled"))
    if quic_disabled:
        add("HTTP3_QUIC_DISABLED", "info", "检测到 QUIC/HTTP3 已被策略禁用", "若仍抓不到流量，优先排查是否绕过代理或证书固定")
    else:
        add(
            "HTTP3_QUIC_RISK",
            "info",
            "部分 Chromium 系应用可能走 HTTP/3(QUIC)，代理抓包会缺失",
            "可尝试禁用 QUIC/HTTP3（例如启动参数 --disable-quic 或浏览器策略）",
            command='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v QuicAllowed /t REG_DWORD /d 0 /f\n'
            'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v QuicAllowed /t REG_DWORD /d 0 /f',
        )

    # 若长时间无流量：提示绕过代理/SSL pinning
    if recent_requests == 0:
        # best-effort：若观察到 UDP 443 活动，强提示 QUIC/HTTP3
        if udp_443 and udp_443.get("supported") and int(udp_443.get("count", 0) or 0) > 0:
            add(
                "HTTP3_QUIC",
                "warning",
                "检测到 UDP 443 活动（可能为 QUIC/HTTP3），代理抓包可能为空",
                "尝试禁用 QUIC/HTTP3 或让应用降级到 TCP（例如启动参数 --disable-quic）",
                command='reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v QuicAllowed /t REG_DWORD /d 0 /f\n'
                'reg add "HKLM\\SOFTWARE\\Policies\\Google\\Chrome" /v QuicAllowed /t REG_DWORD /d 0 /f',
            )

        # best-effort：错误统计（TLS/连接失败）
        if recent_errors:
            sample = None
            try:
                sample = recent_errors[-1]
            except Exception:
                sample = None
            msg = str(sample.get("message")) if isinstance(sample, dict) else ""
            if msg:
                add("TLS_HANDSHAKE_FAIL", "warning", f"检测到代理侧错误（可能为TLS握手/连接中断）：{msg[:140]}", "若已安装证书仍失败，可能存在证书固定/自研TLS；尝试 Native Hook 的 SSL Unpin 或对应库 Hook")
            else:
                add("TLS_HANDSHAKE_FAIL", "warning", "检测到代理侧错误（可能为TLS握手/连接中断）", "若已安装证书仍失败，可能存在证书固定/自研TLS；尝试 Native Hook 的 SSL Unpin 或对应库 Hook")

            # 证书已安装但仍出现证书相关错误 → 提示可能 pinning
            if _is_windows() and bool(_safe_get(cert_status, "installed_windows")):
                low = msg.lower()
                if any(k in low for k in ["certificate", "cert", "unknown ca", "self signed", "verify", "pin"]):
                    add("CERT_PINNING", "warning", "证书已安装但仍出现证书校验相关失败：可能存在证书固定(pinning)或自研TLS", "优先尝试 Native Hook：Windows SSL Unpin；若无效，需针对 OpenSSL/BoringSSL 等库进行 Hook")

        # 绕过代理提示：WinINet/WinHTTP 均未设置
        wininet_enabled = bool(_safe_get(wininet, "proxy_enabled"))
        winhttp_mode = str(_safe_get(winhttp, "mode") or "")
        if (not wininet_enabled) and (winhttp_mode in {"", "direct", "unknown"}):
            add("BYPASS_PROXY", "warning", "WinINet/WinHTTP 均未指向代理：目标应用很可能绕过代理或不使用系统代理", "开启 WinINet/WinHTTP；若仍无流量，考虑直连/QUIC/证书固定 → 使用 Native Hook 定位网络栈")

        add(
            "NO_TRAFFIC",
            "warning",
            "当前暂无捕获到的请求（可能未走代理/走 QUIC/证书固定/直连）",
            "确认目标应用代理设置；若 HTTPS 报错或抓不到，可尝试 Native Hook 的 SSL Unpin 模板",
        )

    return issues


def run_proxy_diagnostics(manager) -> Dict[str, Any]:
    """聚合诊断信息。manager 为 ProxyServiceManager 实例。"""
    from backend.proxy.cert_manager import CertManager
    from backend.utils.firewall_checker import FirewallChecker

    proxy_server = manager.get_server()
    proxy_running = bool(proxy_server and manager.is_running())
    proxy_host = proxy_server.host if proxy_server else ""
    proxy_port = int(proxy_server.port) if proxy_server else 0

    wininet = get_wininet_proxy_settings()
    winhttp = {"supported": False}
    if _is_windows():
        try:
            from backend.proxy.winhttp_proxy import WindowsWinHttpProxy

            winhttp = WindowsWinHttpProxy().get_current_settings().to_dict()
        except Exception as exc:
            winhttp = {"supported": True, "mode": "unknown", "error": str(exc)}

    cert_manager = CertManager()
    cert_status = cert_manager.get_cert_status()

    try:
        firewall_status = FirewallChecker.check_firewall_status()
    except Exception as exc:
        firewall_status = {"supported": _is_windows(), "error": str(exc)}

    # 统计：用于判断“无流量”
    stats: Dict[str, Any] = {}
    try:
        stats = manager.get_statistics().get_summary()
        total_requests = int(stats.get("total_requests", 0))
        recent_errors = stats.get("recent_errors") or []
    except Exception:
        total_requests = 0
        recent_errors = []

    quic_policy = get_quic_policy_status()
    udp_443 = get_udp_443_activity()

    issues = build_issues_summary(
        proxy_running=proxy_running,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        wininet=wininet,
        winhttp=winhttp,
        cert_status=cert_status,
        firewall_status=firewall_status,
        recent_requests=total_requests,
        recent_errors=recent_errors,
        quic_policy=quic_policy,
        udp_443=udp_443,
    )

    # “抓到了但看不懂”：应用层加密/压缩/自研协议 best-effort 识别
    payload_hint: Dict[str, Any] = {}
    try:
        storage = manager.get_storage()
        recent = []
        try:
            recent = storage.get_recent_requests(limit=80)
        except Exception:
            recent = list(getattr(storage, "requests", []) or [])[-80:]
        payload_hint = analyze_app_layer_encryption_suspect(recent_requests=recent)
        if int(payload_hint.get("total", 0) or 0) >= 10 and float(payload_hint.get("ratio", 0.0) or 0.0) >= 0.5 and int(payload_hint.get("suspect", 0) or 0) >= 5:
            issues.append(
                {
                    "code": "APP_LAYER_ENCRYPTION",
                    "level": "warning",
                    "message": f"检测到 payload 多为不可读/二进制：{payload_hint.get('suspect')}/{payload_hint.get('total')}（可能存在应用层加密/压缩/自研序列化）",
                    "action": "可尝试 Native Hook：encryption_locator / compression_monitor；若为 WebView2/Electron/CEF，可启用 JS 注入获取调用栈",
                }
            )
    except Exception:
        payload_hint = {}

    return {
        "supported": True,
        "os": {"name": os.name, "is_windows": _is_windows()},
        "proxy_service": {
            "running": proxy_running,
            "host": proxy_host,
            "port": proxy_port,
        },
        "proxy": {
            "wininet": wininet,
            "winhttp": winhttp,
        },
        "cert": cert_status,
        "firewall": firewall_status,
        "quic": {"policy": quic_policy, "udp_443": udp_443},
        "statistics": {
            "total_requests": total_requests,
            "total_errors": int(stats.get("total_errors", 0)) if isinstance(stats, dict) else 0,
        },
        "payload_hint": payload_hint,
        "issues": issues,
    }
