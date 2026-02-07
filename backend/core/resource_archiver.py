import asyncio
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, List, Optional, Set
from urllib.parse import urlparse

from models.request_record import RequestRecord
from .har_exporter import export_har


class ResourceArchiver:
    """负责创建会话目录并将请求/响应落盘的简单工具类。"""

    def __init__(
        self,
        base_output_dir: Path,
        log_callback: Optional[Callable[[str], None]] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self._log = log_callback or (lambda _msg: None)

        base_output_dir.mkdir(parents=True, exist_ok=True)

        self._start_time = datetime.now()
        timestamp = self._start_time.strftime("%Y%m%d_%H%M%S")
        session_dir_name = session_id or f"session_{timestamp}"
        self._session_dir = base_output_dir / session_dir_name
        self._responses_dir = self._session_dir / "responses"
        self._request_bodies_dir = self._session_dir / "request_bodies"
        self._hooks_dir = self._session_dir / "hooks"

        self._session_dir.mkdir(parents=True, exist_ok=True)
        self._responses_dir.mkdir(parents=True, exist_ok=True)
        self._request_bodies_dir.mkdir(parents=True, exist_ok=True)
        self._hooks_dir.mkdir(parents=True, exist_ok=True)

        # 分类目录
        self._scripts_dir = self._session_dir / "scripts"
        self._styles_dir = self._session_dir / "styles"
        self._images_dir = self._session_dir / "images"
        self._scripts_dir.mkdir(parents=True, exist_ok=True)
        self._styles_dir.mkdir(parents=True, exist_ok=True)
        self._images_dir.mkdir(parents=True, exist_ok=True)

        # 浏览器数据目录
        self._browser_data_dir = self._session_dir / "browser_data"
        self._screenshots_dir = self._session_dir / "screenshots"
        self._storage_dir = self._browser_data_dir / "storage"
        self._interactions_dir = self._browser_data_dir / "interactions"
        self._performance_dir = self._browser_data_dir / "performance"
        self._dom_dir = self._browser_data_dir / "dom"
        
        self._browser_data_dir.mkdir(parents=True, exist_ok=True)
        self._screenshots_dir.mkdir(parents=True, exist_ok=True)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._interactions_dir.mkdir(parents=True, exist_ok=True)
        self._performance_dir.mkdir(parents=True, exist_ok=True)
        self._dom_dir.mkdir(parents=True, exist_ok=True)

        # 会话元信息
        self._start_url: Optional[str] = None
        self._request_count: int = 0
        self._browser_data_count: int = 0
        self._screenshot_count: int = 0
        self._js_resources_report: Optional[dict] = None
        self._crawl_report: Optional[dict] = None

        self._log(f"会话目录: {self._session_dir}")
        self._log(f"浏览器数据目录: {self._browser_data_dir}")
        self._log(f"截图目录: {self._screenshots_dir}")
        self._log(f"请求体目录: {self._request_bodies_dir}")

    def set_start_url(self, url: str) -> None:
        """设置录制起始 URL。"""
        self._start_url = url

    @property
    def session_dir(self) -> Path:
        return self._session_dir

    @property
    def responses_dir(self) -> Path:
        return self._responses_dir

    @property
    def request_bodies_dir(self) -> Path:
        """请求体落盘目录。"""
        return self._request_bodies_dir

    @property
    def hooks_dir(self) -> Path:
        return self._hooks_dir

    @property
    def screenshots_dir(self) -> Path:
        """截图落盘目录（用于确保 session zip 自包含）。"""
        return self._screenshots_dir

    def set_crawl_report(self, report: Optional[dict]) -> None:
        """记录自动爬链路摘要（写入 metadata.json）。"""
        self._crawl_report = report

    def _guess_ext_for_content_type(self, content_type: str, fallback: str = ".bin") -> str:
        ct = str(content_type or "").split(";", 1)[0].strip().lower()
        if not ct:
            return fallback
        if ct == "application/json":
            return ".json"
        if ct in {"application/x-www-form-urlencoded"}:
            return ".txt"
        if ct.startswith("text/"):
            return ".txt"
        if "javascript" in ct:
            return ".js"
        if "xml" in ct:
            return ".xml"
        return fallback

    def save_request_body(self, request_id: str, body: bytes, content_type: str = "") -> dict:
        """保存请求体到 request_bodies/，返回引用信息（类似 proxy artifacts）。"""
        if not request_id:
            request_id = f"req_{int(time.time() * 1000)}"

        ct_norm = str(content_type or "").split(";", 1)[0].strip()
        ext = self._guess_ext_for_content_type(ct_norm, ".bin")
        filename = f"{request_id}{ext}"
        full_path = self._request_bodies_dir / filename

        sha256 = hashlib.sha256(body or b"").hexdigest()
        try:
            with open(full_path, "wb") as f:
                f.write(body or b"")
        except Exception as exc:  # noqa: BLE001
            self._log(f"保存请求体失败: {exc}")

        try:
            rel_path = os.path.relpath(full_path, self._session_dir).replace("\\", "/")
        except Exception:
            rel_path = str(full_path.name)

        is_binary = True
        try:
            (body or b"").decode("utf-8")
            is_binary = False
        except Exception:
            is_binary = True

        return {
            "relative_path": rel_path,
            "size": int(len(body or b"")),
            "sha256": sha256,
            "content_type": ct_norm or "application/octet-stream",
            "is_binary": is_binary,
            "truncated": False,
        }

    def save_response(self, record: RequestRecord, body: bytes) -> str:
        """保存响应体，根据类型分类存储，返回相对会话目录的路径。"""
        # 根据 Content-Type 选择更合适的扩展名和目录
        content_type = None
        if record.response_headers:
            for k, v in record.response_headers.items():
                if k.lower() == "content-type":
                    content_type = v.split(";")[0].strip()
                    break

        # Content-Type 缺失时，尽可能从 URL 后缀推断
        if not content_type:
            try:
                parsed = urlparse(record.url)
                path_lower = (parsed.path or "").lower()
                if path_lower.endswith(".js"):
                    content_type = "application/javascript"
                elif path_lower.endswith(".css"):
                    content_type = "text/css"
                elif path_lower.endswith(".json"):
                    content_type = "application/json"
                elif path_lower.endswith(".html") or path_lower.endswith(".htm"):
                    content_type = "text/html"
                elif path_lower.endswith(".png"):
                    content_type = "image/png"
                elif path_lower.endswith(".jpg") or path_lower.endswith(".jpeg"):
                    content_type = "image/jpeg"
                elif path_lower.endswith(".gif"):
                    content_type = "image/gif"
                elif path_lower.endswith(".webp"):
                    content_type = "image/webp"
                elif path_lower.endswith(".svg"):
                    content_type = "image/svg+xml"
                elif path_lower.endswith(".woff"):
                    content_type = "font/woff"
                elif path_lower.endswith(".woff2"):
                    content_type = "font/woff2"
            except Exception:
                content_type = None

        record.content_type = content_type

        ext = ".bin"
        target_dir = self._responses_dir  # 默认目录

        if content_type:
            if content_type.startswith("application/json"):
                ext = ".json"
            elif content_type.startswith("text/html"):
                ext = ".html"
            elif content_type.startswith("text/css"):
                ext = ".css"
                target_dir = self._styles_dir
            elif content_type.startswith("application/javascript") or content_type.startswith("text/javascript"):
                ext = ".js"
                target_dir = self._scripts_dir
            elif content_type.startswith("image/png"):
                ext = ".png"
                target_dir = self._images_dir
            elif content_type.startswith("image/jpeg"):
                ext = ".jpg"
                target_dir = self._images_dir
            elif content_type.startswith("image/gif"):
                ext = ".gif"
                target_dir = self._images_dir
            elif content_type.startswith("image/webp"):
                ext = ".webp"
                target_dir = self._images_dir
            elif content_type.startswith("image/svg"):
                ext = ".svg"
                target_dir = self._images_dir

        filename = f"{record.id}{ext}"
        full_path = target_dir / filename

        try:
            with open(full_path, "wb") as f:
                f.write(body)
            rel_path = os.path.relpath(full_path, self._session_dir)
            self._log(f"保存响应: {rel_path} ({len(body)} bytes)")
            return rel_path
        except Exception as exc:  # noqa: BLE001
            self._log(f"保存响应失败: {exc}")
            return filename

    def save_requests(self, records: List[RequestRecord]) -> None:
        """将请求记录列表写入 requests.json。"""
        self._request_count = len(records)
        path = self._session_dir / "requests.json"
        try:
            data = [asdict(r) for r in records]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self._log(f"已写入 requests.json ({len(records)} 条)")
        except Exception as exc:  # noqa: BLE001
            self._log(f"写入 requests.json 失败: {exc}")

    def save_metadata(self, records: List[RequestRecord]) -> None:
        """生成 metadata.json 会话元信息文件。"""
        end_time = datetime.now()
        duration_seconds = (end_time - self._start_time).total_seconds()

        # 统计资源类型
        resource_types: dict = {}
        content_types: dict = {}
        domains: set = set()

        for r in records:
            # 资源类型统计
            rt = r.resource_type or "unknown"
            resource_types[rt] = resource_types.get(rt, 0) + 1

            # Content-Type 统计
            ct = r.content_type or "unknown"
            content_types[ct] = content_types.get(ct, 0) + 1

            # 域名统计
            try:
                parsed = urlparse(r.url)
                if parsed.netloc:
                    domains.add(parsed.netloc)
            except Exception:
                pass

        # 统计有调用栈的请求数
        requests_with_stack = sum(1 for r in records if r.call_stack)

        metadata = {
            "session_id": self._session_dir.name,
            "start_time": self._start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": round(duration_seconds, 2),
            "start_url": self._start_url,
            "total_requests": len(records),
            "requests_with_call_stack": requests_with_stack,
            "resource_types": resource_types,
            "content_types": content_types,
            "domains": sorted(domains),
            "js_resources": self._js_resources_report or {},
            "crawl": self._crawl_report or {},
        }

        path = self._session_dir / "metadata.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
            self._log("已生成 metadata.json")
        except Exception as exc:  # noqa: BLE001
            self._log(f"生成 metadata.json 失败: {exc}")

    def save_har(self, records: List[RequestRecord]) -> None:
        """生成 HAR 文件 trace.har。"""
        path = self._session_dir / "trace.har"
        try:
            export_har(records, path)
            self._log("已生成 trace.har")
        except Exception as exc:  # noqa: BLE001
            self._log(f"生成 HAR 失败: {exc}")

    def append_hook_line(self, line: str) -> None:
        """追加一行 Hook 日志到 hooks/console.log。"""
        path = self._hooks_dir / "console.log"
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as exc:  # noqa: BLE001
            self._log(f"写入 Hook 日志失败: {exc}")

    @property
    def scripts_dir(self) -> Path:
        """JS 脚本目录。"""
        return self._scripts_dir

    async def save_js_resources(
        self,
        page: Any,
        max_urls: int = 80,
        max_concurrency: int = 3,
        per_url_timeout_seconds: float = 3.0,
        time_budget_seconds: float = 15.0,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> List[str]:
        """主动抓取并保存页面所有 JS 资源。
        
        通过 JavaScript 在页面中获取所有 <script> 标签的 src，
        然后通过 page.evaluate 或 fetch 下载它们。
        
        Args:
            page: Playwright Page 对象
            
        Returns:
            已保存的 JS 文件相对路径列表
        """
        saved_paths: List[str] = []
        saved_urls: Set[str] = set()
        failures: List[dict] = []
        start_ts = time.monotonic()
        
        try:
            # 获取页面上所有脚本 URL
            script_urls = await page.evaluate("""
                () => {
                    const urls = [];
                    // 获取所有 <script> 标签
                    document.querySelectorAll('script[src]').forEach(s => {
                        if (s.src) urls.push(s.src);
                    });
                    // 获取所有动态加载的脚本（通过 performance API）
                    if (window.performance && window.performance.getEntriesByType) {
                        const resources = window.performance.getEntriesByType('resource');
                        resources.forEach(r => {
                            if (r.initiatorType === 'script' && r.name) {
                                urls.push(r.name);
                            }
                        });
                    }
                    return [...new Set(urls)];  // 去重
                }
            """)
            
            self._log(f"发现 {len(script_urls)} 个 JS 资源")

            filtered_urls: List[str] = []
            for url in script_urls:
                if len(filtered_urls) >= max_urls:
                    break
                if url in saved_urls:
                    continue
                if url.startswith("data:") or url.startswith("blob:"):
                    continue
                saved_urls.add(url)
                filtered_urls.append(url)

            total = len(filtered_urls)
            if total == 0:
                return []

            sem = asyncio.Semaphore(max(1, int(max_concurrency)))
            timeout_ms = max(100, int(per_url_timeout_seconds * 1000))

            async def _fetch_and_save(url: str) -> tuple[str, Optional[str], Optional[str]]:
                async with sem:
                    if (time.monotonic() - start_ts) > time_budget_seconds:
                        return url, None, "time_budget_exceeded"

                    try:
                        content = None
                        err: Optional[str] = None

                        # 1) Prefer Playwright APIRequestContext (not subject to browser CORS)
                        try:
                            req_ctx = getattr(page, "request", None)
                            if req_ctx is not None and hasattr(req_ctx, "get"):
                                resp = await req_ctx.get(url, timeout=timeout_ms)
                                ok_attr = getattr(resp, "ok", False) if resp is not None else False
                                ok = bool(ok_attr() if callable(ok_attr) else ok_attr)
                                if ok:
                                    content = await resp.text()
                                else:
                                    status = getattr(resp, "status", None)
                                    err = f"http_{status}" if status is not None else "http_failed"
                        except Exception as e:
                            err = str(e)

                        # 2) Fallback to in-page fetch (may fail due to CORS)
                        if content is None:
                            result = await asyncio.wait_for(
                                page.evaluate(
                                    """async ({ url, timeoutMs }) => {
                                        try {
                                            const controller = new AbortController();
                                            const timer = setTimeout(() => controller.abort(), timeoutMs);
                                            const resp = await fetch(url, { signal: controller.signal, credentials: 'include' });
                                            clearTimeout(timer);
                                            if (!resp) return { ok: false, error: 'no_response' };
                                            if (!resp.ok) return { ok: false, error: 'http_' + resp.status };
                                            const text = await resp.text();
                                            return { ok: true, text: text };
                                        } catch (e) {
                                            return { ok: false, error: String(e) };
                                        }
                                    }""",
                                    {"url": url, "timeoutMs": timeout_ms},
                                ),
                                timeout=per_url_timeout_seconds + 1.0,
                            )
                            if isinstance(result, dict) and result.get("ok") and isinstance(result.get("text"), str):
                                content = result.get("text")
                            else:
                                if isinstance(result, dict) and result.get("error"):
                                    err = str(result.get("error"))
                    except Exception:
                        return url, None, "exception"

                    if not content:
                        return url, None, err or "empty"

                    rel_path = await asyncio.to_thread(self._save_js_content, url, content)
                    return url, rel_path, None

            tasks = [asyncio.create_task(_fetch_and_save(url)) for url in filtered_urls]
            done_count = 0
            for fut in asyncio.as_completed(tasks):
                url, rel_path, err = await fut
                done_count += 1
                if progress_callback is not None:
                    try:
                        progress_callback(done_count, total, url)
                    except Exception:
                        pass
                if rel_path:
                    saved_paths.append(rel_path)
                else:
                    failures.append({"url": url, "error": err or "unknown"})
                if (time.monotonic() - start_ts) > time_budget_seconds:
                    break
                    
        except Exception as exc:
            self._log(f"获取 JS 资源列表失败: {exc}")
        
        report = {
            "attempted": int(len(filtered_urls) if 'filtered_urls' in locals() else 0),
            "saved": int(len(saved_paths)),
            "failed": int(len(failures)),
            "failures_sample": failures[: min(12, len(failures))],
            "time_budget_seconds": float(time_budget_seconds),
            "duration_seconds": round(float(time.monotonic() - start_ts), 3),
        }
        self._js_resources_report = report
        try:
            (self._session_dir / "js_resources_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

        self._log(f"共保存 {len(saved_paths)} 个 JS 文件")
        if failures:
            self._log(f"[WARNING] JS 资源保存失败: {len(failures)}/{len(saved_paths) + len(failures)}（跨域/CORS/网络/超时等）")
        return saved_paths

    def _save_js_content(self, url: str, content: str) -> Optional[str]:
        """保存 JS 内容到文件。
        
        Args:
            url: 脚本 URL
            content: 脚本内容
            
        Returns:
            相对路径，失败返回 None
        """
        try:
            # 从 URL 生成文件名
            parsed = urlparse(url)
            path_part = parsed.path.rstrip("/")
            
            # 获取文件名
            if path_part:
                filename = path_part.split("/")[-1]
            else:
                filename = parsed.netloc
            
            # 确保是 .js 扩展名
            if not filename.endswith(".js"):
                filename = filename + ".js"
            
            # 清理文件名
            filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
            
            # 如果文件名太长或不合适，用 hash
            if len(filename) > 100 or not filename.strip("_.js"):
                content_hash = hashlib.md5(content.encode()).hexdigest()[:12]
                filename = f"{content_hash}.js"
            
            # 检查是否已存在同名文件
            target_path = self._scripts_dir / filename
            counter = 1
            while target_path.exists():
                name, ext = os.path.splitext(filename)
                target_path = self._scripts_dir / f"{name}_{counter}{ext}"
                counter += 1
            
            # 写入文件
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(content)
            
            rel_path = os.path.relpath(target_path, self._session_dir)
            self._log(f"保存 JS: {rel_path}")
            return rel_path
            
        except Exception as exc:
            self._log(f"保存 JS 内容失败: {exc}")
            return None

    def beautify_js_files(
        self,
        use_builtin: bool = True,
        max_files: Optional[int] = None,
        time_budget_seconds: Optional[float] = None,
    ) -> int:
        """格式化 scripts 目录下的所有 JS 文件。
        
        优先使用内置的简单格式化，如果安装了 js-beautify 则可以使用外部工具。
        
        Args:
            use_builtin: 是否使用内置格式化（默认 True）
            
        Returns:
            成功格式化的文件数量
        """
        js_files = list(self._scripts_dir.glob("*.js"))
        if max_files is not None:
            js_files = js_files[: max(0, int(max_files))]
        success_count = 0
        start_ts = time.monotonic()
        
        self._log(f"开始格式化 {len(js_files)} 个 JS 文件...")
        
        for js_path in js_files:
            if time_budget_seconds is not None and (time.monotonic() - start_ts) > float(time_budget_seconds):
                break
            try:
                if use_builtin:
                    if self._beautify_js_builtin(js_path):
                        success_count += 1
                else:
                    if self._beautify_js_external(js_path):
                        success_count += 1
            except Exception as exc:
                self._log(f"格式化失败 {js_path.name}: {exc}")
        
        self._log(f"格式化完成: {success_count}/{len(js_files)} 成功")
        return success_count

    def _beautify_js_builtin(self, js_path: Path) -> bool:
        """使用内置简单格式化。
        
        对于压缩的 JS 做基本的换行和缩进处理。
        """
        try:
            with open(js_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            
            # 如果文件已经格式化良好（行数较多），跳过
            lines = content.split("\n")
            avg_line_length = len(content) / max(len(lines), 1)
            if avg_line_length < 200 and len(lines) > 10:
                return True  # 已经是格式化的
            
            # 简单格式化：在 { } ; 后添加换行
            formatted = self._simple_js_format(content)
            
            # 写回文件
            with open(js_path, "w", encoding="utf-8") as f:
                f.write(formatted)
            
            return True
            
        except Exception:
            return False

    def _simple_js_format(self, code: str) -> str:
        """简单的 JS 格式化。
        
        在关键位置添加换行，便于阅读。
        """
        # 保护字符串内容
        strings: List[str] = []
        
        def protect_string(match):
            strings.append(match.group(0))
            return f"__STRING_{len(strings) - 1}__"
        
        # 匹配字符串（简化版，不处理所有边界情况）
        code = re.sub(r'"(?:[^"\\]|\\.)*"', protect_string, code)
        code = re.sub(r"'(?:[^'\\]|\\.)*'", protect_string, code)
        code = re.sub(r"`(?:[^`\\]|\\.)*`", protect_string, code)
        
        # 在 { 后添加换行
        code = re.sub(r"\{(?!\s*\n)", "{\n", code)
        # 在 } 前添加换行
        code = re.sub(r"(?<!\n)\s*\}", "\n}", code)
        # 在 ; 后添加换行（如果不是在 for 循环中）
        code = re.sub(r";(?!\s*[\n\)])", ";\n", code)
        
        # 恢复字符串
        for i, s in enumerate(strings):
            code = code.replace(f"__STRING_{i}__", s)
        
        # 简单缩进
        lines = code.split("\n")
        formatted_lines = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            
            # 减少缩进
            if stripped.startswith("}") or stripped.startswith("]") or stripped.startswith(")"):
                indent_level = max(0, indent_level - 1)
            
            formatted_lines.append("    " * indent_level + stripped)
            
            # 增加缩进
            open_count = stripped.count("{") + stripped.count("[") + stripped.count("(")
            close_count = stripped.count("}") + stripped.count("]") + stripped.count(")")
            indent_level += open_count - close_count
            indent_level = max(0, indent_level)
        
        return "\n".join(formatted_lines)

    def _beautify_js_external(self, js_path: Path) -> bool:
        """使用外部 js-beautify 工具格式化。
        
        需要先安装：npm install -g js-beautify
        """
        try:
            result = subprocess.run(
                ["js-beautify", "-r", str(js_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except FileNotFoundError:
            self._log("js-beautify 未安装，使用内置格式化")
            return self._beautify_js_builtin(js_path)
        except subprocess.TimeoutExpired:
            self._log(f"格式化超时: {js_path.name}")
            return False
        except Exception:
            return False

    def save_browser_data(self, event_type: str, data: dict) -> Optional[str]:
        """保存浏览器数据到对应的分类目录"""
        try:
            self._browser_data_count += 1
            timestamp = datetime.now().strftime("%H%M%S_%f")[:-3]  # 精确到毫秒
            
            # 根据事件类型选择存储目录和文件名
            if event_type in {"STORAGE_SNAPSHOT"} or event_type.startswith(("LOCALSTORAGE_", "SESSIONSTORAGE_", "INDEXEDDB_")):
                file_path = self._storage_dir / f"{event_type.lower()}_{timestamp}.json"
                
            elif event_type == 'USER_INTERACTION':
                file_path = self._interactions_dir / f"interaction_{timestamp}.json"
                
            elif event_type in ['FORM_INPUT', 'FORM_SUBMIT']:
                file_path = self._interactions_dir / f"form_{event_type.lower()}_{timestamp}.json"
                
            elif event_type in {"DOM_FINAL"} or event_type in ['DOM_CHANGE', 'DOM_SNAPSHOT']:
                file_path = self._dom_dir / f"dom_{event_type.lower()}_{timestamp}.json"
                
            elif event_type in ['HISTORY_PUSH', 'HISTORY_REPLACE', 'HISTORY_POP']:
                file_path = self._browser_data_dir / f"navigation_{timestamp}.json"
                
            elif event_type == 'CONSOLE_OUTPUT':
                file_path = self._browser_data_dir / f"console_{timestamp}.json"
                
            elif event_type in {"PERFORMANCE_SNAPSHOT"} or event_type in ['PERFORMANCE_NAVIGATION', 'PERFORMANCE_RESOURCE']:
                file_path = self._performance_dir / f"perf_{event_type.lower()}_{timestamp}.json"
                
            elif event_type in ['PAGE_INFO', 'INITIAL_LOCALSTORAGE', 'INITIAL_SESSIONSTORAGE']:
                file_path = self._browser_data_dir / f"initial_{event_type.lower()}_{timestamp}.json"
                
            else:
                # 未分类的数据
                file_path = self._browser_data_dir / f"other_{event_type.lower()}_{timestamp}.json"
            
            # 添加元数据
            data_with_meta = {
                "event_type": event_type,
                "timestamp": datetime.now().isoformat(),
                "data": data
            }
            
            # 保存到文件
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data_with_meta, f, indent=2, ensure_ascii=False, default=str)
            
            self._log(f"[浏览器数据] 已保存 {event_type}: {file_path.name}")
            return str(file_path.relative_to(self._session_dir))
            
        except Exception as e:
            self._log(f"保存浏览器数据失败 ({event_type}): {e}")
            return None

    def save_screenshot_info(self, reason: str, screenshot_path: str) -> Optional[str]:
        """保存截图信息到元数据文件"""
        try:
            self._screenshot_count += 1
            timestamp = datetime.now().strftime("%H%M%S_%f")[:-3]

            rel_screenshot_path = screenshot_path
            try:
                sp = Path(str(screenshot_path or ""))
                if sp.is_absolute():
                    # 只要落在 session_dir 内，就记录相对路径，保证 zip 自包含可读
                    rel_screenshot_path = str(sp.relative_to(self._session_dir)).replace("\\", "/")
            except Exception:
                rel_screenshot_path = screenshot_path
            
            screenshot_info = {
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
                "screenshot_path": rel_screenshot_path,
                "screenshot_number": self._screenshot_count
            }
            
            info_file = self._screenshots_dir / f"screenshot_{timestamp}_{reason}.json"
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(screenshot_info, f, indent=2, ensure_ascii=False)
            
            self._log(f"[截图] 已保存截图信息: {reason} -> {info_file.name}")
            return str(info_file.relative_to(self._session_dir))
            
        except Exception as e:
            self._log(f"保存截图信息失败 ({reason}): {e}")
            return None

    def get_session_statistics(self) -> dict:
        """获取会话统计信息"""
        return {
            "requests_captured": self._request_count,
            "browser_events_captured": self._browser_data_count,
            "screenshots_taken": self._screenshot_count,
            "session_duration": str(datetime.now() - self._start_time),
            "storage_size": self._calculate_directory_size(self._session_dir)
        }
    
    def _calculate_directory_size(self, directory: Path) -> str:
        """计算目录大小"""
        try:
            total_size = sum(f.stat().st_size for f in directory.rglob('*') if f.is_file())
            # 转换为人类可读格式
            for unit in ['B', 'KB', 'MB', 'GB']:
                if total_size < 1024.0:
                    return f"{total_size:.1f} {unit}"
                total_size /= 1024.0
            return f"{total_size:.1f} TB"
        except Exception:
            return "未知"
