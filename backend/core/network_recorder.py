import asyncio
import json
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .browser_manager import BrowserManager
from .js_hooks import JS_HOOK_SCRIPT, generate_hook_script
from .resource_archiver import ResourceArchiver
from models.request_record import RequestRecord


class NetworkRecorder:
    def __init__(
        self,
        browser_manager: BrowserManager,
        log_callback: Optional[Callable[[str], None]] = None,
        archiver: Optional[ResourceArchiver] = None,
        config: Optional[dict] = None,
    ) -> None:
        self._browser_manager = browser_manager
        self._records: List[RequestRecord] = []
        self._is_recording: bool = False
        self._listeners_attached: bool = False
        self._records_by_key: Dict[int, RequestRecord] = {}
        self._log = log_callback or (lambda _msg: None)
        self._archiver: Optional[ResourceArchiver] = archiver
        self._pending_response_tasks: set[asyncio.Task] = set()
        self._stopping: bool = False
        
        # 用户配置
        self._config = config or {}
        self._screenshot_enabled = self._config.get('capture_screenshots', False)
        
        # Hook 选项配置 - 处理可能的 None 或空值情况
        hook_opts = self._config.get('hook_options')
        if hook_opts is None:
            self._hook_options = {'network': True}  # 默认只开启网络请求
        elif isinstance(hook_opts, dict):
            self._hook_options = hook_opts
        else:
            # 可能是 Pydantic 模型对象，尝试转换
            self._hook_options = dict(hook_opts) if hasattr(hook_opts, '__iter__') else {'network': True}
        
        if self._screenshot_enabled:
            self._log("[OK] 截图功能已启用")
        else:
            self._log("[INFO] 截图功能已禁用（用户未勾选）")
        
        # 记录启用的 Hook 模块
        enabled_hooks = [k for k, v in self._hook_options.items() if v]
        if enabled_hooks:
            self._log(f"[INFO] 启用的 Hook 模块: {', '.join(enabled_hooks)}")
        else:
            self._log("[INFO] 未启用任何 JS Hook（纯 CDP 监听模式）")

    @property
    def is_recording(self) -> bool:
        return self._is_recording

    @property
    def records(self) -> List[RequestRecord]:
        return self._records

    def set_archiver(self, archiver: Optional[ResourceArchiver]) -> None:
        self._archiver = archiver

    async def start(self) -> None:
        if self._is_recording:
            return

        page = self._browser_manager.page
        if page is None:
            raise RuntimeError("browser page is not available")

        # 新一轮录制时清空历史记录
        self._records.clear()
        self._records_by_key.clear()
        self._pending_response_tasks.clear()
        self._stopping = False

        if not self._listeners_attached:
            self._attach_listeners(page)
            self._listeners_attached = True

        self._is_recording = True
        self._log("[INFO] 开始录制网络请求")

    async def stop(self) -> None:
        if not self._is_recording:
            return

        self._stopping = True
        self._is_recording = False
        self._log(f"[INFO] 停止录制，共捕获 {len(self._records)} 条请求")

        if self._pending_response_tasks:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 5.0

            while self._pending_response_tasks:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    self._log(
                        f"[WARNING] 停止录制：仍有 {len(self._pending_response_tasks)} 个响应处理任务未完成，已超时"
                    )
                    break

                tasks = list(self._pending_response_tasks)
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    self._log(
                        f"[WARNING] 停止录制：仍有 {len(self._pending_response_tasks)} 个响应处理任务未完成，已超时"
                    )
                    break
        self._stopping = False

    def _attach_listeners(self, page: Any) -> None:  # page: playwright.async_api.Page
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("console", self._on_console)

    # --- Playwright 事件回调 -------------------------------------------------

    def _on_request(self, request: Any) -> None:  # request: playwright.async_api.Request
        if not self._is_recording:
            return

        key = id(request)

        # 某些请求（如 data: URL）可能没有完整 header，这里做个简单保护
        try:
            headers = dict(request.headers)
        except Exception:  # noqa: BLE001
            headers = {}

        try:
            post_data = request.post_data
        except Exception:  # noqa: BLE001
            post_data = None

        record = RequestRecord(
            id=str(key),
            timestamp=time.time(),
            method=request.method,
            url=request.url,
            headers=headers,
            post_data=post_data,
            resource_type=getattr(request, "resource_type", None),
        )

        self._records.append(record)
        self._records_by_key[key] = record
        self._log(f"[REQ] {record.method} {record.url}")

    def _on_response(self, response: Any) -> None:  # response: playwright.async_api.Response
        # 需要异步获取 body，用 task 处理
        task = asyncio.create_task(self._handle_response(response))
        self._pending_response_tasks.add(task)
        task.add_done_callback(self._pending_response_tasks.discard)

    def _on_console(self, message: Any) -> None:  # message: playwright.async_api.ConsoleMessage
        text = message.text

        # 处理所有类型的Web Recorder事件
        if text.startswith("[WEB_RECORDER_"):
            self._log(text)
            if self._archiver is not None:
                self._archiver.append_hook_line(text)

            # 处理不同类型的浏览器数据
            self._process_browser_data(text)

            # 处理网络请求相关的调用栈关联
            if "FETCH_" in text or "XHR_" in text:
                self._associate_call_stack(text)

            # 处理WebSocket事件
            if "WEBSOCKET_" in text:
                self._process_websocket_event(text)

        # 保持对旧格式的兼容性
        elif text.startswith("[FETCH_HOOK]") or text.startswith("[XHR_HOOK]"):
            self._log(text)
            if self._archiver is not None:
                self._archiver.append_hook_line(text)
            self._associate_call_stack(text)

    async def _handle_response(self, response: Any) -> None:
        request = response.request
        key = id(request)
        record = self._records_by_key.get(key)
        if record is None:
            # 录制开始前的请求，其响应就忽略
            return

        try:
            headers = dict(response.headers)
        except Exception:  # noqa: BLE001
            headers = {}

        body_size: Optional[int] = None
        body: Optional[bytes] = None
        try:
            body = await response.body()
            if body is not None:
                body_size = len(body)
        except Exception:  # noqa: BLE001
            body_size = None

        record.status = response.status
        record.response_headers = headers
        record.response_size = body_size
        record.response_timestamp = time.time()

        if self._archiver is not None and body is not None:
            rel_path = self._archiver.save_response(record, body)
            record.response_body_path = rel_path

        self._log(f"[RES] {record.status} {record.url}")

    def _associate_call_stack(self, hook_text: str) -> None:
        """解析 Hook 日志，将调用栈关联到匹配的 RequestRecord。"""
        try:
            hook_url = ""
            stack = ""

            # 兼容旧格式:
            # [FETCH_HOOK] {"url": "...", "stack": "..."}
            # [XHR_HOOK] {"method": "...", "url": "...", "body": "...", "stack": "..."}
            if hook_text.startswith("[FETCH_HOOK] "):
                json_str = hook_text[len("[FETCH_HOOK] "):]
                data = json.loads(json_str)
                hook_url = data.get("url", "")
                stack = data.get("stack", "")
            elif hook_text.startswith("[XHR_HOOK] "):
                json_str = hook_text[len("[XHR_HOOK] "):]
                data = json.loads(json_str)
                hook_url = data.get("url", "")
                stack = data.get("stack", "")

            # 兼容新格式: JS_HOOK_SCRIPT 使用 console.log('[WEB_RECORDER_xxx]', JSON.stringify(payload))
            # message.text 常见形态为: [WEB_RECORDER_FETCH_START] {"timestamp":...,"url":"...","stack":"..."}
            elif hook_text.startswith("[WEB_RECORDER_"):
                import re

                match = re.match(r"\[WEB_RECORDER_([^\]]+)\]\s*(.+)", hook_text)
                if not match:
                    return
                event_type = match.group(1)
                json_str = match.group(2)
                # 只在请求发起时做关联，避免响应事件覆盖
                if event_type not in {"FETCH_START", "XHR_START"}:
                    return
                data = json.loads(json_str)
                hook_url = data.get("url", "")
                stack = data.get("stack", "")
            else:
                return

            if not hook_url or not stack:
                return

            # URL 可能是相对路径，需要标准化匹配
            # 从后往前找最近的匹配请求（Hook 通常在请求之后很快触发）
            for record in reversed(self._records):
                if record.call_stack:
                    # 已有调用栈，跳过
                    continue
                if self._url_matches(record.url, hook_url):
                    record.call_stack = stack
                    self._log(f"[STACK] 关联调用栈到: {record.url[:60]}...")
                    break
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    def _url_matches(self, record_url: str, hook_url: str) -> bool:
        """判断两个 URL 是否匹配（支持相对路径）。"""
        # 完全匹配
        if record_url == hook_url:
            return True

        # hook_url 可能是相对路径或 Request 对象
        if isinstance(hook_url, str):
            # 检查 record_url 是否以 hook_url 结尾（相对路径情况）
            if record_url.endswith(hook_url):
                return True
            # 检查路径部分是否匹配
            try:
                parsed = urlparse(record_url)
                if parsed.path and hook_url.startswith(parsed.path):
                    return True
                if hook_url.startswith("/") and parsed.path == hook_url:
                    return True
            except Exception:
                pass

        return False

    async def start_recording(self, browser_context, url: str):
        """开始录制 - 兼容同步和异步接口"""
        print(f"[INFO] 开始设置录制，目标URL: {url}")
        
        # 获取或创建页面
        if hasattr(browser_context, 'pages') and browser_context.pages:
            page = browser_context.pages[0]
            print("[OK] 使用现有页面")
        else:
            print("[INFO] 创建新页面...")
            page = await browser_context.new_page()
            print("[OK] 新页面已创建")

        # 根据配置动态生成 Hook 脚本
        try:
            target_page = getattr(page, "async_page", page)
            if hasattr(target_page, "add_init_script"):
                hook_script = generate_hook_script(self._hook_options)
                if hook_script:
                    await target_page.add_init_script(hook_script)
                    self._log("[OK] JS Hook 脚本已注入")
                else:
                    self._log("[INFO] 未注入 JS Hook（纯 CDP 监听模式）")
        except Exception as e:
            self._log(f"[WARNING] JS Hook 注入失败: {e}")
        
        # 设置页面到browser_manager（需要处理包装器）
        if hasattr(page, 'sync_page'):
            # 这是同步页面包装器
            self._browser_manager._page = page.sync_page
            print("[OK] 设置同步页面到browser_manager")
        else:
            # 这是标准异步页面
            self._browser_manager._page = page
            print("[OK] 设置异步页面到browser_manager")

        print("[INFO] 开始网络录制...")
        await self.start()
        print("[OK] 网络录制已启动")

        # 导航到目标URL - Windows下需要在原线程中执行
        print(f"[INFO] 导航到目标URL: {url}")
        
        import sys
        if sys.platform == 'win32' and hasattr(page, 'sync_page'):
            # Windows同步页面包装器，使用goto方法
            await page.goto(url, wait_until="domcontentloaded")
        else:
            # 标准异步页面
            await page.goto(url, wait_until="domcontentloaded")
            
        print(f"[OK] 已导航到: {url}")

    def _process_browser_data(self, console_text: str) -> None:
        """处理浏览器数据事件"""
        try:
            import json
            import re
            
            # 提取事件类型和数据
            match = re.match(r'\[WEB_RECORDER_([^\]]+)\]\s*(.+)', console_text)
            if not match:
                return
                
            event_type = match.group(1)
            data_str = match.group(2)
            
            try:
                data = json.loads(data_str)
            except json.JSONDecodeError:
                self._log(f"无法解析浏览器数据: {data_str}")
                return
            
            # 根据事件类型处理数据
            if event_type in ['LOCALSTORAGE_SET', 'LOCALSTORAGE_REMOVE', 'LOCALSTORAGE_CLEAR',
                             'SESSIONSTORAGE_SET', 'SESSIONSTORAGE_REMOVE', 'SESSIONSTORAGE_CLEAR',
                             'INDEXEDDB_OPEN', 'INDEXEDDB_OPENED']:
                self._process_storage_event(event_type, data)
                
            elif event_type == 'USER_INTERACTION':
                self._process_user_interaction(data)
                
            elif event_type in ['FORM_INPUT', 'FORM_SUBMIT']:
                self._process_form_event(event_type, data)
                
            elif event_type in ['DOM_CHANGE', 'DOM_SNAPSHOT']:
                self._process_dom_event(event_type, data)
                
            elif event_type in ['HISTORY_PUSH', 'HISTORY_REPLACE', 'HISTORY_POP']:
                self._process_navigation_event(event_type, data)
                
            elif event_type == 'CONSOLE_OUTPUT':
                self._process_console_event(data)
                
            elif event_type in ['PERFORMANCE_NAVIGATION', 'PERFORMANCE_RESOURCE']:
                self._process_performance_event(event_type, data)
                
            elif event_type in ['PAGE_INFO', 'INITIAL_LOCALSTORAGE', 'INITIAL_SESSIONSTORAGE']:
                self._process_initial_data(event_type, data)
                
            # 保存浏览器数据到归档器
            if self._archiver is not None:
                self._archiver.save_browser_data(event_type, data)
                
        except Exception as e:
            self._log(f"处理浏览器数据失败: {e}")
    
    def _process_storage_event(self, event_type: str, data: dict) -> None:
        """处理存储事件"""
        self._log(f"[存储] {event_type}: {data.get('key', '')}")
    
    def _process_user_interaction(self, data: dict) -> None:
        """处理用户交互事件"""
        interaction_type = data.get('type', '')
        target_info = data.get('target', {})
        self._log(f"[交互] {interaction_type} on {target_info.get('tagName', '')}#{target_info.get('id', '')}")
        
        # 在关键交互时截图
        if interaction_type in ['click', 'submit', 'dblclick']:
            self._schedule_screenshot(f"interaction_{interaction_type}")
    
    def _process_form_event(self, event_type: str, data: dict) -> None:
        """处理表单事件"""
        if event_type == 'FORM_SUBMIT':
            self._log(f"[表单] 提交到 {data.get('action', '')}")
            self._schedule_screenshot("form_submit")
        else:
            self._log(f"[表单] 输入 {data.get('name', '')}: {data.get('type', '')}")
    
    def _process_dom_event(self, event_type: str, data: dict) -> None:
        """处理DOM事件"""
        if event_type == 'DOM_SNAPSHOT':
            self._log(f"[DOM] 快照: {data.get('url', '')} ({data.get('bodyHTML', 0)} chars)")
        else:
            self._log(f"[DOM] 变化: {data.get('target', {}).get('tagName', '')}")
    
    def _process_navigation_event(self, event_type: str, data: dict) -> None:
        """处理导航事件"""
        self._log(f"[导航] {event_type}: {data.get('url', '')}")
        if event_type == 'HISTORY_PUSH':
            self._schedule_screenshot("navigation")
    
    def _process_console_event(self, data: dict) -> None:
        """处理控制台事件"""
        level = data.get('level', 'log')
        args = data.get('args', [])
        self._log(f"[控制台] {level.upper()}: {' '.join(args)}")
    
    def _process_performance_event(self, event_type: str, data: dict) -> None:
        """处理性能事件"""
        if event_type == 'PERFORMANCE_NAVIGATION':
            load_time = data.get('loadEventEnd', 0)
            self._log(f"[性能] 页面加载完成: {load_time}ms")
        else:
            name = data.get('name', '')
            duration = data.get('duration', 0)
            self._log(f"[性能] 资源 {name}: {duration}ms")
    
    def _process_initial_data(self, event_type: str, data: dict) -> None:
        """处理初始数据快照"""
        if event_type == 'PAGE_INFO':
            self._log(f"[页面] {data.get('title', '')} - {data.get('url', '')}")
            self._schedule_screenshot("page_load")
        else:
            storage_type = event_type.replace('INITIAL_', '').lower()
            count = len(data) if isinstance(data, dict) else 0
            self._log(f"[初始] {storage_type}: {count} 项")
    
    def _should_take_screenshot(self, record) -> bool:
        """判断是否需要截图"""
        # 对于API请求和重要资源截图
        if record.resource_type in ['xhr', 'fetch']:
            return True
        if record.url.endswith(('.json', '.api')):
            return True
        return False
    
    def _schedule_screenshot(self, reason: str) -> None:
        """安排截图"""
        try:
            # 检查用户是否启用截图功能
            if not self._screenshot_enabled:
                return
                
            if hasattr(self._browser_manager, 'take_screenshot'):
                # 异步执行截图，避免阻塞
                import asyncio
                asyncio.create_task(self._take_screenshot_async(reason))
        except Exception as e:
            self._log(f"截图安排失败: {e}")
    
    async def _take_screenshot_async(self, reason: str) -> None:
        """异步截图"""
        try:
            if hasattr(self._browser_manager, 'take_screenshot'):
                screenshot_path = await self._browser_manager.take_screenshot(reason)
                if screenshot_path and self._archiver:
                    self._archiver.save_screenshot_info(reason, screenshot_path)
                    self._log(f"截图保存: {reason} -> {screenshot_path}")
        except Exception as e:
            self._log(f"截图失败 ({reason}): {e}")

    def _process_websocket_event(self, console_text: str) -> None:
        """处理WebSocket事件"""
        try:
            import json
            import re

            match = re.match(r'\[WEB_RECORDER_([^\]]+)\]\s*(.+)', console_text)
            if not match:
                return

            event_type = match.group(1)
            data_str = match.group(2)

            try:
                data = json.loads(data_str)
            except json.JSONDecodeError:
                self._log(f"无法解析WebSocket数据: {data_str}")
                return

            # 记录WebSocket事件
            if event_type == 'WEBSOCKET_CONNECT':
                self._log(f"[WebSocket] 连接: {data.get('url', '')}")
            elif event_type == 'WEBSOCKET_OPEN':
                self._log(f"[WebSocket] 已打开: {data.get('url', '')}")
            elif event_type == 'WEBSOCKET_MESSAGE':
                direction = data.get('direction', '')
                size = data.get('size', 0)
                self._log(f"[WebSocket] 消息 {direction}: {size} bytes")
            elif event_type == 'WEBSOCKET_CLOSE':
                code = data.get('code', '')
                reason = data.get('reason', '')
                self._log(f"[WebSocket] 关闭: code={code}, reason={reason}")
            elif event_type == 'WEBSOCKET_ERROR':
                self._log(f"[WebSocket] 错误: {data.get('url', '')}")

            # 保存到归档器
            if self._archiver is not None:
                self._archiver.save_browser_data(event_type, data)

        except Exception as e:
            self._log(f"处理WebSocket事件失败: {e}")
