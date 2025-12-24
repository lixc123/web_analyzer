import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# 导入现有业务逻辑模块 (零修改复用)
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from core.network_recorder import NetworkRecorder
from core.browser_manager import BrowserManager  
from core.resource_archiver import ResourceArchiver
from models.request_record import RequestRecord
import utils.file_helper as file_helper

from ..config import settings
from ..database import HybridStorage
from ..websocket import manager
from .cache_service import get_cache_service

logger = logging.getLogger(__name__)

class RecorderService:
    """
    网络录制服务 - 封装现有NetworkRecorder等业务逻辑
    提供FastAPI兼容的异步接口，同时保持100%功能一致性
    使用单例模式确保会话状态在所有API调用间共享
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RecorderService, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        # 防止重复初始化
        if RecorderService._initialized:
            return
            
        self.cache_service = get_cache_service()
        self.active_sessions: Dict[str, Dict] = {}
        self.session_recorders: Dict[str, NetworkRecorder] = {}
        self.browser_managers: Dict[str, BrowserManager] = {}
        self.session_archivers: Dict[str, ResourceArchiver] = {}

        self._realtime_tasks: Dict[str, asyncio.Task] = {}
        self._realtime_sent_counts: Dict[str, int] = {}
        
        # 确保数据目录存在
        os.makedirs(settings.data_dir, exist_ok=True)
        
        RecorderService._initialized = True
        logger.info("RecorderService单例实例已创建")

    def _serialize_request_for_api(self, request: Any, session_id: str) -> Dict:
        if isinstance(request, dict):
            request_dict = request.copy()
            request_dict["session_id"] = session_id
            return request_dict

        if hasattr(request, 'to_dict'):
            request_dict = request.to_dict()
            request_dict["session_id"] = session_id
            return request_dict

        if hasattr(request, '__dict__'):
            request_dict = {
                key: value for key, value in request.__dict__.items()
                if not key.startswith('_') and isinstance(value, (str, int, float, bool, list, dict, type(None)))
            }
            request_dict["session_id"] = session_id
            return request_dict

        return {"session_id": session_id, "raw": str(request)}

    def _filter_requests(
        self,
        requests: List[Dict],
        q: Optional[str] = None,
        resource_type: Optional[str] = None,
        method: Optional[str] = None,
        status: Optional[int] = None,
    ) -> List[Dict]:
        filtered = requests

        if q:
            q_lower = q.lower()
            filtered = [r for r in filtered if q_lower in str(r.get("url", "")).lower()]

        if resource_type:
            filtered = [r for r in filtered if r.get("resource_type") == resource_type]

        if method:
            filtered = [r for r in filtered if str(r.get("method", "")).upper() == method.upper()]

        if status is not None:
            filtered = [r for r in filtered if (r.get("status") if r.get("status") is not None else r.get("status_code")) == status]

        return filtered

    def _ensure_realtime_task(self, session_id: str) -> None:
        existing = self._realtime_tasks.get(session_id)
        if existing and not existing.done():
            return
        self._realtime_sent_counts[session_id] = 0
        self._realtime_tasks[session_id] = asyncio.create_task(self._push_realtime_updates(session_id))
        logger.info(f"启动实时推送任务: {session_id}")

    async def _cancel_realtime_task(self, session_id: str) -> None:
        task = self._realtime_tasks.pop(session_id, None)
        self._realtime_sent_counts.pop(session_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            logger.info(f"已取消实时推送任务: {session_id}")

    async def _push_realtime_updates(self, session_id: str) -> None:
        while True:
            session = self.active_sessions.get(session_id)
            recorder = self.session_recorders.get(session_id)
            browser_manager = self.browser_managers.get(session_id)

            if not session or not recorder:
                logger.info(f"实时推送退出(会话或录制器不存在): {session_id}")
                return
            if session.get("status") not in {"starting", "running"}:
                logger.info(f"实时推送退出(状态为{session.get('status')}): {session_id}")
                return

            try:
                if browser_manager and getattr(browser_manager, "page", None) is not None:
                    try:
                        session["current_url"] = browser_manager.page.url
                    except Exception:
                        pass

                records = recorder.records
                sent_count = self._realtime_sent_counts.get(session_id, 0)
                new_records = records[sent_count:]
                self._realtime_sent_counts[session_id] = len(records)

                recent_requests = [
                    self._serialize_request_for_api(r, session_id)
                    for r in new_records[-20:]
                ]

                total_requests = len(records)
                completed_requests = len([r for r in records if getattr(r, "status", None) is not None])

                progress_data = {
                    "session_id": session_id,
                    "status": session.get("status"),
                    "current_url": session.get("current_url"),
                    "total_requests": total_requests,
                    "completed_requests": completed_requests,
                    "recent_requests": recent_requests,
                    "timestamp": datetime.now().isoformat(),
                }

                await manager.send_crawler_progress(progress_data)

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.warning(f"实时推送失败 {session_id}: {e}")
                return

            await asyncio.sleep(1)
    
    async def create_session(self, url: str, session_name: Optional[str] = None, config: Dict = None) -> str:
        """创建新的爬虫会话"""
        # 使用时间戳格式作为session_id，确保与目录命名一致
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        session_id = f"session_{timestamp}"
        
        session_data = {
            "session_id": session_id,
            "session_name": session_name or session_id,
            "url": url,
            "config": config or {},
            "status": "created",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "total_requests": 0,
            "completed_requests": 0,
            "errors": [],
            "progress": {}
        }
        
        self.active_sessions[session_id] = session_data
        
        # 初始化BrowserManager (直接使用现有类)
        browser_manager = BrowserManager()
        self.browser_managers[session_id] = browser_manager
        
        # 创建会话资源存储目录并初始化ResourceArchiver
        sessions_base_dir = Path(settings.data_dir) / "sessions"
        archiver = ResourceArchiver(
            base_output_dir=sessions_base_dir,
            log_callback=lambda msg: logger.info(f"[ResourceArchiver] {msg}"),
            session_id=session_id,
        )
        archiver.set_start_url(url)
        self.session_archivers[session_id] = archiver
        
        # Create fresh instances for each session with proper config
        config = session_data["config"]
        recorder = NetworkRecorder(
            browser_manager=browser_manager,
            log_callback=lambda msg: print(f" [录制] {msg}"),
            archiver=archiver,
            config=config  # 传递用户配置
        )
        
        # 存储录制器到字典中
        self.session_recorders[session_id] = recorder
        
        logger.info(f"创建会话 {session_id}: {url} (截图功能: {'启用' if config.get('capture_screenshots', False) else '禁用'})")
        return session_id
    
    async def start_recording(self, session_id: str):
        """启动网络录制"""
        if session_id not in self.active_sessions:
            raise ValueError(f"会话 {session_id} 不存在")
        
        session = self.active_sessions[session_id]
        recorder = self.session_recorders[session_id]
        browser_manager = self.browser_managers[session_id]
        archiver = self.session_archivers.get(session_id)
        
        try:
            # 更新会话状态
            session["status"] = "starting"
            session["updated_at"] = datetime.now().isoformat()

            # 确保会话在内存中可见，并尽早启动实时推送（不要等待 page.goto 完成）
            self.active_sessions[session_id] = session
            self._ensure_realtime_task(session_id)
            
            # 🟢 使用现有BrowserManager启动浏览器 - 直接调用async方法
            config = session["config"]
            browser_context = await browser_manager.create_browser_context(
                config.get("headless", True),
                config.get("user_agent"),
                config.get("timeout", 30)
            )

            # 确保录制器已经绑定 archiver（用于响应落盘、hook落盘、浏览器数据落盘）
            if archiver is not None:
                recorder.set_archiver(archiver)
                try:
                    if hasattr(browser_manager, "set_screenshot_directory"):
                        browser_manager.set_screenshot_directory(str(archiver.session_dir / "screenshots"))
                except Exception:
                    pass
            
            # 🟢 使用现有NetworkRecorder开始录制 - 直接调用async方法
            await recorder.start_recording(browser_context, session["url"])
            
            # 设置当前URL用于实时预览
            session["current_url"] = session["url"]
            
            # 更新会话状态并确保存储
            session["status"] = "running"
            session["updated_at"] = datetime.now().isoformat()
            
            # 确保会话在内存中正确存储
            self.active_sessions[session_id] = session

            self._ensure_realtime_task(session_id)
            
            logger.info(f"会话 {session_id} 开始录制，当前活动会话数: {len(self.active_sessions)}")
            logger.info(f"活动会话列表: {list(self.active_sessions.keys())}")
            
        except Exception as e:
            session["status"] = "failed"
            session["errors"].append(str(e))
            logger.error(f"启动录制失败 {session_id}: {e}")
            raise
    
    async def stop_recording(self, session_id: str):
        """停止网络录制"""
        if session_id not in self.active_sessions:
            raise ValueError(f"会话 {session_id} 不存在")
        
        session = self.active_sessions[session_id]
        recorder = self.session_recorders.get(session_id)
        browser_manager = self.browser_managers.get(session_id)
        archiver = self.session_archivers.get(session_id)
        
        try:
            # 🟢 使用现有NetworkRecorder停止录制 - 直接调用async方法
            if recorder:
                await recorder.stop()

            # 录制停止后，尽可能抓取并保存 JS 资源（即使部分脚本从缓存导致 response.body 为空也能补全）
            if archiver is not None and browser_manager and getattr(browser_manager, "page", None) is not None:
                try:
                    await archiver.save_js_resources(browser_manager.page)
                    archiver.beautify_js_files(use_builtin=True)
                except Exception as e:
                    logger.warning(f"保存JS资源失败 {session_id}: {e}")
                page = getattr(browser_manager, "page", None)
                if page is not None:
                    try:
                        storage_snapshot = await page.evaluate(
                            """() => {
                                const ls = {};
                                const ss = {};
                                try {
                                    for (let i = 0; i < localStorage.length; i++) {
                                        const k = localStorage.key(i);
                                        ls[k] = localStorage.getItem(k);
                                    }
                                } catch (e) {}
                                try {
                                    for (let i = 0; i < sessionStorage.length; i++) {
                                        const k = sessionStorage.key(i);
                                        ss[k] = sessionStorage.getItem(k);
                                    }
                                } catch (e) {}
                                return { url: location.href, localStorage: ls, sessionStorage: ss };
                            }"""
                        )
                        archiver.save_browser_data("STORAGE_SNAPSHOT", storage_snapshot)
                    except Exception as e:
                        logger.warning(f"导出storage快照失败 {session_id}: {e}")

                    try:
                        perf_snapshot = await page.evaluate(
                            """() => {
                                try {
                                    const nav = performance.getEntriesByType('navigation') || [];
                                    const res = performance.getEntriesByType('resource') || [];
                                    return {
                                        url: location.href,
                                        navigation: nav.map(n => ({
                                            name: n.name,
                                            startTime: n.startTime,
                                            duration: n.duration,
                                            domContentLoadedEventEnd: n.domContentLoadedEventEnd,
                                            loadEventEnd: n.loadEventEnd,
                                            responseEnd: n.responseEnd,
                                            domComplete: n.domComplete
                                        })),
                                        resources: res.map(r => ({
                                            name: r.name,
                                            initiatorType: r.initiatorType,
                                            startTime: r.startTime,
                                            duration: r.duration,
                                            transferSize: r.transferSize,
                                            encodedBodySize: r.encodedBodySize,
                                            decodedBodySize: r.decodedBodySize
                                        }))
                                    };
                                } catch (e) {
                                    return { error: String(e) };
                                }
                            }"""
                        )
                        archiver.save_browser_data("PERFORMANCE_SNAPSHOT", perf_snapshot)
                    except Exception as e:
                        logger.warning(f"导出performance快照失败 {session_id}: {e}")

                    try:
                        dom_snapshot = await page.evaluate(
                            """() => {
                                try {
                                    const html = document.documentElement ? document.documentElement.outerHTML : '';
                                    return { url: location.href, title: document.title, html: html, length: html.length };
                                } catch (e) {
                                    return { error: String(e) };
                                }
                            }"""
                        )
                        if isinstance(dom_snapshot, dict) and isinstance(dom_snapshot.get("html"), str):
                            if len(dom_snapshot["html"]) > 1000000:
                                dom_snapshot["html"] = dom_snapshot["html"][:1000000]
                                dom_snapshot["truncated"] = True
                        archiver.save_browser_data("DOM_FINAL", dom_snapshot)
                    except Exception as e:
                        logger.warning(f"导出DOM快照失败 {session_id}: {e}")

                try:
                    storage_state_path = archiver.session_dir / "browser_data" / "storage" / "storage_state.json"
                    await browser_manager.export_storage_state(storage_state_path)
                    try:
                        legacy_path = archiver.session_dir / "browser_data" / "storage_state.json"
                        legacy_path.write_text(storage_state_path.read_text(encoding="utf-8"), encoding="utf-8")
                    except Exception:
                        pass
                except Exception as e:
                    logger.warning(f"导出storage_state失败 {session_id}: {e}")

            # 生成 metadata / har / requests.json（基于 RequestRecord，包含 response_body_path 等）
            if archiver is not None and recorder:
                try:
                    archiver.save_requests(recorder.records)
                    archiver.save_metadata(recorder.records)
                    archiver.save_har(recorder.records)
                except Exception as e:
                    logger.warning(f"导出会话文件失败 {session_id}: {e}")

            # 生成可执行 Python 回放代码
            if archiver is not None:
                try:
                    from core.code_generator import generate_code_from_session, generate_per_request_scripts

                    replay_code = generate_code_from_session(archiver.session_dir)
                    replay_path = archiver.session_dir / "replay_session.py"
                    with open(replay_path, "w", encoding="utf-8") as f:
                        f.write(replay_code)
                    logger.info(f"已生成回放代码: {replay_path}")
                    try:
                        generate_per_request_scripts(archiver.session_dir)
                    except Exception as e:
                        logger.warning(f"生成逐请求脚本失败 {session_id}: {e}")
                except Exception as e:
                    logger.warning(f"生成回放代码失败 {session_id}: {e}")
            
            # 🟢 使用现有BrowserManager关闭浏览器 - 直接调用async方法
            if browser_manager:
                await browser_manager.close()

            session["status"] = "completed"
            session["updated_at"] = datetime.now().isoformat()
            self.active_sessions[session_id] = session

            await self._cancel_realtime_task(session_id)

            # 保存录制结果到JSON文件 (保持现有格式)
            await self._save_session_data(session_id)
            
            logger.info(f"会话 {session_id} 停止录制，当前活动会话数: {len(self.active_sessions)}")
            logger.info(f"活动会话列表: {list(self.active_sessions.keys())}")
            
        except Exception as e:
            session["status"] = "failed"
            session["errors"].append(str(e))
            logger.error(f"停止录制失败 {session_id}: {e}")
            raise
    
    async def get_session_status(self, session_id: str) -> Dict:
        """获取会话状态"""
        if session_id not in self.active_sessions:
            raise ValueError(f"会话 {session_id} 不存在")
        
        session = self.active_sessions[session_id]
        recorder = self.session_recorders.get(session_id)
        
        # 🟢 获取现有NetworkRecorder的录制进度 - 使用可用的属性
        if recorder:
            try:
                records = recorder.records
                total_requests = len(records)
                completed_requests = len([r for r in records if r.status is not None])
                
                progress = {
                    "total_requests": total_requests,
                    "completed_requests": completed_requests,
                    "is_recording": recorder.is_recording
                }
                session["progress"] = progress
                session["total_requests"] = total_requests
                session["completed_requests"] = completed_requests
                session["updated_at"] = datetime.now().isoformat()
                
                logger.info(f"会话 {session_id} 进度更新: {completed_requests}/{total_requests}, 录制状态: {recorder.is_recording}")
            except Exception as e:
                logger.warning(f"获取进度失败 {session_id}: {e}")
                # 设置默认值避免0/0显示
                session["total_requests"] = session.get("total_requests", 0) 
                session["completed_requests"] = session.get("completed_requests", 0)
        else:
            # 没有recorder时使用已有数据或默认值
            session["total_requests"] = session.get("total_requests", 0)
            session["completed_requests"] = session.get("completed_requests", 0)
        
        return session.copy()
    
    async def list_sessions(self) -> List[Dict]:
        """列出所有会话"""
        sessions_by_id: Dict[str, Dict] = {}

        for session_id, session_data in self.active_sessions.items():
            sessions_by_id[session_id] = session_data.copy()

        try:
            sessions_file = HybridStorage.get_sessions_json_path()
            HybridStorage.ensure_sessions_json_exists()
            historical_sessions = HybridStorage.load_json_data(sessions_file)
            if historical_sessions:
                for s in historical_sessions:
                    sid = s.get("session_id")
                    if sid and sid not in sessions_by_id:
                        sessions_by_id[sid] = s
        except Exception as e:
            logger.warning(f"加载历史会话失败: {e}")

        sessions_list = list(sessions_by_id.values())

        try:
            from core.code_generator import generate_per_request_scripts

            sessions_base_dir = Path(settings.data_dir) / "sessions"
            for s in sessions_list:
                sid = (s.get("session_id") or s.get("session_name") or "").strip()
                if not sid:
                    continue

                safe_sid = Path(sid).name
                session_dir = sessions_base_dir / safe_sid
                if not session_dir.exists() or not session_dir.is_dir():
                    continue

                requests_file = session_dir / "requests.json"
                if not requests_file.exists():
                    continue

                out_py = session_dir / "requests_py"
                out_js = session_dir / "requests_js"
                try:
                    py_count = len(list(out_py.glob("*.py"))) if out_py.exists() else 0
                    js_count = len(list(out_js.glob("*.js"))) if out_js.exists() else 0
                except Exception:
                    py_count = 0
                    js_count = 0

                if py_count <= 1 and js_count <= 1:
                    try:
                        generate_per_request_scripts(session_dir)
                    except Exception as e:
                        logger.warning(f"补生成逐请求脚本失败 {safe_sid}: {e}")
        except Exception as e:
            logger.warning(f"逐请求脚本自愈检查失败: {e}")

        def _sort_key(s: Dict) -> tuple:
            created_raw = s.get("created_at") or s.get("updated_at") or ""
            sid = s.get("session_id") or s.get("session_name") or ""

            dt = None
            if isinstance(created_raw, str) and created_raw:
                try:
                    dt = datetime.fromisoformat(created_raw)
                except Exception:
                    dt = None

            if dt is None and isinstance(sid, str) and sid.startswith("session_"):
                try:
                    ts = sid[len("session_"):]
                    dt = datetime.strptime(ts, "%Y%m%d_%H%M%S")
                except Exception:
                    dt = None

            if dt is None:
                dt = datetime.min

            return (dt, str(sid))

        sessions_list.sort(key=_sort_key, reverse=True)
        return sessions_list
    
    async def get_session_requests(self, session_id: str, offset: int = 0, limit: int = 100) -> List[Dict]:
        """获取会话的请求记录"""
        session = self.active_sessions.get(session_id)
        recorder = self.session_recorders.get(session_id)
        if session and recorder and session.get("status") in {"starting", "running"}:
            serialized_requests = []
            for request in recorder.records:
                if isinstance(request, dict):
                    request_dict = request.copy()
                    request_dict["session_id"] = session_id
                    serialized_requests.append(request_dict)
                elif hasattr(request, 'to_dict'):
                    request_dict = request.to_dict()
                    request_dict["session_id"] = session_id
                    serialized_requests.append(request_dict)
                elif hasattr(request, '__dict__'):
                    request_dict = {
                        key: value for key, value in request.__dict__.items()
                        if not key.startswith('_') and isinstance(value, (str, int, float, bool, list, dict, type(None)))
                    }
                    request_dict["session_id"] = session_id
                    serialized_requests.append(request_dict)

            return serialized_requests[offset:offset + limit]

        # 🟢 优先从session级别存储读取数据
        session_requests = HybridStorage.load_session_requests(session_id)
        
        if session_requests:
            return session_requests[offset:offset + limit]
        
        # 🟢 向后兼容：如果session级别没有数据，尝试从全局requests.json读取
        requests_file = HybridStorage.get_requests_json_path()
        
        if not os.path.exists(requests_file):
            return []

        try:
            with open(requests_file, 'r', encoding='utf-8') as f:
                all_requests = json.load(f)

            session_requests = [
                req for req in all_requests
                if req.get("session_id") == session_id
            ]

            return session_requests[offset:offset + limit]

        except Exception as e:
            logger.error(f"读取请求数据失败: {e}")
            return []

    async def get_session_requests_page(
        self,
        session_id: str,
        offset: int = 0,
        limit: int = 100,
        q: Optional[str] = None,
        resource_type: Optional[str] = None,
        method: Optional[str] = None,
        status: Optional[int] = None,
    ) -> Dict:
        """获取会话请求分页数据（包含 total）"""
        session = self.active_sessions.get(session_id)
        recorder = self.session_recorders.get(session_id)

        if session and recorder and session.get("status") in {"starting", "running"}:
            all_requests = [self._serialize_request_for_api(r, session_id) for r in recorder.records]
            filtered = self._filter_requests(all_requests, q=q, resource_type=resource_type, method=method, status=status)
            total = len(filtered)
            return {
                "session_id": session_id,
                "requests": filtered[offset:offset + limit],
                "total": total,
                "offset": offset,
                "limit": limit,
            }

        # 🟢 优先从session级别存储读取数据
        session_requests = HybridStorage.load_session_requests(session_id)
        
        if not session_requests:
            # 🟢 向后兼容：如果session级别没有数据，尝试从全局requests.json读取
            requests_file = HybridStorage.get_requests_json_path()
            if os.path.exists(requests_file):
                try:
                    with open(requests_file, 'r', encoding='utf-8') as f:
                        all_requests = json.load(f)
                    session_requests = [
                        req for req in all_requests
                        if req.get("session_id") == session_id
                    ]
                except Exception as e:
                    logger.error(f"读取全局requests.json失败: {e}")
                    session_requests = []
        
        if not session_requests:
            return {
                "session_id": session_id,
                "requests": [],
                "total": 0,
                "offset": offset,
                "limit": limit,
            }

        filtered = self._filter_requests(session_requests, q=q, resource_type=resource_type, method=method, status=status)
        total = len(filtered)
        return {
            "session_id": session_id,
            "requests": filtered[offset:offset + limit],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    async def get_all_session_requests(self, session_id: str) -> List[Dict]:
        """获取会话全部请求（用于索引/分析等场景）"""
        session = self.active_sessions.get(session_id)
        recorder = self.session_recorders.get(session_id)

        if session and recorder and session.get("status") in {"starting", "running"}:
            return [self._serialize_request_for_api(r, session_id) for r in recorder.records]

        # 🟢 优先从session级别存储读取数据
        session_requests = HybridStorage.load_session_requests(session_id)
        
        if session_requests:
            return session_requests
        
        # 🟢 向后兼容：如果session级别没有数据，尝试从全局requests.json读取
        requests_file = HybridStorage.get_requests_json_path()
        if not os.path.exists(requests_file):
            return []

        try:
            with open(requests_file, 'r', encoding='utf-8') as f:
                all_requests = json.load(f)

            return [
                req for req in all_requests
                if req.get("session_id") == session_id
            ]

        except Exception as e:
            logger.error(f"读取全部请求数据失败: {e}")
            return []
    
    async def delete_session(self, session_id: str):
        """删除会话"""
        try:
            logger.info(f"开始删除会话: {session_id}")
            
            # 先停止录制（如果正在运行）
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                if session.get("status") == "running":
                    try:
                        await self.stop_recording(session_id)
                        logger.info(f"已停止运行中的会话: {session_id}")
                    except Exception as e:
                        logger.warning(f"停止会话时出错: {e}")
            
            # 清理内存中的会话数据
            self.active_sessions.pop(session_id, None)
            self.session_recorders.pop(session_id, None)  
            self.browser_managers.pop(session_id, None)
            await self._cancel_realtime_task(session_id)
            logger.info(f"已清理内存中的会话数据: {session_id}")
            
            # 删除持久化存储中的会话数据
            try:
                # 删除sessions.json中的会话记录
                sessions_file = HybridStorage.get_sessions_json_path()
                sessions = HybridStorage.load_json_data(sessions_file)
                if sessions:
                    # 过滤掉要删除的会话
                    sessions = [s for s in sessions if s.get("session_id") != session_id]
                    HybridStorage.save_json_data(sessions_file, sessions)
                    logger.info(f"已从sessions.json删除会话: {session_id}")
                
                # 删除requests.json中的相关请求记录  
                requests_file = HybridStorage.get_requests_json_path()
                requests = HybridStorage.load_json_data(requests_file)
                if requests:
                    # 过滤掉该会话的所有请求
                    original_count = len(requests)
                    requests = [r for r in requests if r.get("session_id") != session_id]
                    deleted_count = original_count - len(requests)
                    HybridStorage.save_json_data(requests_file, requests)
                    logger.info(f"已从requests.json删除 {deleted_count} 个请求记录")
                
            except Exception as e:
                logger.error(f"删除持久化数据失败: {e}")
                # 继续执行，不要因为文件操作失败而中断
            
            # 清理缓存
            try:
                await self.cache_service.invalidate_session_cache(session_id)
            except Exception as e:
                logger.warning(f"清理缓存失败: {e}")
            
            logger.info(f"会话 {session_id} 删除完成")
            
        except Exception as e:
            logger.error(f"删除会话 {session_id} 失败: {e}")
            raise RuntimeError(f"删除会话失败: {str(e)}")
    
    async def export_session(self, session_id: str, format: str = "json") -> Any:
        """导出会话数据"""
        requests = await self.get_all_session_requests(session_id)
        session_info = self.active_sessions.get(session_id, {})
        
        export_data = {
            "session_info": session_info,
            "requests": requests,
            "export_time": datetime.now().isoformat(),
            "format": format
        }
        
        if format == "json":
            return export_data
        elif format == "csv":
            return await self._export_to_csv(requests)
        elif format == "har":
            # 🟢 使用现有HAR导出功能 (如果已实现)
            return await self._export_to_har(requests)
        else:
            raise ValueError(f"不支持的导出格式: {format}")
    
    async def _save_session_data(self, session_id: str):
        """保存会话数据到持久化存储"""
        recorder = self.session_recorders.get(session_id)
        
        if not recorder:
            return
        
        try:
            # 🟢 获取现有NetworkRecorder的录制结果 - 使用records属性
            recorded_requests = recorder.records
            
            # 🟢 保存到session级别的requests.json文件
            # 序列化请求记录（session_id在session级别存储中不再需要）
            serialized_requests = []
            for request in recorded_requests:
                try:
                    if isinstance(request, dict):
                        request_dict = request.copy()
                        serialized_requests.append(request_dict)
                    elif hasattr(request, 'to_dict'):
                        request_dict = request.to_dict()
                        serialized_requests.append(request_dict)
                    elif hasattr(request, '__dict__'):
                        # 处理对象类型，转换为字典
                        request_dict = {
                            key: value for key, value in request.__dict__.items()
                            if not key.startswith('_') and isinstance(value, (str, int, float, bool, list, dict, type(None)))
                        }
                        serialized_requests.append(request_dict)
                    else:
                        # 跳过无法序列化的对象
                        logger.warning(f"跳过无法序列化的请求对象: {type(request)}")
                        continue
                except Exception as e:
                    logger.warning(f"序列化请求失败，跳过: {e}")
                    continue
            
            # 覆盖保存到 session 级别 requests.json，避免重复追加导致同一会话数据膨胀
            # 如需增量保存，应由调用方明确实现（目前 stop_recording 会保存最终结果）
            HybridStorage.save_session_requests(session_id, serialized_requests)
            
            # 保存会话元数据
            sessions_file = HybridStorage.get_sessions_json_path()
            HybridStorage.ensure_sessions_json_exists()
            sessions = HybridStorage.load_json_data(sessions_file)
            
            # 添加或更新当前会话
            session_data = self.active_sessions[session_id].copy()
            # 确保会话数据可以序列化
            for key, value in session_data.items():
                if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                    session_data[key] = str(value)
            
            if not isinstance(sessions, list):
                sessions = []
            sessions = [s for s in sessions if s.get("session_id") != session_id]
            sessions.append(session_data)
            
            HybridStorage.save_json_data(sessions_file, sessions)
            
            logger.info(f"会话数据已保存到session级别存储: {session_id}")
            
        except Exception as e:
            logger.error(f"保存会话数据失败 {session_id}: {e}")
            raise
    
    async def _export_to_csv(self, requests: List[Dict]) -> str:
        """导出为CSV格式"""
        import csv
        import io
        
        output = io.StringIO()
        
        if not requests:
            return ""
        
        # 获取所有字段名
        fieldnames = set()
        for req in requests:
            fieldnames.update(req.keys())
        
        writer = csv.DictWriter(output, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(requests)
        
        return output.getvalue()
    
    async def _export_to_har(self, requests: List[Dict]) -> Dict:
        """导出为HAR格式"""
        # 🟢 使用现有har_exporter模块 (如果存在)
        try:
            from core.har_exporter import HarExporter
            exporter = HarExporter()
            return await asyncio.get_event_loop().run_in_executor(
                None,
                exporter.export_to_har,
                requests
            )
        except ImportError:
            # 如果HAR导出器不存在，返回基本格式
            return {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "Web Analyzer V2", "version": "2.0.0"},
                    "entries": requests
                }
            }
