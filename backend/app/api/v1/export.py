from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse

from backend.app.services.analysis_bundle_service import AnalysisBundleBuilder, generate_analysis_session_id


router = APIRouter()


@router.get("/analysis-bundle")
async def download_analysis_bundle(
    background_tasks: BackgroundTasks,
    analysis_session_id: Optional[str] = None,
    proxy_session_id: List[str] = Query(default=[]),
    crawler_session_id: List[str] = Query(default=[]),
    hook_session_id: List[str] = Query(default=[]),
    include_proxy_artifacts: bool = True,
    auto: bool = True,
):
    """一键导出 AI 分析包（zip）。

    - 可显式传入 session id（支持多值 query）
    - 也可 auto=true：缺省时自动选择“当前活跃/最近”的会话（best-effort）
    """
    try:
        resolved_analysis_id = analysis_session_id or generate_analysis_session_id()

        resolved_proxy_ids = list(proxy_session_id or [])
        resolved_crawler_ids = list(crawler_session_id or [])
        resolved_hook_ids = list(hook_session_id or [])

        if auto:
            # proxy: current session
            if not resolved_proxy_ids:
                try:
                    from backend.proxy.service_manager import ProxyServiceManager

                    cur = ProxyServiceManager.get_instance().get_proxy_session_id()
                    if cur:
                        resolved_proxy_ids.append(str(cur))
                except Exception:
                    pass

            # crawler: most recent session in sessions.json (best-effort)
            if not resolved_crawler_ids:
                try:
                    from backend.app.services.shared_recorder import get_recorder_service

                    svc = get_recorder_service()
                    sessions = await svc.list_sessions()
                    if sessions:
                        # first one is newest due to sort in list_sessions()
                        sid = sessions[0].get("session_id")
                        if sid:
                            resolved_crawler_ids.append(str(sid))
                except Exception:
                    pass

            # hook: most recent session (best-effort)
            if not resolved_hook_ids:
                try:
                    from backend.app.services.hook_storage import HookStorage

                    hs = HookStorage()
                    sessions, _total = hs.list_sessions(limit=1, offset=0)
                    if sessions:
                        sid = sessions[0].get("session_id")
                        if sid:
                            resolved_hook_ids.append(str(sid))
                except Exception:
                    pass

        if not (resolved_proxy_ids or resolved_crawler_ids or resolved_hook_ids):
            raise HTTPException(status_code=400, detail="未指定任何会话（proxy/crawler/hook），且 auto 未能发现可用会话")

        builder = AnalysisBundleBuilder()
        zip_path = builder.build_zip(
            analysis_session_id=resolved_analysis_id,
            proxy_session_ids=resolved_proxy_ids,
            crawler_session_ids=resolved_crawler_ids,
            hook_session_ids=resolved_hook_ids,
            include_proxy_artifacts=include_proxy_artifacts,
        )

        background_tasks.add_task(lambda p: os.path.exists(p) and os.remove(p), str(zip_path))
        return FileResponse(
            path=str(zip_path),
            media_type="application/zip",
            filename=f"{Path(resolved_analysis_id).name}.zip",
        )
    except HTTPException:
        raise
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导出分析包失败: {e}")

