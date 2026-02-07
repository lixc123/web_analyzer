"""
命令处理API - Web版本qwen-code命令系统
实现/clear, /stats, /model, /help等30+命令功能
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import json
import os
import fnmatch
from ...services.auth_service import AuthService
from ...services.session_service import SessionService
from ...services.command_service import CommandService, CommandResult
from ...config import PROJECT_ROOT

router = APIRouter()

class ExecuteCommandRequest(BaseModel):
    command: str
    args: List[str] = []
    session_id: Optional[str] = None

class CommandResponse(BaseModel):
    success: bool
    result: Any
    message: str
    command_type: str

def get_command_service():
    return CommandService()

def get_auth_service():
    return AuthService()

def get_session_service():
    return SessionService()

@router.post("/execute", response_model=CommandResponse)
async def execute_command(
    request: ExecuteCommandRequest,
    command_service: CommandService = Depends(get_command_service),
    auth_service: AuthService = Depends(get_auth_service),
    session_service: SessionService = Depends(get_session_service)
):
    """执行Web命令"""
    try:
        # 验证认证状态
        if request.session_id:
            auth_state = auth_service.get_auth_session(request.session_id)
            if not auth_state:
                raise HTTPException(status_code=401, detail="未认证")
        else:
            auth_state = None

        # 执行命令
        result = await command_service.execute_command(
            command=request.command,
            args=request.args,
            auth_state=auth_state,
            session_service=session_service
        )

        return CommandResponse(
            success=result.success,
            result=result.data,
            message=result.message,
            command_type=result.command_type
        )

    except Exception as e:
        return CommandResponse(
            success=False,
            result=None,
            message=f"命令执行失败: {str(e)}",
            command_type="error"
        )

@router.get("/list")
async def list_available_commands():
    """获取可用命令列表"""
    commands = {
        "session": [
            {
                "name": "clear",
                "description": "清除当前会话历史",
                "usage": "/clear",
                "examples": ["/clear"]
            },
            {
                "name": "compress", 
                "description": "压缩会话历史以节省token",
                "usage": "/compress",
                "examples": ["/compress"]
            },
            {
                "name": "stats",
                "description": "显示当前会话统计信息",
                "usage": "/stats",
                "examples": ["/stats"]
            },
            {
                "name": "memory",
                "description": "管理对话记忆",
                "usage": "/memory <action> [content]",
                "examples": ["/memory show", "/memory add '重要信息'", "/memory clear"]
            }
        ],
        "model": [
            {
                "name": "model",
                "description": "切换AI模型",
                "usage": "/model <model_name>",
                "examples": ["/model qwen-coder", "/model qwen-vision"]
            },
            {
                "name": "auth",
                "description": "切换认证方式", 
                "usage": "/auth",
                "examples": ["/auth"]
            }
        ],
        "analysis": [
            {
                "name": "analyze",
                "description": "分析指定内容",
                "usage": "/analyze <type> [target]",
                "examples": ["/analyze code", "/analyze requests session_123"]
            },
            {
                "name": "export",
                "description": "导出分析结果",
                "usage": "/export <format> [session_id]", 
                "examples": ["/export json", "/export csv session_123"]
            }
        ],
        "system": [
            {
                "name": "settings",
                "description": "打开设置面板",
                "usage": "/settings",
                "examples": ["/settings"]
            },
            {
                "name": "theme",
                "description": "切换主题",
                "usage": "/theme <theme>",
                "examples": ["/theme dark", "/theme light"]
            }
        ],
        "help": [
            {
                "name": "help",
                "description": "显示帮助信息",
                "usage": "/help [command]",
                "aliases": ["?"],
                "examples": ["/help", "/help model", "/?"]
            },
            {
                "name": "docs",
                "description": "打开文档",
                "usage": "/docs",
                "examples": ["/docs"]
            }
        ]
    }
    
    return {"commands": commands}

@router.post("/models/switch")
async def switch_model(
    model_id: str,
    reason: str = "user_selection",
    session_id: Optional[str] = None,
    auth_service: AuthService = Depends(get_auth_service),
    command_service: CommandService = Depends(get_command_service)
):
    """切换模型 - Web版/model命令"""
    try:
        if not session_id:
            raise HTTPException(status_code=401, detail="需要认证会话")
        
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        # 执行模型切换
        result = await command_service.switch_model(
            auth_state=auth_state,
            target_model=model_id,
            reason=reason
        )

        if result.success:
            # 更新认证状态中的模型信息
            auth_state.model = model_id
            auth_service.update_auth_session(session_id, auth_state)

        return {
            "success": result.success,
            "message": result.message,
            "current_model": model_id if result.success else auth_state.model,
            "reason": reason
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"模型切换失败: {str(e)}")

@router.get("/session/stats/{session_id}")
async def get_session_stats(
    session_id: str,
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """获取会话统计信息 - Web版/stats命令"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        stats = session_service.get_session_stats(session_id)
        
        return {
            "session_id": session_id,
            "auth_type": auth_state.auth_type.value,
            "current_model": getattr(auth_state, 'model', 'unknown'),
            "stats": {
                "messages_count": stats.get("messages_count", 0),
                "tokens_used": stats.get("tokens_used", 0),
                "tokens_limit": auth_state.quota_limit,
                "requests_count": stats.get("requests_count", 0),
                "session_duration": stats.get("session_duration", 0),
                "last_activity": stats.get("last_activity"),
                "memory_items": stats.get("memory_items", 0)
            },
            "quota": {
                "used": auth_state.quota_used,
                "limit": auth_state.quota_limit,
                "remaining": auth_state.quota_limit - auth_state.quota_used if auth_state.quota_limit else None,
                "reset_time": auth_state.quota_reset_time.isoformat() if auth_state.quota_reset_time else None
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取会话统计失败: {str(e)}")

@router.post("/session/clear/{session_id}")
async def clear_session(
    session_id: str,
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """清除会话历史 - Web版/clear命令"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        # 清除会话数据
        cleared_items = session_service.clear_session_history(session_id)
        
        return {
            "success": True,
            "message": f"已清除 {cleared_items} 条会话记录",
            "cleared_items": cleared_items,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清除会话失败: {str(e)}")

@router.post("/session/compress/{session_id}")
async def compress_session(
    session_id: str,
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """压缩会话历史 - Web版/compress命令"""
    try:
        auth_state = auth_service.get_auth_session(session_id)
        if not auth_state:
            raise HTTPException(status_code=401, detail="认证会话无效")

        # 压缩会话历史
        result = await session_service.compress_session_history(session_id)

        return {
            "success": True,
            "message": "会话历史已压缩",
            "before_tokens": result.get("before_tokens", 0),
            "after_tokens": result.get("after_tokens", 0),
            "compression_ratio": result.get("compression_ratio", 0),
            "summary": result.get("summary", ""),
            "estimatedSavings": result.get("before_tokens", 0) - result.get("after_tokens", 0),
            "compressionRatio": result.get("compression_ratio", 0)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"压缩会话失败: {str(e)}")

@router.post("/session/compress")
async def compress_session_by_body(
    body: Dict[str, Any],
    session_service: SessionService = Depends(get_session_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """压缩会话历史 - 别名路由（兼容前端，session_id在body中）"""
    session_id = body.get('session_id')
    if not session_id:
        raise HTTPException(status_code=400, detail="缺少session_id参数")
    return await compress_session(session_id, session_service, auth_service)

@router.get("/help")
async def get_help(command: Optional[str] = None):
    """获取帮助信息 - Web版/help命令"""
    if command:
        # 获取特定命令的帮助
        commands = await list_available_commands()
        all_commands = {}
        for category in commands["commands"].values():
            for cmd in category:
                all_commands[cmd["name"]] = cmd
                if "aliases" in cmd:
                    for alias in cmd["aliases"]:
                        all_commands[alias] = cmd

        if command in all_commands:
            cmd_info = all_commands[command]
            return {
                "command": command,
                "description": cmd_info["description"],
                "usage": cmd_info["usage"],
                "examples": cmd_info["examples"],
                "aliases": cmd_info.get("aliases", [])
            }
        else:
            raise HTTPException(status_code=404, detail=f"命令 '{command}' 不存在")
    else:
        # 获取全部帮助信息
        return {
            "title": "Web Analyzer 命令帮助",
            "description": "基于qwen-code CLI的Web命令系统",
            "categories": {
                "session": "会话管理 - 清除、压缩、统计会话数据",
                "model": "模型管理 - 切换AI模型和认证方式", 
                "analysis": "分析工具 - 数据分析和结果导出",
                "system": "系统设置 - 主题、配置等系统功能",
                "help": "帮助信息 - 命令说明和文档"
            },
            "quick_start": [
                "输入 /help 查看所有命令",
                "输入 /stats 查看当前会话统计",
                "输入 /model qwen-coder 切换到编程模型",
                "输入 /clear 清除会话历史"
            ],
            "features": [
                "多种认证方式 (Qwen OAuth, OpenAI API)",
                "智能模型切换 (编程/视觉模型自动切换)",
                "实时会话统计和Token管理",
                "30+专业命令 (基于qwen-code CLI)",
                "会话记忆和历史压缩",
                "现代化Web界面"
            ]
        }


def _match_any_pattern(path_value: str, patterns: List[str]) -> bool:
    for pattern in patterns:
        if not pattern:
            continue
        candidates = [pattern]
        # Common glob style: `name/**` should also match the directory `name` itself.
        if pattern.endswith("/**"):
            candidates.append(pattern[:-3])

        # Support matching at any depth (frontend default patterns are not anchored).
        if not pattern.startswith("**/"):
            candidates.append(f"**/{pattern}")
            if pattern.endswith("/**"):
                candidates.append(f"**/{pattern[:-3]}")
        for candidate in candidates:
            if fnmatch.fnmatchcase(path_value, candidate):
                return True
    return False


def _build_file_tree(root: Path, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    include_hidden = bool(config.get("includeHidden", False))
    follow_symlinks = bool(config.get("followSymlinks", False))
    max_depth = int(config.get("maxDepth", 5))
    exclude_patterns = list(config.get("excludePatterns") or [])
    include_patterns = list(config.get("includePatterns") or [])

    def should_skip(p: Path, rel_posix: str) -> bool:
        if not include_hidden and p.name.startswith("."):
            return True
        if p.is_symlink() and not follow_symlinks:
            return True
        if exclude_patterns and _match_any_pattern(rel_posix, exclude_patterns):
            return True
        return False

    def should_include_file(rel_posix: str) -> bool:
        if not include_patterns:
            return True
        return _match_any_pattern(rel_posix, include_patterns)

    def walk_dir(current: Path, depth: int) -> List[Dict[str, Any]]:
        if depth > max_depth:
            return []

        try:
            entries = list(current.iterdir())
        except Exception:
            return []

        # 文件夹优先，其次按名称排序
        entries.sort(key=lambda p: (p.is_file(), p.name.lower()))

        nodes: List[Dict[str, Any]] = []
        for entry in entries:
            try:
                rel = entry.relative_to(root).as_posix()
            except Exception:
                rel = entry.name

            if should_skip(entry, rel):
                continue

            if entry.is_dir():
                children = walk_dir(entry, depth + 1)
                # 如果指定了 includePatterns，则仅保留包含可见子节点的目录
                if include_patterns and not children:
                    continue
                nodes.append(
                    {
                        "key": rel,
                        "title": entry.name,
                        "path": str(entry),
                        "isLeaf": False,
                        "type": "folder",
                        "children": children,
                        "selected": False,
                        "analyzed": False,
                    }
                )
            else:
                if not should_include_file(rel):
                    continue
                try:
                    stat = entry.stat()
                    size = stat.st_size
                    last_modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
                except Exception:
                    size = None
                    last_modified = None

                ext = entry.suffix.lstrip(".").lower() if entry.suffix else ""
                nodes.append(
                    {
                        "key": rel,
                        "title": entry.name,
                        "path": str(entry),
                        "isLeaf": True,
                        "type": "file",
                        "size": size,
                        "extension": ext or None,
                        "lastModified": last_modified,
                        "selected": False,
                        "analyzed": False,
                    }
                )

        return nodes

    children = walk_dir(root, depth=0)
    root_key = root.as_posix()
    return [
        {
            "key": root_key,
            "title": root.name or root_key,
            "path": str(root),
            "isLeaf": False,
            "type": "folder",
            "children": children,
            "selected": False,
            "analyzed": False,
        }
    ]


@router.post("/directory/scan")
async def scan_directory(body: Dict[str, Any]):
    """扫描目录并返回文件树（SSE 流式，兼容前端 DirectoryTree 组件）"""
    raw_path = (body or {}).get("path") or ""
    config = (body or {}).get("config") or {}

    base_path = Path(raw_path)
    if not raw_path:
        base_path = PROJECT_ROOT
    elif not base_path.is_absolute():
        base_path = (PROJECT_ROOT / base_path).resolve()

    if not base_path.exists() or not base_path.is_dir():
        raise HTTPException(status_code=400, detail=f"目录不存在或不是目录: {base_path}")

    async def event_stream():
        yield f"data: {json.dumps({'type': 'progress', 'progress': 5}, ensure_ascii=False)}\n\n"

        tree = _build_file_tree(base_path, config)

        yield f"data: {json.dumps({'type': 'progress', 'progress': 90}, ensure_ascii=False)}\n\n"
        yield f"data: {json.dumps({'type': 'file_tree', 'tree': tree}, ensure_ascii=False)}\n\n"
        yield f"data: {json.dumps({'type': 'progress', 'progress': 100}, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.post("/directory/analyze")
async def analyze_files(body: Dict[str, Any]):
    """对选中的文件做轻量分析（为前端文件树标注信息）"""
    files = (body or {}).get("files") or []
    analyses: List[Dict[str, Any]] = []

    def classify(ext: str) -> Dict[str, Any]:
        ext = (ext or "").lower()
        code_map = {
            "js": "JavaScript",
            "ts": "TypeScript",
            "jsx": "JavaScript (React)",
            "tsx": "TypeScript (React)",
            "py": "Python",
            "java": "Java",
            "c": "C",
            "cpp": "C++",
            "cs": "C#",
            "go": "Go",
            "rs": "Rust",
        }
        if ext in code_map:
            return {"type": "code", "language": code_map[ext]}
        if ext in {"json", "yaml", "yml", "toml", "ini", "env", "xml"}:
            return {"type": "config"}
        if ext in {"csv", "db", "sqlite", "parquet"}:
            return {"type": "data"}
        if ext in {"png", "jpg", "jpeg", "gif", "svg", "webp"}:
            return {"type": "image"}
        if ext in {"md", "txt", "pdf", "doc", "docx"}:
            return {"type": "document"}
        return {"type": "other"}

    for file_path in files:
        p = Path(str(file_path))
        ext = p.suffix.lstrip(".")
        meta = classify(ext)
        analysis: Dict[str, Any] = {
            "path": str(p),
            "type": meta.get("type", "other"),
            "risk": "low",
        }
        if "language" in meta:
            analysis["language"] = meta["language"]

        if not p.exists() or not p.is_file():
            analysis["risk"] = "high"
            analysis["issues"] = ["文件不存在或不是文件"]
            analyses.append(analysis)
            continue

        try:
            size = p.stat().st_size
        except Exception:
            size = None

        # 避免读取超大文件
        if size is not None and size > 2 * 1024 * 1024:
            analysis["risk"] = "medium"
            analysis["issues"] = ["文件过大，已跳过内容分析"]
            analyses.append(analysis)
            continue

        issues: List[str] = []
        suggestions: List[str] = []
        complexity = None
        lines = None

        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            lines = len(content.splitlines())

            if analysis["type"] == "code":
                # 非严格复杂度：统计常见分支/循环关键字出现次数
                keywords = [" if ", " for ", " while ", " switch ", " case ", " catch ", " except "]
                complexity = sum(content.count(k) for k in keywords)

                # 简单风险规则
                risky_snippets = [
                    ("eval(", "存在 eval()，可能带来代码注入风险"),
                    ("exec(", "存在 exec()，可能带来代码注入风险"),
                    ("os.system(", "存在系统命令执行，注意输入校验"),
                    ("subprocess.", "存在子进程调用，注意输入校验"),
                    ("password", "包含 password 关键字，注意敏感信息处理"),
                    ("SECRET", "包含 SECRET 关键字，注意敏感信息处理"),
                    ("token", "包含 token 关键字，注意敏感信息处理"),
                ]
                for needle, desc in risky_snippets:
                    if needle.lower() in content.lower():
                        issues.append(desc)

                if any("代码注入" in i for i in issues) or any("系统命令" in i for i in issues):
                    analysis["risk"] = "high"
                elif issues:
                    analysis["risk"] = "medium"

                if issues:
                    suggestions.append("检查敏感信息与危险调用的输入来源，必要时增加校验/脱敏/白名单。")
            else:
                # 其他类型给一些通用建议
                if analysis["type"] == "config" and ("SECRET" in content or "password" in content.lower()):
                    issues.append("配置文件可能包含敏感信息")
                    analysis["risk"] = "medium"
                    suggestions.append("建议将密钥放入环境变量或安全的密钥管理方案。")

        except Exception as e:
            analysis["risk"] = "medium"
            issues.append(f"读取/分析失败: {e}")

        if lines is not None:
            analysis["lines"] = lines
        if complexity is not None:
            analysis["complexity"] = complexity
        if issues:
            analysis["issues"] = issues
        if suggestions:
            analysis["suggestions"] = suggestions

        analyses.append(analysis)

    return {"analyses": analyses}
