"""
代码生成API端点

提供将录制的HTTP请求转换为可执行Python代码的功能。
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import json
from pathlib import Path
from datetime import datetime

from core.code_generator import generate_code_from_session, write_session_summary

router = APIRouter()


class CodeGenerationRequest(BaseModel):
    session_path: str
    include_js_analysis: bool = True
    output_format: str = "python"  # python, executable


class CodeGenerationResponse(BaseModel):
    success: bool
    message: str
    code_preview: Optional[str] = None
    file_path: Optional[str] = None
    stats: Optional[Dict[str, Any]] = None


@router.post("/generate", response_model=CodeGenerationResponse)
async def generate_session_code(
    request: CodeGenerationRequest,
    background_tasks: BackgroundTasks
) -> CodeGenerationResponse:
    """
    为指定会话生成Python代码
    
    Args:
        request: 代码生成请求，包含会话路径和选项
        
    Returns:
        代码生成结果，包含预览和文件路径
    """
    session_path = Path(request.session_path)
    
    # 验证会话路径
    if not session_path.exists():
        raise HTTPException(status_code=404, detail=f"会话目录不存在: {request.session_path}")
    
    if not session_path.is_dir():
        raise HTTPException(status_code=400, detail="指定路径不是目录")
    
    # 检查requests.json文件
    requests_file = session_path / "requests.json"
    if not requests_file.exists():
        raise HTTPException(status_code=404, detail="会话中未找到requests.json文件")
    
    try:
        # 读取请求统计信息
        with open(requests_file, 'r', encoding='utf-8') as f:
            requests_data = json.load(f)
        
        stats = {
            "total_requests": len(requests_data),
            "api_requests": len([r for r in requests_data if r.get('resource_type') in ['xhr', 'fetch']]),
            "domains": len(set(r.get('url', '').split('/')[2] for r in requests_data if r.get('url'))),
            "session_name": session_path.name
        }
        
        # 生成代码
        generated_code = generate_code_from_session(session_path)

        try:
            write_session_summary(session_path)
        except Exception:
            pass
        
        # 保存生成的代码
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"session_{session_path.name}_{timestamp}.py"
        output_path = session_path / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(generated_code)
        
        # 创建预览（前500个字符）
        code_preview = generated_code[:500] + "..." if len(generated_code) > 500 else generated_code
        
        return CodeGenerationResponse(
            success=True,
            message=f"成功生成代码，包含 {stats['api_requests']} 个API请求",
            code_preview=code_preview,
            file_path=str(output_path),
            stats=stats
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"代码生成失败: {str(e)}")


@router.get("/preview/{session_name}")
async def preview_generated_code(session_name: str) -> PlainTextResponse:
    """
    预览生成的代码（不保存到文件）
    
    Args:
        session_name: 会话名称
        
    Returns:
        生成的Python代码文本
    """
    # 查找会话目录
    project_root = Path(__file__).parent.parent.parent.parent.parent
    sessions_dir = project_root / "data" / "sessions"
    session_path = sessions_dir / session_name
    
    if not session_path.exists():
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_name}")
    
    try:
        generated_code = generate_code_from_session(session_path)
        return PlainTextResponse(generated_code, media_type="text/plain; charset=utf-8")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"代码预览失败: {str(e)}")


@router.get("/download/{session_name}")
async def download_generated_code(session_name: str):
    """
    下载生成的Python代码文件
    
    Args:
        session_name: 会话名称
        
    Returns:
        Python代码文件
    """
    # 查找会话目录
    project_root = Path(__file__).parent.parent.parent.parent.parent
    sessions_dir = project_root / "data" / "sessions"
    session_path = sessions_dir / session_name
    
    if not session_path.exists():
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_name}")
    
    try:
        # 生成代码
        generated_code = generate_code_from_session(session_path)
        
        # 创建临时文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_filename = f"session_{session_name}_{timestamp}.py"
        temp_path = session_path / temp_filename
        
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(generated_code)
        
        return FileResponse(
            path=temp_path,
            filename=temp_filename,
            media_type='text/plain',
            headers={"Content-Disposition": f"attachment; filename={temp_filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"代码下载失败: {str(e)}")


@router.get("/stats/{session_name}")
async def get_session_stats(session_name: str) -> Dict[str, Any]:
    """
    获取会话统计信息
    
    Args:
        session_name: 会话名称
        
    Returns:
        会话统计数据
    """
    # 查找会话目录
    project_root = Path(__file__).parent.parent.parent.parent.parent
    sessions_dir = project_root / "data" / "sessions"
    session_path = sessions_dir / session_name
    
    if not session_path.exists():
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_name}")
    
    requests_file = session_path / "requests.json"
    if not requests_file.exists():
        raise HTTPException(status_code=404, detail="会话中未找到requests.json文件")
    
    try:
        with open(requests_file, 'r', encoding='utf-8') as f:
            requests_data = json.load(f)
        
        # 统计信息
        total_requests = len(requests_data)
        api_requests = [r for r in requests_data if r.get('resource_type') in ['xhr', 'fetch']]
        domains = set()
        methods = {}
        status_codes = {}
        js_calls = 0
        
        for request in requests_data:
            # 域名统计
            url = request.get('url', '')
            if url:
                try:
                    domain = url.split('/')[2]
                    domains.add(domain)
                except:
                    pass
            
            # 方法统计
            method = request.get('method', 'UNKNOWN')
            methods[method] = methods.get(method, 0) + 1
            
            # 状态码统计
            status = request.get('status')
            if status:
                status_codes[str(status)] = status_codes.get(str(status), 0) + 1
            
            # JavaScript调用栈统计
            if request.get('call_stack'):
                js_calls += 1
        
        return {
            "session_name": session_name,
            "session_path": str(session_path),
            "total_requests": total_requests,
            "api_requests_count": len(api_requests),
            "domains_count": len(domains),
            "domains": sorted(list(domains)),
            "methods": methods,
            "status_codes": status_codes,
            "js_calls_count": js_calls,
            "has_js_analysis": js_calls > 0,
            "files": {
                "requests_json": requests_file.exists(),
                "scripts_dir": (session_path / "scripts").exists(),
                "responses_dir": (session_path / "responses").exists(),
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取统计信息失败: {str(e)}")


@router.post("/batch-generate")
async def batch_generate_codes(
    session_names: list[str],
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    批量生成多个会话的代码
    
    Args:
        session_names: 会话名称列表
        background_tasks: 后台任务管理器
        
    Returns:
        批量生成结果
    """
    project_root = Path(__file__).parent.parent.parent.parent.parent
    sessions_dir = project_root / "data" / "sessions"
    
    results = {
        "total_sessions": len(session_names),
        "successful": [],
        "failed": [],
        "summary": {}
    }
    
    for session_name in session_names:
        session_path = sessions_dir / session_name
        
        if not session_path.exists():
            results["failed"].append({
                "session": session_name,
                "error": "会话目录不存在"
            })
            continue
        
        try:
            # 添加到后台任务
            background_tasks.add_task(
                _generate_code_background,
                session_path,
                session_name
            )
            
            results["successful"].append(session_name)
            
        except Exception as e:
            results["failed"].append({
                "session": session_name,
                "error": str(e)
            })
    
    results["summary"] = {
        "success_count": len(results["successful"]),
        "failed_count": len(results["failed"]),
        "status": "批量任务已启动，代码将在后台生成"
    }
    
    return results


async def _generate_code_background(session_path: Path, session_name: str):
    """后台代码生成任务"""
    try:
        generated_code = generate_code_from_session(session_path)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"session_{session_name}_{timestamp}.py"
        output_path = session_path / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(generated_code)
        
        print(f"[OK] 后台生成代码完成: {output_path}")
        
    except Exception as e:
        print(f"[FAIL] 后台生成代码失败 {session_name}: {e}")
