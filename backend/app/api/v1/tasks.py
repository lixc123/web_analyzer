"""
后台任务队列API端点
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
from datetime import datetime

from ...services.task_queue import get_task_queue, TaskStatus, init_task_handlers

router = APIRouter()

# 初始化任务处理函数
init_task_handlers()


class TaskSubmissionRequest(BaseModel):
    task_type: str
    task_name: str
    params: Dict[str, Any] = {}


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str


@router.post("/submit", response_model=TaskResponse)
async def submit_task(request: TaskSubmissionRequest):
    """提交后台任务"""
    try:
        queue = get_task_queue()
        
        task_id = await queue.submit_task(
            task_type=request.task_type,
            task_name=request.task_name,
            **request.params
        )
        
        return TaskResponse(
            task_id=task_id,
            status="submitted",
            message=f"任务已提交: {request.task_name}"
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"提交任务失败: {str(e)}")


@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    queue = get_task_queue()
    task_status = queue.get_task_status(task_id)
    
    if not task_status:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    return task_status


@router.delete("/cancel/{task_id}")
async def cancel_task(task_id: str):
    """取消任务"""
    queue = get_task_queue()
    
    if not queue.get_task(task_id):
        raise HTTPException(status_code=404, detail="任务未找到")
    
    success = await queue.cancel_task(task_id)
    
    return {
        "success": success,
        "message": "任务已取消" if success else "任务无法取消（可能已完成）"
    }


@router.get("/list")
async def list_tasks(
    status: Optional[str] = None,
    limit: int = 50
):
    """列出任务"""
    queue = get_task_queue()
    
    task_status = None
    if status:
        try:
            task_status = TaskStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"无效的状态值: {status}")
    
    tasks = queue.list_tasks(status=task_status, limit=limit)
    
    return {
        "tasks": tasks,
        "total": len(tasks)
    }


@router.get("/stats")
async def get_task_stats():
    """获取任务队列统计信息"""
    queue = get_task_queue()
    return queue.get_stats()


@router.post("/cleanup")
async def cleanup_old_tasks(max_age_hours: int = 24):
    """清理旧任务"""
    queue = get_task_queue()
    cleaned_count = queue.cleanup_old_tasks(max_age_hours)
    
    return {
        "success": True,
        "cleaned_tasks": cleaned_count,
        "message": f"已清理 {cleaned_count} 个旧任务"
    }


# 便利的任务提交端点
@router.post("/submit/code-generation")
async def submit_code_generation_task(session_path: str, task_name: str = None):
    """提交代码生成任务"""
    if not task_name:
        task_name = f"代码生成 - {session_path}"
    
    request = TaskSubmissionRequest(
        task_type="code_generation",
        task_name=task_name,
        params={"session_path": session_path}
    )
    
    return await submit_task(request)


@router.post("/submit/batch-analysis") 
async def submit_batch_analysis_task(
    session_ids: List[str],
    analysis_config: Dict[str, Any] = None,
    task_name: str = None
):
    """提交批量分析任务"""
    if not task_name:
        task_name = f"批量分析 - {len(session_ids)} 个会话"
    
    if not analysis_config:
        analysis_config = {"analysis_type": "all"}
    
    request = TaskSubmissionRequest(
        task_type="batch_analysis", 
        task_name=task_name,
        params={
            "session_ids": session_ids,
            "analysis_config": analysis_config
        }
    )
    
    return await submit_task(request)
