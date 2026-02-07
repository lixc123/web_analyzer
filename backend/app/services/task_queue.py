"""
后台任务队列服务

用于处理耗时操作，如代码生成、大文件分析等，避免阻塞用户界面
"""

import asyncio
import uuid
import time
from enum import Enum
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """任务定义"""
    id: str
    name: str
    status: TaskStatus
    progress: float = 0.0
    result: Any = None
    error: Optional[str] = None
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        data = asdict(self)
        data['status'] = self.status.value
        # 转换datetime为ISO格式字符串
        for key in ['created_at', 'started_at', 'completed_at']:
            if data[key]:
                data[key] = data[key].isoformat()
        return data


class TaskQueue:
    """后台任务队列管理器"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # 任务存储
        self.tasks: Dict[str, Task] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
        
        # 任务处理函数注册表
        self.handlers: Dict[str, Callable] = {}
        
        # 统计信息
        self.stats = {
            'total_created': 0,
            'total_completed': 0,
            'total_failed': 0,
            'total_cancelled': 0
        }
    
    def register_handler(self, task_type: str, handler: Callable):
        """注册任务处理函数"""
        self.handlers[task_type] = handler
        logger.info(f"注册任务处理器: {task_type}")
    
    async def submit_task(self, task_type: str, task_name: str, **kwargs) -> str:
        """提交新任务"""
        if task_type not in self.handlers:
            raise ValueError(f"未知的任务类型: {task_type}")
        
        task_id = str(uuid.uuid4())
        task = Task(
            id=task_id,
            name=task_name,
            status=TaskStatus.PENDING,
            metadata={
                'task_type': task_type,
                'params': kwargs
            }
        )
        
        self.tasks[task_id] = task
        self.stats['total_created'] += 1
        
        # 启动任务
        asyncio_task = asyncio.create_task(self._run_task(task))
        self.running_tasks[task_id] = asyncio_task
        
        logger.info(f"提交任务: {task_name} (ID: {task_id})")
        return task_id
    
    async def _run_task(self, task: Task):
        """执行任务"""
        try:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            
            task_type = task.metadata['task_type']
            params = task.metadata['params']
            handler = self.handlers[task_type]
            
            # 执行任务
            loop = asyncio.get_event_loop()
            
            # 如果处理函数是协程，直接await
            if asyncio.iscoroutinefunction(handler):
                result = await handler(task, **params)
            else:
                # 在线程池中执行同步函数
                result = await loop.run_in_executor(
                    self.executor, 
                    lambda: handler(task, **params)
                )
            
            # 任务完成
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = datetime.now()
            task.progress = 100.0
            
            self.stats['total_completed'] += 1
            logger.info(f"任务完成: {task.name} (ID: {task.id})")
            
        except asyncio.CancelledError:
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now()
            self.stats['total_cancelled'] += 1
            logger.info(f"任务取消: {task.name} (ID: {task.id})")
            raise
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.now()
            self.stats['total_failed'] += 1
            logger.error(f"任务失败: {task.name} (ID: {task.id}): {e}")
            
        finally:
            # 清理运行中的任务引用
            self.running_tasks.pop(task.id, None)
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """获取任务信息"""
        return self.tasks.get(task_id)
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务状态"""
        task = self.get_task(task_id)
        return task.to_dict() if task else None
    
    async def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        if task_id in self.running_tasks:
            asyncio_task = self.running_tasks[task_id]
            asyncio_task.cancel()
            
            try:
                await asyncio_task
            except asyncio.CancelledError:
                pass
            
            return True
        return False
    
    def list_tasks(self, status: Optional[TaskStatus] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """列出任务"""
        tasks = list(self.tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        
        # 按创建时间倒序排列
        tasks.sort(key=lambda t: t.created_at, reverse=True)
        
        return [t.to_dict() for t in tasks[:limit]]
    
    def cleanup_old_tasks(self, max_age_hours: int = 24):
        """清理旧任务"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        old_task_ids = []
        for task_id, task in self.tasks.items():
            if task.completed_at and task.completed_at < cutoff_time:
                old_task_ids.append(task_id)
        
        for task_id in old_task_ids:
            del self.tasks[task_id]
        
        logger.info(f"清理了 {len(old_task_ids)} 个旧任务")
        return len(old_task_ids)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        current_tasks = {
            'pending': len([t for t in self.tasks.values() if t.status == TaskStatus.PENDING]),
            'running': len([t for t in self.tasks.values() if t.status == TaskStatus.RUNNING]),
            'completed': len([t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]),
            'failed': len([t for t in self.tasks.values() if t.status == TaskStatus.FAILED]),
            'cancelled': len([t for t in self.tasks.values() if t.status == TaskStatus.CANCELLED])
        }
        
        return {
            'current_tasks': current_tasks,
            'total_stats': self.stats,
            'queue_size': len(self.tasks),
            'running_tasks': len(self.running_tasks),
            'max_workers': self.max_workers
        }


# 全局任务队列实例
_task_queue: Optional[TaskQueue] = None


def get_task_queue() -> TaskQueue:
    """获取任务队列实例"""
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue()
    return _task_queue


def update_task_progress(task: Task, progress: float, message: str = None):
    """更新任务进度"""
    task.progress = max(0.0, min(100.0, progress))
    if message:
        task.metadata['progress_message'] = message
    logger.debug(f"任务进度更新: {task.name} - {progress}% - {message}")


# 常用任务处理函数示例
async def code_generation_task(task: Task, session_path: str, **kwargs):
    """代码生成任务处理函数"""
    from core.code_generator import generate_code_from_session
    from pathlib import Path
    
    try:
        update_task_progress(task, 10.0, "开始生成代码...")
        
        session_path_obj = Path(session_path)
        
        update_task_progress(task, 30.0, "读取会话数据...")
        
        # 生成代码
        generated_code = generate_code_from_session(session_path_obj)
        
        update_task_progress(task, 80.0, "保存生成的代码...")
        
        # 保存代码文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"session_{session_path_obj.name}_{timestamp}.py"
        output_path = session_path_obj / output_filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(generated_code)
        
        update_task_progress(task, 100.0, "代码生成完成")
        
        return {
            'generated_code_path': str(output_path),
            'code_length': len(generated_code),
            'session_name': session_path_obj.name
        }
        
    except Exception as e:
        logger.error(f"代码生成任务失败: {e}")
        raise


async def batch_analysis_task(task: Task, session_ids: List[str], analysis_config: Dict, **kwargs):
    """批量分析任务处理函数"""
    # 使用相对导入避免在不同启动方式下出现 `app.*` / `backend.app.*` 重复加载
    from .analysis_service import AnalysisService
    
    try:
        analysis_service = AnalysisService()
        results = {}
        
        total_sessions = len(session_ids)
        
        for i, session_id in enumerate(session_ids):
            update_task_progress(
                task, 
                (i / total_sessions) * 90.0, 
                f"分析会话 {i+1}/{total_sessions}: {session_id}"
            )
            
            try:
                result = await analysis_service.analyze(
                    session_id=session_id,
                    config=analysis_config
                )
                results[session_id] = result
            except Exception as e:
                logger.error(f"分析会话 {session_id} 失败: {e}")
                results[session_id] = {"error": str(e)}
        
        update_task_progress(task, 100.0, f"批量分析完成，共处理 {total_sessions} 个会话")
        
        return {
            'results': results,
            'total_sessions': total_sessions,
            'successful_analyses': len([r for r in results.values() if "error" not in r])
        }
        
    except Exception as e:
        logger.error(f"批量分析任务失败: {e}")
        raise


# 初始化时注册常用任务处理函数
def init_task_handlers():
    """初始化任务处理函数"""
    queue = get_task_queue()
    queue.register_handler("code_generation", code_generation_task)
    queue.register_handler("batch_analysis", batch_analysis_task)
    logger.info("任务处理函数初始化完成")
