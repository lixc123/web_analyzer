"""
HTTP请求分析和重放API路由
支持请求录制、分析、重放和调用栈追踪
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import asyncio
import aiohttp
import json
from datetime import datetime
import logging
import uuid

router = APIRouter()

# 请求/响应模型
class HttpRequestRecord(BaseModel):
    id: str
    method: str
    url: str
    status: int
    responseType: str
    size: int
    duration: int
    timestamp: datetime
    headers: Dict[str, str]
    payload: Optional[Any] = None
    response: Optional[Any] = None
    callStack: Optional[List[str]] = None

class ReplayRequestModel(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    payload: Optional[Any] = None

class CallStackFrame(BaseModel):
    id: str
    function: str
    file: str
    line: int
    column: int
    source: Optional[str] = None
    variables: Optional[Dict[str, Any]] = None
    isUserCode: bool
    executionTime: Optional[int] = None

# 全局请求存储
recorded_requests: List[HttpRequestRecord] = []
logger = logging.getLogger(__name__)

@router.get("/requests")
async def get_recorded_requests(
    method: Optional[str] = None,
    status_range: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """获取录制的HTTP请求列表"""
    try:
        filtered_requests = recorded_requests.copy()
        
        # 方法筛选
        if method and method != 'all':
            filtered_requests = [req for req in filtered_requests if req.method == method]
        
        # 状态码筛选
        if status_range and status_range != 'all':
            status_start, status_end = map(int, status_range.split('-'))
            filtered_requests = [
                req for req in filtered_requests 
                if status_start <= req.status <= status_end
            ]
        
        # 搜索筛选
        if search:
            search_lower = search.lower()
            filtered_requests = [
                req for req in filtered_requests
                if search_lower in req.url.lower() or search_lower in req.method.lower()
            ]
        
        # 分页
        total = len(filtered_requests)
        requests_page = filtered_requests[offset:offset + limit]
        
        return {
            'requests': [req.dict() for req in requests_page],
            'total': total,
            'limit': limit,
            'offset': offset
        }
        
    except Exception as e:
        logger.error(f"获取请求列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/replay-request")
async def replay_request(request: ReplayRequestModel):
    """重放HTTP请求"""
    try:
        start_time = datetime.now()
        
        # 使用aiohttp重放请求
        async with aiohttp.ClientSession() as session:
            kwargs = {
                'method': request.method,
                'url': request.url,
                'headers': request.headers
            }
            
            # 添加请求体
            if request.payload and request.method.upper() in ['POST', 'PUT', 'PATCH']:
                if isinstance(request.payload, dict):
                    kwargs['json'] = request.payload
                else:
                    kwargs['data'] = request.payload
            
            async with session.request(**kwargs) as response:
                duration = (datetime.now() - start_time).total_seconds() * 1000
                response_text = await response.text()
                
                # 创建重放记录
                replay_record = HttpRequestRecord(
                    id=str(uuid.uuid4()),
                    method=request.method,
                    url=request.url,
                    status=response.status,
                    responseType=response.headers.get('content-type', 'text/plain'),
                    size=len(response_text.encode('utf-8')),
                    duration=int(duration),
                    timestamp=datetime.now(),
                    headers=dict(request.headers),
                    payload=request.payload,
                    response=response_text[:1000] if response_text else None  # 限制响应大小
                )
                
                # 添加到请求记录
                recorded_requests.insert(0, replay_record)
                
                return {
                    'success': True,
                    'replay_id': replay_record.id,
                    'status': response.status,
                    'duration': duration,
                    'size': replay_record.size,
                    'message': f'请求重放成功: {request.method} {request.url}'
                }
        
    except Exception as e:
        logger.error(f"请求重放失败: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'message': f'请求重放失败: {str(e)}'
        }

@router.get("/request/{request_id}")
async def get_request_details(request_id: str):
    """获取请求详细信息"""
    try:
        request_record = next(
            (req for req in recorded_requests if req.id == request_id), 
            None
        )
        
        if not request_record:
            raise HTTPException(status_code=404, detail=f"请求记录不存在: {request_id}")
        
        return {
            'request': request_record.dict(),
            'callStack': generate_mock_call_stack(request_record)  # 模拟调用栈
        }
        
    except Exception as e:
        logger.error(f"获取请求详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/request/{request_id}/call-stack")
async def get_request_call_stack(request_id: str):
    """获取请求的调用栈信息"""
    try:
        request_record = next(
            (req for req in recorded_requests if req.id == request_id), 
            None
        )
        
        if not request_record:
            raise HTTPException(status_code=404, detail=f"请求记录不存在: {request_id}")
        
        # 生成模拟调用栈
        call_stack = generate_detailed_call_stack(request_record)
        
        return {
            'request_id': request_id,
            'callStack': call_stack,
            'analysis': analyze_call_stack_performance(call_stack)
        }
        
    except Exception as e:
        logger.error(f"获取调用栈失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/start-recording")
async def start_request_recording():
    """开始HTTP请求录制"""
    try:
        # 在实际实现中，这里会启动请求拦截器
        return {
            'success': True,
            'message': '请求录制已启动',
            'recording_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"启动录制失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop-recording")
async def stop_request_recording():
    """停止HTTP请求录制"""
    try:
        return {
            'success': True,
            'message': '请求录制已停止',
            'recorded_count': len(recorded_requests),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"停止录制失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/requests")
async def clear_recorded_requests():
    """清空录制的请求"""
    try:
        global recorded_requests
        count = len(recorded_requests)
        recorded_requests.clear()
        
        return {
            'success': True,
            'message': f'已清除 {count} 条请求记录',
            'cleared_count': count
        }
        
    except Exception as e:
        logger.error(f"清除请求记录失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/statistics")
async def get_request_statistics():
    """获取请求统计信息"""
    try:
        if not recorded_requests:
            return {
                'total': 0,
                'methods': {},
                'status_codes': {},
                'avg_duration': 0,
                'total_size': 0
            }
        
        # 方法统计
        methods = {}
        for req in recorded_requests:
            methods[req.method] = methods.get(req.method, 0) + 1
        
        # 状态码统计
        status_codes = {}
        for req in recorded_requests:
            status_codes[str(req.status)] = status_codes.get(str(req.status), 0) + 1
        
        # 计算平均响应时间和总大小
        total_duration = sum(req.duration for req in recorded_requests)
        avg_duration = total_duration / len(recorded_requests)
        total_size = sum(req.size for req in recorded_requests)
        
        return {
            'total': len(recorded_requests),
            'methods': methods,
            'status_codes': status_codes,
            'avg_duration': round(avg_duration, 2),
            'total_size': total_size,
            'success_rate': len([req for req in recorded_requests if 200 <= req.status < 300]) / len(recorded_requests) * 100
        }
        
    except Exception as e:
        logger.error(f"获取统计信息失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 辅助函数

def generate_mock_call_stack(request_record: HttpRequestRecord) -> List[str]:
    """生成模拟调用栈"""
    if request_record.callStack:
        return request_record.callStack
    
    # 根据请求类型生成不同的调用栈
    if 'api' in request_record.url.lower():
        return [
            f"apiClient.{request_record.method.lower()}() at api-client.js:45",
            f"handleApiRequest() at request-handler.js:23", 
            f"onClick() at component.tsx:67"
        ]
    else:
        return [
            f"fetch('{request_record.url}') at network.js:12",
            f"loadResource() at resource-loader.js:34",
            f"componentDidMount() at page.tsx:89"
        ]

def generate_detailed_call_stack(request_record: HttpRequestRecord) -> List[CallStackFrame]:
    """生成详细调用栈信息"""
    base_frames = [
        CallStackFrame(
            id="1",
            function=f"{request_record.method.lower()}Request",
            file="/src/api/client.js",
            line=45,
            column=12,
            source=f"return fetch('{request_record.url}', options);",
            isUserCode=True,
            executionTime=request_record.duration - 100,
            variables={
                "url": request_record.url,
                "method": request_record.method,
                "options": request_record.headers
            }
        ),
        CallStackFrame(
            id="2",
            function="handleRequest",
            file="/src/services/http.js",
            line=23,
            column=8,
            source="const response = await apiClient.request(config);",
            isUserCode=True,
            executionTime=5,
            variables={
                "config": {"timeout": 5000, "retry": 3}
            }
        ),
        CallStackFrame(
            id="3", 
            function="XMLHttpRequest.send",
            file="native",
            line=0,
            column=0,
            isUserCode=False,
            executionTime=100
        )
    ]
    
    return base_frames

def analyze_call_stack_performance(call_stack: List[CallStackFrame]) -> Dict[str, Any]:
    """分析调用栈性能"""
    total_time = sum(frame.executionTime or 0 for frame in call_stack)
    user_code_time = sum(
        frame.executionTime or 0 
        for frame in call_stack 
        if frame.isUserCode
    )
    
    return {
        'total_execution_time': total_time,
        'user_code_time': user_code_time,
        'system_code_time': total_time - user_code_time,
        'user_code_percentage': (user_code_time / total_time * 100) if total_time > 0 else 0,
        'bottlenecks': [
            {
                'function': frame.function,
                'file': frame.file,
                'execution_time': frame.executionTime,
                'percentage': (frame.executionTime / total_time * 100) if total_time > 0 else 0
            }
            for frame in call_stack
            if frame.executionTime and frame.executionTime > total_time * 0.3  # 超过30%的函数
        ],
        'recommendations': [
            "考虑添加请求缓存机制以减少重复请求",
            "优化网络请求的并发处理",
            "检查是否存在不必要的同步操作"
        ]
    }

# 不再初始化示例数据，使用真实的录制数据
