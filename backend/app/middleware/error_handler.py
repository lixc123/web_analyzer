"""
全局错误处理中间件
提供统一的异常处理、日志记录和错误响应
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import traceback
from typing import Union, Dict, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)

# 错误日志存储
error_logs = []
MAX_ERROR_LOGS = 1000


class ErrorResponse:
    """标准错误响应格式"""

    def __init__(
        self,
        status_code: int,
        error_type: str,
        message: str,
        detail: str = None,
        errors: list = None,
        timestamp: str = None
    ):
        self.status_code = status_code
        self.error_type = error_type
        self.message = message
        self.detail = detail
        self.errors = errors or []
        self.timestamp = timestamp or datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        response = {
            "error_type": self.error_type,
            "message": self.message,
            "timestamp": self.timestamp
        }

        if self.detail:
            response["detail"] = self.detail

        if self.errors:
            response["errors"] = self.errors

        return response


def log_error(
    error_type: str,
    message: str,
    detail: str = None,
    status_code: int = 500,
    request: Request = None,
    exception: Exception = None
):
    """记录错误日志"""
    error_info = {
        "error_type": error_type,
        "message": message,
        "detail": detail,
        "status_code": status_code,
        "timestamp": datetime.now().isoformat()
    }

    # 添加请求信息
    if request:
        error_info["request"] = {
            "method": request.method,
            "url": str(request.url),
            "client": request.client.host if request.client else None,
            "headers": dict(request.headers)
        }

    # 添加异常堆栈
    if exception:
        error_info["exception"] = {
            "type": type(exception).__name__,
            "message": str(exception),
            "traceback": traceback.format_exc()
        }

    # 记录到日志
    logger.error(f"[{error_type}] {message}", extra=error_info)

    # 存储到内存（用于调试）
    error_logs.append(error_info)
    if len(error_logs) > MAX_ERROR_LOGS:
        error_logs.pop(0)


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """处理HTTP异常"""
    error_response = ErrorResponse(
        status_code=exc.status_code,
        error_type="HTTP_ERROR",
        message=exc.detail or "HTTP错误",
        detail=str(exc)
    )

    log_error(
        error_type="HTTP_ERROR",
        message=exc.detail or "HTTP错误",
        status_code=exc.status_code,
        request=request,
        exception=exc
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.to_dict()
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """处理请求验证异常"""
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })

    error_response = ErrorResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        error_type="VALIDATION_ERROR",
        message="请求参数验证失败",
        detail="请检查请求参数格式",
        errors=errors
    )

    log_error(
        error_type="VALIDATION_ERROR",
        message="请求参数验证失败",
        detail=json.dumps(errors, ensure_ascii=False),
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        request=request,
        exception=exc
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.to_dict()
    )


async def general_exception_handler(request: Request, exc: Exception):
    """处理通用异常"""
    # 判断异常类型
    if isinstance(exc, ValueError):
        error_type = "VALUE_ERROR"
        message = "参数值错误"
        status_code = status.HTTP_400_BAD_REQUEST
    elif isinstance(exc, KeyError):
        error_type = "KEY_ERROR"
        message = "缺少必要的参数"
        status_code = status.HTTP_400_BAD_REQUEST
    elif isinstance(exc, FileNotFoundError):
        error_type = "FILE_NOT_FOUND"
        message = "文件不存在"
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, PermissionError):
        error_type = "PERMISSION_ERROR"
        message = "权限不足"
        status_code = status.HTTP_403_FORBIDDEN
    elif isinstance(exc, TimeoutError):
        error_type = "TIMEOUT_ERROR"
        message = "操作超时"
        status_code = status.HTTP_408_REQUEST_TIMEOUT
    else:
        error_type = "INTERNAL_ERROR"
        message = "服务器内部错误"
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    error_response = ErrorResponse(
        status_code=status_code,
        error_type=error_type,
        message=message,
        detail=str(exc)
    )

    log_error(
        error_type=error_type,
        message=message,
        detail=str(exc),
        status_code=status_code,
        request=request,
        exception=exc
    )

    return JSONResponse(
        status_code=status_code,
        content=error_response.to_dict()
    )


def get_error_logs(limit: int = 100) -> list:
    """获取错误日志"""
    return error_logs[-limit:]


def clear_error_logs():
    """清空错误日志"""
    error_logs.clear()


def export_error_logs() -> str:
    """导出错误日志"""
    return json.dumps(error_logs, ensure_ascii=False, indent=2)


# 自定义业务异常
class BusinessException(Exception):
    """业务异常基类"""

    def __init__(
        self,
        message: str,
        error_type: str = "BUSINESS_ERROR",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        detail: str = None
    ):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        self.detail = detail
        super().__init__(message)


class ResourceNotFoundException(BusinessException):
    """资源不存在异常"""

    def __init__(self, resource: str, resource_id: str = None):
        message = f"{resource}不存在"
        if resource_id:
            message += f": {resource_id}"

        super().__init__(
            message=message,
            error_type="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )


class ResourceConflictException(BusinessException):
    """资源冲突异常"""

    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_type="RESOURCE_CONFLICT",
            status_code=status.HTTP_409_CONFLICT
        )


class InvalidOperationException(BusinessException):
    """无效操作异常"""

    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_type="INVALID_OPERATION",
            status_code=status.HTTP_400_BAD_REQUEST
        )


class ServiceUnavailableException(BusinessException):
    """服务不可用异常"""

    def __init__(self, service: str, reason: str = None):
        message = f"{service}服务不可用"
        if reason:
            message += f": {reason}"

        super().__init__(
            message=message,
            error_type="SERVICE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )


async def business_exception_handler(request: Request, exc: BusinessException):
    """处理业务异常"""
    error_response = ErrorResponse(
        status_code=exc.status_code,
        error_type=exc.error_type,
        message=exc.message,
        detail=exc.detail
    )

    log_error(
        error_type=exc.error_type,
        message=exc.message,
        detail=exc.detail,
        status_code=exc.status_code,
        request=request,
        exception=exc
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.to_dict()
    )


def setup_error_handlers(app):
    """设置错误处理器"""
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    # 注册异常处理器
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(BusinessException, business_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)

    logger.info("Error handlers registered successfully")
