/**
 * 全局错误处理工具
 * 提供统一的错误处理、日志记录和用户提示
 */

import { message, notification } from 'antd'
import type { AxiosError } from 'axios'

// 错误类型枚举
export enum ErrorType {
  NETWORK = 'NETWORK',           // 网络错误
  TIMEOUT = 'TIMEOUT',           // 超时错误
  SERVER = 'SERVER',             // 服务器错误
  CLIENT = 'CLIENT',             // 客户端错误
  VALIDATION = 'VALIDATION',     // 验证错误
  PERMISSION = 'PERMISSION',     // 权限错误
  NOT_FOUND = 'NOT_FOUND',       // 资源不存在
  UNKNOWN = 'UNKNOWN'            // 未知错误
}

// 错误级别
export enum ErrorLevel {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

// 错误信息接口
export interface ErrorInfo {
  type: ErrorType
  level: ErrorLevel
  message: string
  detail?: string
  code?: string | number
  timestamp: number
  stack?: string
  context?: Record<string, any>
}

// 错误处理配置
export interface ErrorHandlerConfig {
  showNotification?: boolean     // 是否显示通知
  showMessage?: boolean          // 是否显示消息提示
  logToConsole?: boolean         // 是否输出到控制台
  reportToServer?: boolean       // 是否上报到服务器
  customHandler?: (error: ErrorInfo) => void  // 自定义处理函数
}

// 默认配置
const defaultConfig: ErrorHandlerConfig = {
  showNotification: false,
  showMessage: true,
  logToConsole: true,
  reportToServer: false
}

// 错误日志存储
const errorLogs: ErrorInfo[] = []
const MAX_ERROR_LOGS = 100

/**
 * 解析Axios错误
 */
export function parseAxiosError(error: AxiosError): ErrorInfo {
  const timestamp = Date.now()

  // 网络错误
  if (!error.response) {
    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return {
        type: ErrorType.TIMEOUT,
        level: ErrorLevel.WARNING,
        message: '请求超时，请检查网络连接',
        detail: error.message,
        code: error.code,
        timestamp
      }
    }

    return {
      type: ErrorType.NETWORK,
      level: ErrorLevel.ERROR,
      message: '网络连接失败，请检查网络设置',
      detail: error.message,
      code: error.code,
      timestamp
    }
  }

  const { status, data } = error.response
  const errorMessage = (data as any)?.detail || (data as any)?.message || error.message

  // 根据HTTP状态码分类
  switch (status) {
    case 400:
      return {
        type: ErrorType.VALIDATION,
        level: ErrorLevel.WARNING,
        message: '请求参数错误',
        detail: errorMessage,
        code: status,
        timestamp
      }

    case 401:
      return {
        type: ErrorType.PERMISSION,
        level: ErrorLevel.WARNING,
        message: '未授权，请先登录',
        detail: errorMessage,
        code: status,
        timestamp
      }

    case 403:
      return {
        type: ErrorType.PERMISSION,
        level: ErrorLevel.WARNING,
        message: '权限不足，无法访问',
        detail: errorMessage,
        code: status,
        timestamp
      }

    case 404:
      return {
        type: ErrorType.NOT_FOUND,
        level: ErrorLevel.WARNING,
        message: '请求的资源不存在',
        detail: errorMessage,
        code: status,
        timestamp
      }

    case 500:
    case 502:
    case 503:
    case 504:
      return {
        type: ErrorType.SERVER,
        level: ErrorLevel.ERROR,
        message: '服务器错误，请稍后重试',
        detail: errorMessage,
        code: status,
        timestamp
      }

    default:
      return {
        type: ErrorType.UNKNOWN,
        level: ErrorLevel.ERROR,
        message: '请求失败',
        detail: errorMessage,
        code: status,
        timestamp
      }
  }
}

/**
 * 解析普通错误
 */
export function parseError(error: Error | string): ErrorInfo {
  const timestamp = Date.now()

  if (typeof error === 'string') {
    return {
      type: ErrorType.CLIENT,
      level: ErrorLevel.ERROR,
      message: error,
      timestamp
    }
  }

  return {
    type: ErrorType.CLIENT,
    level: ErrorLevel.ERROR,
    message: error.message,
    stack: error.stack,
    timestamp
  }
}

/**
 * 记录错误日志
 */
function logError(errorInfo: ErrorInfo) {
  errorLogs.push(errorInfo)

  // 限制日志数量
  if (errorLogs.length > MAX_ERROR_LOGS) {
    errorLogs.shift()
  }
}

/**
 * 显示错误提示
 */
function showErrorUI(errorInfo: ErrorInfo, config: ErrorHandlerConfig) {
  const { message: msg, detail, level } = errorInfo

  // 显示消息提示
  if (config.showMessage) {
    switch (level) {
      case ErrorLevel.INFO:
        message.info(msg)
        break
      case ErrorLevel.WARNING:
        message.warning(msg)
        break
      case ErrorLevel.ERROR:
      case ErrorLevel.CRITICAL:
        message.error(msg)
        break
    }
  }

  // 显示通知
  if (config.showNotification) {
    const notificationConfig = {
      message: msg,
      description: detail,
      duration: level === ErrorLevel.CRITICAL ? 0 : 4.5
    }

    switch (level) {
      case ErrorLevel.INFO:
        notification.info(notificationConfig)
        break
      case ErrorLevel.WARNING:
        notification.warning(notificationConfig)
        break
      case ErrorLevel.ERROR:
      case ErrorLevel.CRITICAL:
        notification.error(notificationConfig)
        break
    }
  }
}

/**
 * 上报错误到服务器
 */
async function reportError(errorInfo: ErrorInfo) {
  try {
    // TODO: 实现错误上报接口
    console.log('Error reported:', errorInfo)
  } catch (err) {
    console.error('Failed to report error:', err)
  }
}

/**
 * 统一错误处理函数
 */
export function handleError(
  error: Error | AxiosError | string,
  config: ErrorHandlerConfig = {}
): ErrorInfo {
  const finalConfig = { ...defaultConfig, ...config }

  // 解析错误
  let errorInfo: ErrorInfo

  if (typeof error === 'string') {
    errorInfo = parseError(error)
  } else if ('isAxiosError' in error && error.isAxiosError) {
    errorInfo = parseAxiosError(error as AxiosError)
  } else {
    errorInfo = parseError(error as Error)
  }

  // 记录日志
  if (finalConfig.logToConsole) {
    console.error('[Error Handler]', errorInfo)
  }

  logError(errorInfo)

  // 显示UI提示
  showErrorUI(errorInfo, finalConfig)

  // 上报错误
  if (finalConfig.reportToServer) {
    reportError(errorInfo)
  }

  // 自定义处理
  if (finalConfig.customHandler) {
    finalConfig.customHandler(errorInfo)
  }

  return errorInfo
}

/**
 * 创建错误处理器
 */
export function createErrorHandler(defaultConfig?: ErrorHandlerConfig) {
  return (error: Error | AxiosError | string, config?: ErrorHandlerConfig) => {
    return handleError(error, { ...defaultConfig, ...config })
  }
}

/**
 * 获取错误日志
 */
export function getErrorLogs(limit?: number): ErrorInfo[] {
  if (limit) {
    return errorLogs.slice(-limit)
  }
  return [...errorLogs]
}

/**
 * 清空错误日志
 */
export function clearErrorLogs() {
  errorLogs.length = 0
}

/**
 * 导出错误日志
 */
export function exportErrorLogs(): string {
  return JSON.stringify(errorLogs, null, 2)
}

/**
 * 错误边界辅助函数
 */
export function createErrorBoundaryHandler(componentName: string) {
  return (error: Error, errorInfo: React.ErrorInfo) => {
    const errorDetail: ErrorInfo = {
      type: ErrorType.CLIENT,
      level: ErrorLevel.CRITICAL,
      message: `组件 ${componentName} 发生错误`,
      detail: error.message,
      stack: error.stack,
      timestamp: Date.now(),
      context: {
        componentStack: errorInfo.componentStack
      }
    }

    handleError(error, {
      showNotification: true,
      showMessage: false,
      logToConsole: true,
      reportToServer: true
    })

    return errorDetail
  }
}

/**
 * Promise错误处理包装器
 */
export function wrapPromise<T>(
  promise: Promise<T>,
  config?: ErrorHandlerConfig
): Promise<T> {
  return promise.catch((error) => {
    handleError(error, config)
    throw error
  })
}

/**
 * 异步函数错误处理装饰器
 */
export function withErrorHandler(config?: ErrorHandlerConfig) {
  return function <T extends (...args: any[]) => Promise<any>>(
    target: any,
    propertyKey: string,
    descriptor: TypedPropertyDescriptor<T>
  ) {
    const originalMethod = descriptor.value!

    descriptor.value = async function (...args: any[]) {
      try {
        return await originalMethod.apply(this, args)
      } catch (error) {
        handleError(error as Error, config)
        throw error
      }
    } as T

    return descriptor
  }
}

/**
 * 重试机制
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: {
    maxRetries?: number
    initialDelay?: number
    maxDelay?: number
    backoffFactor?: number
    onRetry?: (attempt: number, error: Error) => void
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 10000,
    backoffFactor = 2,
    onRetry
  } = options

  let lastError: Error

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error as Error

      if (attempt < maxRetries) {
        const delay = Math.min(
          initialDelay * Math.pow(backoffFactor, attempt),
          maxDelay
        )

        if (onRetry) {
          onRetry(attempt + 1, lastError)
        }

        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
  }

  throw lastError!
}

/**
 * 批量错误处理
 */
export function handleBatchErrors(
  errors: Array<{ error: Error; context?: any }>,
  config?: ErrorHandlerConfig
): ErrorInfo[] {
  return errors.map(({ error, context }) => {
    const errorInfo = handleError(error, {
      ...config,
      showMessage: false,
      showNotification: false
    })

    if (context) {
      errorInfo.context = { ...errorInfo.context, ...context }
    }

    return errorInfo
  })
}

/**
 * 错误恢复策略
 */
export interface RecoveryStrategy {
  canRecover: (error: ErrorInfo) => boolean
  recover: (error: ErrorInfo) => Promise<void>
}

const recoveryStrategies: RecoveryStrategy[] = []

/**
 * 注册错误恢复策略
 */
export function registerRecoveryStrategy(strategy: RecoveryStrategy) {
  recoveryStrategies.push(strategy)
}

/**
 * 尝试错误恢复
 */
export async function tryRecover(errorInfo: ErrorInfo): Promise<boolean> {
  for (const strategy of recoveryStrategies) {
    if (strategy.canRecover(errorInfo)) {
      try {
        await strategy.recover(errorInfo)
        return true
      } catch (err) {
        console.error('Recovery failed:', err)
      }
    }
  }
  return false
}

// 默认导出
export default {
  handleError,
  createErrorHandler,
  parseAxiosError,
  parseError,
  getErrorLogs,
  clearErrorLogs,
  exportErrorLogs,
  wrapPromise,
  retryWithBackoff,
  handleBatchErrors,
  registerRecoveryStrategy,
  tryRecover,
  ErrorType,
  ErrorLevel
}
