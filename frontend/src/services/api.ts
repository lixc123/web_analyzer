import axios, { AxiosError, AxiosRequestConfig } from 'axios'
import { handleError, retryWithBackoff } from '@/utils/errorHandler'

// 动态获取API baseURL - 支持环境变量配置和自动检测
const getApiBaseURL = () => {
  // 优先使用环境变量配置
  const envBaseURL = import.meta.env.VITE_API_BASE_URL;
  if (envBaseURL) {
    return `${envBaseURL}/api/v1`;
  }

  // 如果没有配置环境变量，使用动态检测
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;

  // 如果是localhost或127.0.0.1，直接使用localhost
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:8000/api/v1';
  }

  // 生产环境：使用相对路径（假设前后端同域）
  if (protocol === 'https:') {
    return `https://${hostname}/api/v1`;
  }

  // 局域网IP，假设后端在同一台机器的8000端口
  return `http://${hostname.replace(/:\d+$/, '')}:8000/api/v1`;
};

// 创建axios实例
const apiClient = axios.create({
  baseURL: getApiBaseURL(),
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 请求计数器（用于请求去重）
const pendingRequests = new Map<string, AbortController>()

// 生成请求唯一标识
function generateRequestKey(config: AxiosRequestConfig): string {
  const { method, url, params, data } = config
  return `${method}:${url}:${JSON.stringify(params)}:${JSON.stringify(data)}`
}

// 请求拦截器
apiClient.interceptors.request.use(
  (config) => {
    // 请求去重
    const requestKey = generateRequestKey(config)

    // 如果存在相同的pending请求，取消之前的请求
    if (pendingRequests.has(requestKey)) {
      const controller = pendingRequests.get(requestKey)!
      controller.abort()
      pendingRequests.delete(requestKey)
    }

    // 创建新的AbortController
    const controller = new AbortController()
    config.signal = controller.signal
    pendingRequests.set(requestKey, controller)

    // 可以在这里添加认证token等
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }

    // 添加请求时间戳
    config.headers['X-Request-Time'] = Date.now().toString()

    return config
  },
  (error) => {
    handleError(error, { showMessage: true })
    return Promise.reject(error)
  }
)

// 响应拦截器
apiClient.interceptors.response.use(
  (response) => {
    // 请求成功，从pending列表中移除
    const requestKey = generateRequestKey(response.config)
    pendingRequests.delete(requestKey)

    // 记录响应时间
    const requestTime = parseInt(response.config.headers['X-Request-Time'] as string || '0')
    if (requestTime) {
      const responseTime = Date.now() - requestTime
      console.log(`[API] ${response.config.method?.toUpperCase()} ${response.config.url} - ${responseTime}ms`)
    }

    return response
  },
  (error: AxiosError) => {
    // 请求失败，从pending列表中移除
    if (error.config) {
      const requestKey = generateRequestKey(error.config)
      pendingRequests.delete(requestKey)
    }

    // 如果是取消的请求，不显示错误
    if (axios.isCancel(error)) {
      console.log('[API] Request cancelled:', error.message)
      return Promise.reject(error)
    }

    // 统一错误处理
    handleError(error, {
      showMessage: true,
      showNotification: false,
      logToConsole: true
    })

    return Promise.reject(error)
  }
)

// 带重试的请求包装器
export async function requestWithRetry<T>(
  requestFn: () => Promise<T>,
  options?: {
    maxRetries?: number
    showRetryMessage?: boolean
  }
): Promise<T> {
  const { maxRetries = 3, showRetryMessage = false } = options || {}

  return retryWithBackoff(requestFn, {
    maxRetries,
    initialDelay: 1000,
    maxDelay: 5000,
    backoffFactor: 2,
    onRetry: (attempt, error) => {
      if (showRetryMessage) {
        console.log(`[API] Retry attempt ${attempt}/${maxRetries}:`, error.message)
      }
    }
  })
}

// 类型定义
// Hook 功能选项
export interface HookOptions {
  network: boolean           // 网络请求拦截 (fetch/XHR)
  storage: boolean           // 存储拦截 (localStorage/sessionStorage/IndexedDB)
  userInteraction: boolean   // 用户交互跟踪 (click/input等)
  form: boolean              // 表单数据跟踪
  dom: boolean               // DOM变化监控
  navigation: boolean        // 导航历史跟踪
  console: boolean           // Console日志拦截
  performance: boolean       // 性能数据监控
}

export interface CrawlerConfig {
  url: string
  max_depth: number
  follow_redirects: boolean
  capture_screenshots: boolean
  headless: boolean
  user_agent?: string
  timeout: number
  manual_recording?: boolean  // 手动控制录制模式
  hook_options?: HookOptions  // Hook 功能选项
  use_system_chrome?: boolean // 使用系统 Chrome
  chrome_path?: string        // 自定义 Chrome 路径
}

export interface CrawlerSession {
  session_id: string
  session_name?: string
  url: string
  status: 'created' | 'starting' | 'running' | 'stopping' | 'stopped' | 'completed' | 'failed' | 'browser_ready'
  created_at: string
  updated_at: string
  total_requests: number
  completed_requests: number
  errors: string[]
  progress: Record<string, any>
  config: CrawlerConfig
}

export interface RequestRecord {
  id: string
  url: string
  method: string
  status?: number
  status_code?: number
  resource_type?: string
  headers?: Record<string, string>
  request_headers?: Record<string, string>
  post_data?: string
  request_body?: string
  response_headers?: Record<string, string>
  response_body_path?: string
  response_body?: string
  timestamp: number | string
  session_id: string
}

export interface AnalysisConfig {
  analysis_type: 'entropy' | 'sensitive_params' | 'encryption_keywords' | 'all'
  min_entropy: number
  sensitive_keywords: string[]
  custom_rules: Record<string, any>
}

export interface AnalysisResult {
  analysis_id: string
  session_id?: string
  analysis_type: string
  results: Record<string, any>
  summary: Record<string, any>
  suspicious_requests: any[]
  timestamp: string
}

// 系统API
export const systemApi = {
  // 获取系统健康状态
  getHealth: async (): Promise<any> => {
    const response = await apiClient.get('/health')
    return response.data
  },

  // 获取系统统计
  getStats: async (): Promise<any> => {
    try {
      const response = await apiClient.get('/dashboard/stats')
      return response.data
    } catch (error) {
      console.error('获取统计数据失败:', error)
      // 返回默认空数据而非硬编码数据
      return {
        sessions: { active: 0, today: 0, total: 0 },
        requests: { total: 0, today: 0, success_rate: 0, errors: 0 },
        analysis: { total: 0, today: 0 },
        suspicious: { count: 0, trend: 0 },
        resources: {
          memory: 0,
          cpu: 0,
          disk: 0,
          connections: 0
        },
        services: {
          database: 'unknown'
        }
      }
    }
  }
}

// 爬虫API
export const crawlerApi = {
  // 启动爬虫
  startCrawler: async (config: CrawlerConfig, sessionName?: string): Promise<CrawlerSession> => {
    const response = await apiClient.post('/crawler/start', {
      config,
      session_name: sessionName
    })
    return response.data
  },

  // 停止爬虫
  stopCrawler: async (sessionId: string): Promise<void> => {
    await apiClient.post(`/crawler/stop/${sessionId}`)
  },

  // 手动开始录制（用于手动控制模式）
  startManualRecording: async (sessionId: string): Promise<void> => {
    await apiClient.post(`/crawler/start-recording/${sessionId}`)
  },

  // 获取爬虫状态
  getCrawlerStatus: async (sessionId: string): Promise<CrawlerSession> => {
    const response = await apiClient.get(`/crawler/status/${sessionId}`)
    return response.data
  },

  // 获取所有会话
  getSessions: async (): Promise<CrawlerSession[]> => {
    const response = await apiClient.get('/crawler/sessions')
    return response.data.sessions
  },

  // 获取会话请求
  getSessionRequests: async (
    sessionId: string,
    offset = 0,
    limit = 100,
    filters?: {
      q?: string
      resource_type?: string
      method?: string
      status?: number
    }
  ): Promise<{
    requests: RequestRecord[]
    total: number
    offset: number
    limit: number
  }> => {
    const response = await apiClient.get(`/crawler/requests/${sessionId}`, {
      params: { offset, limit, ...(filters || {}) }
    })
    return response.data
  },

  // 清空会话请求
  clearSessionRequests: async (sessionId: string): Promise<{ success: boolean; session_id: string; cleared_count: number }> => {
    const response = await apiClient.delete(`/crawler/requests/${sessionId}`)
    return response.data
  },

  // 删除会话
  deleteSession: async (sessionId: string): Promise<void> => {
    await apiClient.delete(`/crawler/session/${sessionId}`)
  },

  // 导出会话数据
  exportSession: async (sessionId: string, format: 'json' | 'csv' | 'har' = 'json'): Promise<any> => {
    const response = await apiClient.post(`/crawler/export/${sessionId}`, { format })
    return response.data
  },

  // 下载会话目录（zip）
  downloadSessionZip: async (sessionId: string): Promise<Blob> => {
    const response = await apiClient.get(`/crawler/download/${sessionId}`, {
      responseType: 'blob'
    })
    return response.data
  }
}

// 分析API
export const analysisApi = {
  // 分析请求
  analyze: async (sessionId?: string, requestsData?: any[], config?: AnalysisConfig): Promise<AnalysisResult> => {
    const response = await apiClient.post('/analysis/analyze', {
      session_id: sessionId,
      requests_data: requestsData,
      config: config || { analysis_type: 'all', min_entropy: 4.0, sensitive_keywords: [], custom_rules: {} }
    })
    return response.data
  },

  // 熵值分析
  analyzeEntropy: async (sessionId: string, minEntropy = 4.0): Promise<any> => {
    const response = await apiClient.get(`/analysis/entropy/${sessionId}`, {
      params: { min_entropy: minEntropy }
    })
    return response.data
  },

  // 敏感参数分析
  analyzeSensitiveParams: async (sessionId: string, customKeywords?: string): Promise<any> => {
    const response = await apiClient.get(`/analysis/sensitive-params/${sessionId}`, {
      params: { custom_keywords: customKeywords }
    })
    return response.data
  },

  // 加密关键词分析
  analyzeEncryptionKeywords: async (sessionId: string): Promise<any> => {
    const response = await apiClient.get(`/analysis/encryption-keywords/${sessionId}`)
    return response.data
  },

  // 获取分析摘要
  getAnalysisSummary: async (sessionId: string): Promise<any> => {
    const response = await apiClient.get(`/analysis/summary/${sessionId}`)
    return response.data
  },

  // 获取分析历史
  getAnalysisHistory: async (sessionId: string, limit = 20, offset = 0): Promise<any[]> => {
    const response = await apiClient.get(`/analysis/history/${sessionId}`, {
      params: { limit, offset }
    })
    return response.data.history
  },

  // 导出分析结果
  exportAnalysis: async (analysisId: string, format: 'json' | 'csv' | 'pdf' = 'json'): Promise<any> => {
    const response = await apiClient.post(`/analysis/export/${analysisId}`, { format })
    return response.data
  }
}


export default apiClient
