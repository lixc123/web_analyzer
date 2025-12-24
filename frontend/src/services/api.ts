import axios, { AxiosError } from 'axios'

// 动态获取API baseURL - 支持本地和局域网访问
const getApiBaseURL = () => {
  const hostname = window.location.hostname;
  // 如果是localhost或127.0.0.1，直接使用localhost
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:8000/api/v1';
  }
  // 如果是局域网IP，假设后端在同一台机器的8000端口
  // 用户可能需要根据实际部署情况调整这个逻辑
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

// 请求拦截器
apiClient.interceptors.request.use(
  (config) => {
    // 可以在这里添加认证token等
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器
apiClient.interceptors.response.use(
  (response) => {
    return response
  },
  (error: AxiosError) => {
    // 统一错误处理
    const message = (error.response?.data as any)?.detail || error.message || '请求失败'
    return Promise.reject(new Error(message))
  }
)

// 类型定义
export interface CrawlerConfig {
  url: string
  max_depth: number
  follow_redirects: boolean
  capture_screenshots: boolean
  headless: boolean
  user_agent?: string
  timeout: number
}

export interface CrawlerSession {
  session_id: string
  session_name?: string
  url: string
  status: 'created' | 'starting' | 'running' | 'stopped' | 'completed' | 'failed'
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
