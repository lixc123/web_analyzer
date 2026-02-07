import React, { useState, useEffect } from 'react'
import {
  Card,
  Form,
  Input,
  Switch,
  Button,
  Space,
  Table,
  Tag,
  Progress,
  Modal,
  Drawer,
  Typography,
  Alert,
  Tooltip,
  Popconfirm,
  notification,
  Badge,
  Divider,
  Select,
  theme
} from 'antd'
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  StopOutlined,
  DeleteOutlined,
  EyeOutlined,
  DownloadOutlined,
  ReloadOutlined,
  SettingOutlined,
  ClearOutlined
} from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { crawlerApi, CrawlerConfig, CrawlerSession, RequestRecord, HookOptions } from '@services/api'

const { CheckableTag } = Tag

const { Title, Text } = Typography
const { TextArea } = Input
const { Option } = Select

// Hook 选项配置
const HOOK_OPTIONS_CONFIG = [
  { key: 'network', label: '网络请求', description: 'Fetch/XHR 请求拦截，获取调用栈', risk: 'low' },
  { key: 'storage', label: '存储监控', description: 'localStorage/sessionStorage/IndexedDB', risk: 'medium' },
  { key: 'userInteraction', label: '用户交互', description: '点击、输入、滚动等事件', risk: 'high' },
  { key: 'form', label: '表单跟踪', description: '表单输入和提交', risk: 'medium' },
  { key: 'dom', label: 'DOM监控', description: 'DOM变化监控', risk: 'high' },
  { key: 'navigation', label: '导航历史', description: 'History API 跟踪', risk: 'medium' },
  { key: 'console', label: 'Console拦截', description: '控制台日志拦截', risk: 'high' },
  { key: 'performance', label: '性能数据', description: '页面性能指标', risk: 'low' },
  { key: 'websocket', label: 'WebSocket', description: 'WebSocket connect/send/receive 事件', risk: 'medium' },
  { key: 'crypto', label: 'Crypto', description: 'Web Crypto API (encrypt/decrypt/sign/verify)', risk: 'high' },
  { key: 'storageExport', label: '存储导出', description: '页面加载后导出 local/session/cookies/indexedDB', risk: 'high' },
  { key: 'stateManagement', label: '状态管理', description: 'Redux/Vuex/Pinia 状态快照/变更', risk: 'high' },
] as const

type HookOptionKey = typeof HOOK_OPTIONS_CONFIG[number]['key']

// 默认只开启网络请求（风险最低且最有用）
const DEFAULT_HOOK_OPTIONS: HookOptions = {
  network: true,
  storage: false,
  userInteraction: false,
  form: false,
  dom: false,
  navigation: false,
  console: false,
  performance: false,
  websocket: false,
  crypto: false,
  storageExport: false,
  stateManagement: false,
}

type StopProgress = {
  phase?: string
  percent?: number
  detail?: string
  updated_at?: string
}

const CrawlerPage: React.FC = () => {
  const { token } = theme.useToken()
  const [form] = Form.useForm()
  const [isStarted, setIsStarted] = useState(false)
  const [isBrowserReady, setIsBrowserReady] = useState(false)  // 浏览器已打开但未录制
  const [selectedSession, setSelectedSession] = useState<string | null>(null)
  const [requestsDrawerVisible, setRequestsDrawerVisible] = useState(false)
  const [configModalVisible, setConfigModalVisible] = useState(false)
  const [currentUrl, setCurrentUrl] = useState<string>('')
  const [realtimeRequests, setRealtimeRequests] = useState<any[]>([])
  const [requestsPage, setRequestsPage] = useState<number>(1)
  const [requestsPageSize, setRequestsPageSize] = useState<number>(30)
  const [isStopping, setIsStopping] = useState(false)
  const [stopModalVisible, setStopModalVisible] = useState(false)
  const [stopProgress, setStopProgress] = useState<StopProgress>({ phase: '', percent: 0, detail: '' })
  const [requestFilters, setRequestFilters] = useState<{
    q?: string
    resource_type?: string
    method?: string
    status?: number
  }>({})
  const [hookOptions, setHookOptions] = useState<HookOptions>(DEFAULT_HOOK_OPTIONS)
  const queryClient = useQueryClient()

  const stopPercentRaw = Number(stopProgress.percent)
  const stopPercent = Math.max(0, Math.min(100, Number.isFinite(stopPercentRaw) ? stopPercentRaw : 0))

  // 监听WebSocket爬虫进度消息实现实时预览
  useEffect(() => {
    const handleCrawlerProgress = (event: CustomEvent) => {
      const progressData = event.detail
      if (progressData && selectedSession && progressData.session_id === selectedSession) {
        // 更新当前URL
        if (progressData.current_url) {
          setCurrentUrl(progressData.current_url)
        }
        
        // 更新实时请求列表
        if (progressData.recent_requests) {
          setRealtimeRequests(prev => {
            const combined = [...prev, ...progressData.recent_requests]
            // 保留最近200个请求，避免内存占用过大
            return combined.slice(-200)
          })
        }

        if (progressData.stop_progress) {
          setStopProgress(progressData.stop_progress)
        }

        if (progressData.status === 'stopping') {
          setIsStopping(true)
          setStopModalVisible(true)
        }

        if (progressData.status === 'browser_ready') {
          setIsBrowserReady(true)
          setIsStarted(false)
        }

        if (progressData.status === 'running') {
          setIsStarted(true)
          setIsBrowserReady(false)
        }

        if (progressData.status === 'completed' || progressData.status === 'failed') {
          setIsStarted(false)
          setIsBrowserReady(false)
          setIsStopping(false)
          setStopModalVisible(false)
        }
      }
    }

    window.addEventListener('crawler-progress', handleCrawlerProgress as EventListener)
    return () => {
      window.removeEventListener('crawler-progress', handleCrawlerProgress as EventListener)
    }
  }, [selectedSession])

  useEffect(() => {
    setRequestsPage(1)
  }, [selectedSession])

  // 获取所有会话
  const { data: sessions, isLoading: sessionsLoading, refetch: refetchSessions } = useQuery({
    queryKey: ['crawler-sessions'],
    queryFn: crawlerApi.getSessions,
    refetchInterval: 5000, // 5秒刷新
  })

  // 获取选定会话的请求
  const { data: requestsData, isLoading: requestsLoading } = useQuery({
    queryKey: ['session-requests', selectedSession, requestsPage, requestsPageSize, requestFilters],
    queryFn: () => {
      if (!selectedSession) {
        return Promise.resolve(null)
      }
      const offset = (requestsPage - 1) * requestsPageSize
      return crawlerApi.getSessionRequests(selectedSession, offset, requestsPageSize, requestFilters)
    },
    enabled: !!selectedSession,
    refetchInterval: selectedSession && isStarted ? 2000 : false, // 录制时每2秒刷新一次
  })

  // 启动爬虫
  const startMutation = useMutation({
    mutationFn: ({ config, sessionName }: { config: CrawlerConfig; sessionName?: string }) =>
      crawlerApi.startCrawler(config, sessionName),
    onSuccess: (data) => {
      const isManualMode = data.status === 'browser_ready'
      notification.success({
        message: isManualMode ? '浏览器已打开' : '爬虫启动成功',
        description: isManualMode 
          ? `会话 ${data.session_id} 浏览器已打开，请手动开始录制`
          : `会话 ${data.session_id} 已开始录制`
      })
      if (isManualMode) {
        setIsBrowserReady(true)
        setIsStarted(false)
      } else {
        setIsStarted(true)
        setIsBrowserReady(false)
      }
      setSelectedSession(data.session_id)
      queryClient.invalidateQueries({ queryKey: ['crawler-sessions'] })
    },
    onError: (error: Error) => {
      notification.error({
        message: '爬虫启动失败',
        description: error.message
      })
    }
  })

  // 手动开始录制
  const startManualRecordingMutation = useMutation({
    mutationFn: (sessionId: string) => crawlerApi.startManualRecording(sessionId),
    onSuccess: (_data, sessionId) => {
      notification.success({
        message: '录制已开始',
        description: `会话 ${sessionId} 开始录制网络请求`
      })
      setIsStarted(true)
      setIsBrowserReady(false)
      queryClient.invalidateQueries({ queryKey: ['crawler-sessions'] })
    },
    onError: (error: Error) => {
      notification.error({
        message: '开始录制失败',
        description: error.message
      })
    }
  })

  // 清空会话请求
  const clearRequestsMutation = useMutation({
    mutationFn: (sessionId: string) => crawlerApi.clearSessionRequests(sessionId),
    onSuccess: (_data, sessionId) => {
      setRealtimeRequests([])
      setRequestsPage(1)
      queryClient.invalidateQueries({ queryKey: ['crawler-sessions'] })
      queryClient.invalidateQueries({ queryKey: ['session-requests', sessionId] })
      queryClient.refetchQueries({ queryKey: ['session-requests', sessionId] })
      notification.success({
        message: '已清空会话请求'
      })
    },
    onError: (error: Error) => {
      notification.error({
        message: '清空会话请求失败',
        description: error.message
      })
    }
  })

  // 下载会话目录 zip
  const downloadZipMutation = useMutation({
    mutationFn: (sessionId: string) => crawlerApi.downloadSessionZip(sessionId),
    onSuccess: (blob, sessionId) => {
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${sessionId}.zip`
      a.click()
      URL.revokeObjectURL(url)

      notification.success({
        message: '会话打包下载成功'
      })
    },
    onError: (error: Error) => {
      notification.error({
        message: '会话打包下载失败',
        description: error.message
      })
    }
  })

  // 停止爬虫
  const stopMutation = useMutation({
    mutationFn: crawlerApi.stopCrawler,
    onSuccess: (_data, sessionId) => {
      notification.info({
        message: '停止请求已提交',
        description: '正在收尾导出数据，请稍候'
      })
      setIsStarted(false)
      setIsStopping(true)
      setStopModalVisible(true)
      queryClient.invalidateQueries({ queryKey: ['crawler-sessions'] })
      queryClient.invalidateQueries({ queryKey: ['session-requests', sessionId] })
      queryClient.refetchQueries({ queryKey: ['session-requests', sessionId] })
    },
    onError: (error: Error) => {
      notification.error({
        message: '停止爬虫失败',
        description: error.message
      })
    }
  })

  // 删除会话
  const deleteMutation = useMutation({
    mutationFn: crawlerApi.deleteSession,
    onSuccess: () => {
      notification.success({
        message: '会话已删除'
      })
      queryClient.invalidateQueries({ queryKey: ['crawler-sessions'] })
      if (selectedSession) {
        setSelectedSession(null)
      }
    },
    onError: (error: Error) => {
      notification.error({
        message: '删除会话失败',
        description: error.message
      })
    }
  })

  // 导出会话
  const exportMutation = useMutation({
    mutationFn: ({ sessionId, format }: { sessionId: string; format: 'json' | 'csv' | 'har' }) =>
      crawlerApi.exportSession(sessionId, format),
    onSuccess: (data, variables) => {
      // 创建下载链接（后端返回 {session_id, format, data, message}）
      const payload = (data as any)?.data
      const fmt = variables.format
      let contentType = 'application/json; charset=utf-8'
      let body: string

      if (fmt === 'csv') {
        contentType = 'text/csv; charset=utf-8'
        body = typeof payload === 'string' ? payload : String(payload ?? '')
      } else {
        // json/har 均为 JSON
        body = JSON.stringify(payload ?? data, null, 2)
      }

      const blob = new Blob([body], { type: contentType })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `session_${variables.sessionId}.${variables.format}`
      a.click()
      URL.revokeObjectURL(url)

      notification.success({
        message: '数据导出成功'
      })
    },
    onError: (error: Error) => {
      notification.error({
        message: '数据导出失败',
        description: error.message
      })
    }
  })

  const handleStart = async () => {
    if (startMutation.isPending) {
      // 防止重复提交
      return
    }
    
    try {
      const values = await form.validateFields()
      
      // 从 localStorage 读取 Chrome 路径配置
      const chromePath = localStorage.getItem('chrome_path') || undefined
      
      const config: CrawlerConfig = {
        url: values.url,
        max_depth: values.max_depth || 3,
        follow_redirects: values.follow_redirects ?? true,
        capture_screenshots: values.capture_screenshots ?? false,
        headless: values.headless ?? false,
        user_agent: values.user_agent,
        timeout: values.timeout || 30,
        manual_recording: values.manual_recording ?? false,  // 手动控制录制模式
        hook_options: hookOptions,  // Hook 功能选项
        use_system_chrome: values.use_system_chrome ?? false,  // 使用系统 Chrome
        chrome_path: chromePath  // 自定义 Chrome 路径
      }
      
      startMutation.mutate({
        config,
        sessionName: values.session_name
      })
    } catch (error) {
      console.error('表单验证失败:', error)
    }
  }

  const handleStartManualRecording = () => {
    if (selectedSession) {
      startManualRecordingMutation.mutate(selectedSession)
    }
  }

  const handleStop = () => {
    if (selectedSession) {
      stopMutation.mutate(selectedSession)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'processing'
      case 'stopping': return 'processing'
      case 'completed': return 'success'
      case 'failed': return 'error'
      case 'stopped': return 'warning'
      case 'browser_ready': return 'warning'
      default: return 'default'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'created': return '已创建'
      case 'starting': return '启动中'
      case 'running': return '录制中'
      case 'stopping': return '停止中'
      case 'completed': return '已完成'
      case 'failed': return '失败'
      case 'stopped': return '已停止'
      case 'browser_ready': return '等待录制'
      default: return '未知'
    }
  }

  // 会话表格列定义
  const sessionColumns = [
    {
      title: '会话名称',
      dataIndex: 'session_name',
      key: 'session_name',
      render: (name: string, record: CrawlerSession) => name || `会话-${record.session_id.slice(-8)}`
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Tooltip title={url}>
          <a href={url} target="_blank" rel="noopener noreferrer">{url}</a>
        </Tooltip>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={getStatusColor(status)}>{getStatusText(status)}</Tag>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (time: string) => new Date(time).toLocaleString()
    },
    {
      title: '操作',
      key: 'actions',
      render: (record: CrawlerSession) => (
        <Space>
          <Button
            type="text"
            icon={<EyeOutlined />}
            onClick={() => {
              setSelectedSession(record.session_id)
              setRequestsDrawerVisible(true)
            }}
          />
          {record.status === 'browser_ready' ? (
            <Button
              type="text"
              icon={<PlayCircleOutlined />}
              onClick={() => {
                setSelectedSession(record.session_id)
                startManualRecordingMutation.mutate(record.session_id)
              }}
              loading={startManualRecordingMutation.isPending}
              style={{ color: '#52c41a' }}
            />
          ) : record.status === 'running' ? (
            <Button
              type="text"
              icon={<StopOutlined />}
              onClick={() => stopMutation.mutate(record.session_id)}
              loading={stopMutation.isPending}
            />
          ) : record.status === 'stopping' ? (
            <Button
              type="text"
              icon={<StopOutlined />}
              loading
              disabled
            />
          ) : (
            <Button
              type="text"
              icon={<DownloadOutlined />}
              onClick={() => downloadZipMutation.mutate(record.session_id)}
              loading={downloadZipMutation.isPending}
            />
          )}
          <Popconfirm
            title="确定要删除这个会话吗？"
            onConfirm={() => deleteMutation.mutate(record.session_id)}
          >
            <Button
              type="text"
              icon={<DeleteOutlined />}
              danger
              loading={deleteMutation.isPending}
            />
          </Popconfirm>
        </Space>
      )
    }
  ]

  // 请求表格列定义
  const requestColumns = [
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => <Tag>{method}</Tag>
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true
    },
    {
      title: '状态码',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (code: number) => (
        <Tag color={code >= 400 ? 'red' : code >= 300 ? 'orange' : 'green'}>
          {code || 'N/A'}
        </Tag>
      )
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 160,
      render: (time: string | number) => {
        // 处理时间戳格式：如果是数字且小于13位，可能是秒级时间戳，需要转换为毫秒
        let timestamp: number
        if (typeof time === 'string') {
          timestamp = parseFloat(time)
        } else {
          timestamp = time
        }
        
        // 如果时间戳是秒级（10位数字），转换为毫秒级
        if (timestamp < 10000000000) {
          timestamp = timestamp * 1000
        }
        
        // 验证时间戳是否合理（2020年后）
        const date = new Date(timestamp)
        if (date.getFullYear() < 2020) {
          return '时间格式错误'
        }
        
        return date.toLocaleString()
      }
    }
  ]

  return (
    <div className="page-container">
      {/* 页面头部 */}
      <div className="page-header">
        <div>
          <Title level={2} className="page-title">网络爬虫</Title>
          <Text className="page-description">录制和分析网络流量数据</Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetchSessions()}>
            刷新
          </Button>
          <Button icon={<SettingOutlined />} onClick={() => setConfigModalVisible(true)}>
            高级配置
          </Button>
        </Space>
      </div>

      {/* 爬虫控制面板 */}
      <Card title="爬虫控制" className="mb-24">
        <Modal
          title="正在停止并收尾"
          open={stopModalVisible}
          className="wa-stop-progress-modal"
          onCancel={() => setStopModalVisible(false)}
          footer={null}
          closable
          maskClosable={false}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <Text strong>阶段</Text>
              <div style={{ marginTop: 4 }}>{stopProgress.phase || 'stopping'}</div>
            </div>
            <div>
              <Text strong>详情</Text>
              <div style={{ marginTop: 4 }}>{stopProgress.detail || 'processing'}</div>
            </div>
            <Progress percent={stopPercent} status="normal" />
            <Alert
              type="info"
              showIcon
              message="停止可能需要一些时间"
              description="录制较多时会导出会话文件、生成回放代码并关闭浏览器。页面无需等待请求返回，进度会在此处实时更新。"
            />
          </div>
        </Modal>
        {/* 网络控制台 - 默认显示，类似F12 */}
        <Card 
          title={
            <Space>
              <span>网络控制台</span>
              <Badge 
                count={requestsData?.total || 0} 
                showZero 
                style={{ backgroundColor: '#52c41a' }}
              />
              {selectedSession && (
                <>
                  <Divider orientation="vertical" />
                  <Text code style={{ fontSize: 12 }}>
                    {selectedSession}
                  </Text>
                </>
              )}
            </Space>
          }
          style={{ marginBottom: 16 }}
          size="small"
          extra={
            <Space size="small">
              <Input
                size="small"
                placeholder="搜索 URL/方法/状态码"
                style={{ width: 200 }}
                allowClear
                value={requestFilters.q || ''}
                onChange={(e) => {
                  const value = e.target.value
                  setRequestsPage(1)
                  setRequestFilters(prev => ({ ...prev, q: value || undefined }))
                }}
                disabled={!selectedSession}
              />
              <Button
                size="small"
                onClick={() => setRequestsPage(prev => Math.max(1, prev - 1))}
                disabled={!selectedSession || requestsPage <= 1}
              >
                上一页
              </Button>
              <Button
                size="small"
                onClick={() => {
                  const total = requestsData?.total || 0
                  const maxPage = Math.max(1, Math.ceil(total / requestsPageSize))
                  setRequestsPage(prev => Math.min(maxPage, prev + 1))
                }}
                disabled={!selectedSession || ((requestsData?.total || 0) <= requestsPage * requestsPageSize)}
              >
                下一页
              </Button>
              <Button 
                size="small" 
                icon={<ClearOutlined />}
                onClick={() => {
                  if (!selectedSession) {
                    setRealtimeRequests([])
                    return
                  }
                  clearRequestsMutation.mutate(selectedSession)
                }}
                loading={clearRequestsMutation.isPending}
                disabled={!selectedSession}
              >
                清空
              </Button>
              <Button 
                size="small" 
                type={selectedSession ? 'primary' : 'default'}
                onClick={() => {
                  if (selectedSession) {
                    setRequestsDrawerVisible(true)
                  }
                }}
                disabled={!selectedSession}
              >
                详情
              </Button>
            </Space>
          }
        >
          <div style={{ 
            height: 200, 
            overflowY: 'auto',
            backgroundColor: token.colorFillQuaternary,
            border: `1px solid ${token.colorBorder}`,
            borderRadius: 4,
            padding: 8
          }}>
            {!selectedSession ? (
              <div style={{ 
                textAlign: 'center', 
                color: token.colorTextSecondary, 
                lineHeight: '180px',
                fontSize: 14 
              }}>
                选择或启动一个会话以查看网络活动
              </div>
            ) : requestsLoading ? (
              <div style={{ 
                textAlign: 'center', 
                color: token.colorTextSecondary, 
                lineHeight: '180px',
                fontSize: 14 
              }}>
                加载中...
              </div>
            ) : (requestsData?.requests && requestsData.requests.length > 0) ? (
              <div>
                {(requestsData?.requests || []).map((req, index) => (
                  <div 
                    key={`${req.id || req.timestamp || Date.now()}-${index}-${Math.random()}`} 
                    style={{ 
                      marginBottom: 4, 
                      fontSize: 12,
                      padding: '4px 8px',
                      backgroundColor: token.colorBgElevated,
                      border: `1px solid ${token.colorBorderSecondary}`,
                      borderRadius: 2,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8
                    }}
                  >
                    <Tag color={req.method === 'GET' ? 'blue' : 'green'}>
                      {req.method}
                    </Tag>
                    {req.status && (
                      <Tag 
                        color={req.status >= 400 ? 'red' : req.status >= 300 ? 'orange' : 'green'}
                      >
                        {req.status}
                      </Tag>
                    )}
                    <Tag 
                      color={
                        req.resource_type === 'script' ? 'orange' : 
                        req.resource_type === 'xhr' || req.resource_type === 'fetch' ? 'blue' : 
                        req.resource_type === 'document' ? 'green' : 'default'
                      }
                    >
                      {req.resource_type || 'other'}
                    </Tag>
                    <Text 
                      style={{ 
                        flex: 1, 
                        overflow: 'hidden', 
                        textOverflow: 'ellipsis', 
                        whiteSpace: 'nowrap',
                        fontSize: 11 
                      }}
                      title={req.url}
                    >
                      {req.url}
                    </Text>
                    <Text type="secondary" style={{ fontSize: 10 }}>
                      {(() => {
                        const raw = req.timestamp
                        if (raw === undefined || raw === null) {
                          return ''
                        }
                        const ts = typeof raw === 'string' ? parseFloat(raw) : raw
                        const ms = ts < 10000000000 ? ts * 1000 : ts
                        return new Date(ms).toLocaleTimeString()
                      })()}
                    </Text>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ 
                textAlign: 'center', 
                color: token.colorTextSecondary, 
                lineHeight: '180px',
                fontSize: 14 
              }}>
                暂无网络活动
              </div>
            )}
          </div>
        </Card>

        <Form
          form={form}
          layout="vertical"
          initialValues={{
            max_depth: 3,
            follow_redirects: true,
            capture_screenshots: false,
            headless: false,
            timeout: 30,
            manual_recording: false,
            use_system_chrome: false
          }}
        >
          <Form.Item
            label="目标URL"
            name="url"
            rules={[
              { required: true, message: '请输入目标URL' },
              { type: 'url', message: '请输入有效的URL' }
            ]}
          >
            <Input placeholder="https://example.com" />
          </Form.Item>

          <Form.Item label="会话名称" name="session_name">
            <Input placeholder="可选，用于标识此次爬虫会话" />
          </Form.Item>

          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <Form.Item
              label={
                <Tooltip title="推荐 2-4。语义：1=只访问起始页；2=起始页+其直接链接；3=再向下1层。为防止爆炸式爬取，后端默认最多访问40页（可配置覆盖）。">
                  最大深度
                </Tooltip>
              }
              name="max_depth"
              style={{ minWidth: 120 }}
            >
              <Input type="number" min={1} max={10} />
            </Form.Item>

            <Form.Item label="超时时间(秒)" name="timeout" style={{ minWidth: 120 }}>
              <Input type="number" min={5} max={300} />
            </Form.Item>

            <Form.Item
              label={
                <Tooltip title="关闭后：若页面导航发生重定向（最终URL与目标URL不同），不会继续从重定向后的页面提取/入队链接。">
                  跟随重定向
                </Tooltip>
              }
              name="follow_redirects"
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>

            <Form.Item label="无头模式" name="headless" valuePropName="checked">
              <Switch />
            </Form.Item>

            <Form.Item label="截图" name="capture_screenshots" valuePropName="checked">
              <Switch />
            </Form.Item>

            <Form.Item 
              label={
                <Tooltip title="开启后先打开浏览器，您可以浏览页面后手动点击开始录制，而不是打开就立即录制">
                  手动控制录制
                </Tooltip>
              } 
              name="manual_recording" 
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>

            <Form.Item 
              label={
                <Tooltip title="使用系统安装的 Chrome 浏览器，而非 Playwright 内置的 Chromium。可以更好地绕过网站检测">
                  系统Chrome
                </Tooltip>
              } 
              name="use_system_chrome" 
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          </div>

          {/* Hook 功能选项 */}
          <div style={{ marginTop: 16, marginBottom: 16 }}>
            <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 12 }}>
              <Text strong>JS Hook 选项</Text>
              <Tooltip title="这些选项会向页面注入JS代码来捕获更多信息。开启过多可能触发网站风控，建议只开启必要的选项。">
                <Text type="secondary" style={{ fontSize: 12, cursor: 'help' }}>
                  (⚠️ 开启过多可能触发风控)
                </Text>
              </Tooltip>
              <Button 
                size="small" 
                type="link"
                onClick={() => {
                  const allEnabled = HOOK_OPTIONS_CONFIG.every((opt) => hookOptions[opt.key])
                  const newOptions = HOOK_OPTIONS_CONFIG.reduce((acc, opt) => {
                    (acc as any)[opt.key] = !allEnabled
                    return acc
                  }, {} as HookOptions)
                  setHookOptions(newOptions)
                }}
              >
                {Object.values(hookOptions).every(v => v) ? '取消全选' : '全选'}
              </Button>
              <Button
                size="small"
                type="link"
                onClick={() => setHookOptions(DEFAULT_HOOK_OPTIONS)}
              >
                重置默认
              </Button>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {HOOK_OPTIONS_CONFIG.map(option => (
                <Tooltip 
                  key={option.key} 
                  title={
                    <div>
                      <div>{option.description}</div>
                      <div style={{ marginTop: 4 }}>
                        风险等级: {option.risk === 'low' ? '🟢 低' : option.risk === 'medium' ? '🟡 中' : '🔴 高'}
                      </div>
                    </div>
                  }
                >
                  <Tag.CheckableTag
                    checked={hookOptions[option.key as HookOptionKey]}
                    onChange={(checked) => {
                      setHookOptions(prev => ({
                        ...prev,
                        [option.key]: checked
                      }))
                    }}
                    style={{
                      padding: '4px 12px',
                      border: `1px solid ${hookOptions[option.key as HookOptionKey] ? '#1890ff' : token.colorBorder}`,
                      backgroundColor: hookOptions[option.key as HookOptionKey] ? '#1890ff' : 'transparent',
                      color: hookOptions[option.key as HookOptionKey] ? '#fff' : token.colorText
                    }}
                  >
                    {option.label}
                  </Tag.CheckableTag>
                </Tooltip>
              ))}
            </div>
          </div>

          <Space>
            <Button
              type="primary"
              icon={<PlayCircleOutlined />}
              onClick={handleStart}
              loading={startMutation.isPending}
              disabled={isStarted || isBrowserReady || isStopping}
            >
              {form.getFieldValue('manual_recording') ? '打开浏览器' : '开始录制'}
            </Button>
            {isBrowserReady && (
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={handleStartManualRecording}
                loading={startManualRecordingMutation.isPending}
                style={{ backgroundColor: '#52c41a', borderColor: '#52c41a' }}
              >
                开始录制
              </Button>
            )}
            <Button
              icon={<StopOutlined />}
              onClick={handleStop}
              loading={stopMutation.isPending}
              disabled={(!isStarted && !isBrowserReady) || isStopping}
            >
              停止录制
            </Button>
          </Space>
        </Form>
      </Card>

      {/* 会话列表 */}
      <Card title="爬虫会话" loading={sessionsLoading}>
        <Table
          columns={sessionColumns}
          dataSource={sessions}
          rowKey="session_id"
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => `共 ${total} 个会话`
          }}
        />
      </Card>

      {/* 请求详情抽屉 */}
      <Drawer
        title={`会话请求详情 - ${selectedSession?.slice(-8) || ''}`}
        placement="right"
        size="large"
        onClose={() => setRequestsDrawerVisible(false)}
        open={requestsDrawerVisible}
      >
        <div style={{ marginBottom: 16 }}>
          <Space>
            <Text strong>过滤器:</Text>
            <Input
              placeholder="搜索URL"
              style={{ width: 180 }}
              allowClear
              value={requestFilters.q || ''}
              onChange={(e) => {
                const value = e.target.value
                setRequestsPage(1)
                setRequestFilters(prev => ({ ...prev, q: value || undefined }))
              }}
            />
            <Select
              placeholder="选择资源类型"
              style={{ width: 120 }}
              allowClear
              onChange={(value) => {
                setRequestsPage(1)
                setRequestFilters(prev => ({ ...prev, resource_type: value || undefined }))
              }}
            >
              <Option value="script">JavaScript</Option>
              <Option value="xhr">XHR/Fetch</Option>
              <Option value="document">Document</Option>
              <Option value="stylesheet">CSS</Option>
              <Option value="image">Images</Option>
              <Option value="font">Fonts</Option>
            </Select>
          </Space>
        </div>
        <Table
          columns={[
            ...requestColumns,
            {
              title: '资源类型',
              dataIndex: 'resource_type',
              key: 'resource_type',
              width: 100,
              render: (type: string) => (
                <Tag color={
                  type === 'script' ? 'orange' : 
                  type === 'xhr' || type === 'fetch' ? 'blue' : 
                  type === 'document' ? 'green' : 
                  type === 'stylesheet' ? 'purple' : 
                  type === 'image' ? 'cyan' : 'default'
                }>
                  {type || 'other'}
                </Tag>
              )
            }
          ]}
          dataSource={requestsData?.requests}
          rowKey="id"
          loading={requestsLoading}
          pagination={{
            current: requestsPage,
            pageSize: requestsPageSize,
            total: requestsData?.total || 0,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => `共 ${total} 个请求`,
            onChange: (page, pageSize) => {
              setRequestsPage(page)
              setRequestsPageSize(pageSize)
            }
          }}
        />
      </Drawer>

      {/* 高级配置弹窗 */}
      <Modal
        title="高级配置"
        open={configModalVisible}
        onCancel={() => setConfigModalVisible(false)}
        footer={null}
        width={600}
      >
        <Form layout="vertical">
          <Form.Item label="自定义User-Agent" name="user_agent">
            <TextArea 
              rows={3}
              placeholder="留空使用默认User-Agent"
            />
          </Form.Item>

          <Alert
            title="高级选项"
            description="这些设置将影响爬虫的行为和性能，请谨慎配置"
            type="info"
            showIcon
          />
        </Form>
      </Modal>
    </div>
  )
}

export default CrawlerPage
