import React, { useCallback, useState, useEffect } from 'react'
import {
  Card,
  Table,
  Tag,
  Space,
  Button,
  Select,
  Input,
  Badge,
  Tooltip,
  Modal,
  Descriptions,
  Typography,
  message,
  Switch,
  Alert
} from 'antd'
import {
  ReloadOutlined,
  ClearOutlined,
  SearchOutlined,
  DesktopOutlined,
  MobileOutlined,
  AppleOutlined,
  AndroidOutlined,
  ChromeOutlined,
  GlobalOutlined,
  DownloadOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { useProxyWebSocket } from '@hooks/useProxyWebSocket'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'

const { Option } = Select
const { Text } = Typography

interface ProxyRequest {
  id: string
  method: string
  url: string
  source: 'web_browser' | 'desktop_app' | 'mobile_ios' | 'mobile_android'
  proxy_session_id?: string
  device_info?: {
    platform?: string
    device?: string
    browser?: string
    os?: string
  }
  timestamp: number
  status_code?: number
  response_time?: number
  response_size?: number
  http_version?: string
  server_address?: { host?: string; port?: number }
  client_address?: { host?: string; port?: number }
  client_process?: { pid?: number; name?: string; exe?: string }
  tls?: any
  is_websocket_handshake?: boolean
  proxy_state?: { wininet_enabled?: boolean; winhttp_enabled?: boolean }
  error?: any
  headers?: Record<string, string>
  body?: string
  body_artifact?: any
  body_preview_hex?: string
  response_headers?: Record<string, string>
  response_body?: string
  response_body_artifact?: any
  response_body_preview_hex?: string
  content_type?: string
  tags?: string[]
  grpc?: any
  protobuf?: any
  streaming?: any
  js_events?: any[]
}

const ProxyRequestList: React.FC = () => {
  const navigate = useNavigate()
  const [requests, setRequests] = useState<ProxyRequest[]>([])
  const [loading, setLoading] = useState(false)
  const [total, setTotal] = useState(0)
  const [overallTotal, setOverallTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [sourceFilter, setSourceFilter] = useState<string>('all')
  const [searchText, setSearchText] = useState('')
  const [queryText, setQueryText] = useState('')
  const [selectedRequest, setSelectedRequest] = useState<ProxyRequest | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)
  const [exportModalVisible, setExportModalVisible] = useState(false)
  const [exportFormat, setExportFormat] = useState<'har' | 'csv' | 'json'>('har')
  const [exportLoading, setExportLoading] = useState(false)
  const [includeSensitiveExport, setIncludeSensitiveExport] = useState(true)
  const [includeSensitiveDetail, setIncludeSensitiveDetail] = useState(true)
  const [protocolFilter, setProtocolFilter] = useState<'all' | 'http' | 'ws'>('all')
  const [statusGroupFilter, setStatusGroupFilter] = useState<'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'no_status'>('all')
  const [contentTypeFilter, setContentTypeFilter] = useState<'all' | 'json' | 'html' | 'text' | 'image' | 'other'>('all')
  const [proxyStackFilter, setProxyStackFilter] = useState<'all' | 'wininet' | 'winhttp' | 'both' | 'none'>('all')
  const [processFilter, setProcessFilter] = useState<string>('all')
  const [tagFilter, setTagFilter] = useState<string>('all')
  const [bodyView, setBodyView] = useState<'text' | 'hex'>('text')
  const [respBodyView, setRespBodyView] = useState<'text' | 'hex'>('text')

  // 使用WebSocket实时更新
  const { recentRequests, clearRequests } = useProxyWebSocket()

  const loadRequests = useCallback(async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/proxy/requests', {
        params: {
          limit: pageSize,
          offset: (page - 1) * pageSize,
          source: sourceFilter !== 'all' ? sourceFilter : undefined,
          q: queryText || undefined,
          protocol: protocolFilter,
          status_group: statusGroupFilter,
          content_type_group: contentTypeFilter,
          proxy_stack: proxyStackFilter,
          process_name: processFilter !== 'all' ? processFilter : undefined,
          tag: tagFilter !== 'all' ? tagFilter : undefined,
        }
      })
      setRequests(response.data.requests || [])
      setTotal(Number(response.data.total || 0))
      setOverallTotal(Number(response.data.overall_total || response.data.total || 0))
    } catch (error) {
      console.error('加载请求列表失败:', error)
      // 如果API不存在，忽略错误，只使用WebSocket数据
    } finally {
      setLoading(false)
    }
  }, [page, pageSize, sourceFilter, queryText, protocolFilter, statusGroupFilter, contentTypeFilter, proxyStackFilter, processFilter, tagFilter])

  // 初始化加载请求列表
  useEffect(() => {
    loadRequests()
  }, [loadRequests])

  // 搜索框防抖（避免频繁打接口）
  useEffect(() => {
    const t = window.setTimeout(() => {
      setQueryText((searchText || '').trim())
      setPage(1)
    }, 350)
    return () => window.clearTimeout(t)
  }, [searchText])

  // 实时抓包：在第一页时自动刷新（节流）
  useEffect(() => {
    if (!autoRefresh) return
    if (page !== 1) return
    if (!recentRequests.length) return
    const t = window.setTimeout(() => loadRequests(), 400)
    return () => window.clearTimeout(t)
  }, [recentRequests.length, autoRefresh, page, loadRequests])

  const processOptions = Array.from(
    new Set(
      requests
        .map((r) => r.client_process?.name)
        .filter((n): n is string => !!n)
        .map((n) => n.trim())
        .filter(Boolean)
    )
  ).sort()

  const handleClearRequests = async () => {
    try {
      await axios.delete('/api/v1/proxy/requests')
      message.success('请求列表已清空')
    } catch (e) {
      // fallback: 仅清空前端视图
      console.warn('清空请求失败，将仅清空前端缓存:', e)
    } finally {
      setRequests([])
      clearRequests()
      setPage(1)
      loadRequests()
    }
  }

  const openWebSocketTab = (connectionId: string) => {
    if (!connectionId) return
    try {
      sessionStorage.setItem('proxy_capture_ws_connection_id', connectionId)
      window.dispatchEvent(new CustomEvent('proxy-capture:switch-tab', { detail: { key: 'websocket' } }))
      message.success('已切换到 WebSocket 标签页并定位连接')
    } catch {
      message.info('无法自动切换，请手动打开 WebSocket 标签页')
    }
  }

  const openNativeHookForRequest = (requestId: string) => {
    if (!requestId) return
    navigate(`/native-hook?correlated_request_id=${encodeURIComponent(requestId)}`)
  }

  const openJsInjectionForRequest = (requestId: string) => {
    if (!requestId) return
    try {
      sessionStorage.setItem('proxy_js_filter_request_id', requestId)
      window.dispatchEvent(new CustomEvent('proxy-capture:switch-tab', { detail: { key: 'js_injection' } }))
      window.dispatchEvent(new CustomEvent('proxy-js-injection:set-filter', { detail: { requestId } }))
      message.success('已切换到 JS 注入标签页并按 request_id 过滤')
    } catch {
      message.info('无法自动切换，请手动打开 JS 注入标签页')
    }
  }

  const handleExport = async () => {
    setExportLoading(true)
    try {
      const params = new URLSearchParams({
        format: exportFormat,
        limit: '1000',
        include_sensitive: includeSensitiveExport ? 'true' : 'false',
      })
      
      if (sourceFilter !== 'all') {
        params.append('source', sourceFilter)
      }

      const response = await axios.get(`/api/v1/proxy/requests/export?${params.toString()}`, {
        responseType: 'blob'
      })

      // 创建下载链接
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      
      // 从响应头获取文件名，或使用默认文件名
      const contentDisposition = response.headers['content-disposition']
      let filename = `requests_${new Date().getTime()}.${exportFormat}`
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/)
        if (filenameMatch) {
          filename = filenameMatch[1]
        }
      }
      
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      message.success(`成功导出 ${exportFormat.toUpperCase()} 格式文件`)
      setExportModalVisible(false)
    } catch (error) {
      console.error('导出失败:', error)
      message.error('导出失败，请稍后重试')
    } finally {
      setExportLoading(false)
    }
  }

  const handleViewDetail = async (record: ProxyRequest) => {
    try {
      // 从API获取完整的请求详情
      const response = await axios.get(`/api/v1/proxy/request/${record.id}`, {
        params: {
          include_sensitive: includeSensitiveDetail ? true : undefined,
        },
      })
      setSelectedRequest(response.data)
      setBodyView('text')
      setRespBodyView('text')
      setDetailModalVisible(true)
    } catch (error) {
      console.error('获取请求详情失败:', error)
      // 如果API失败，使用当前记录
      setSelectedRequest(record)
      setBodyView('text')
      setRespBodyView('text')
      setDetailModalVisible(true)
    }
  }

  const openRequestDetailById = useCallback(
    async (requestId: string) => {
      if (!requestId) return
      try {
        const response = await axios.get(`/api/v1/proxy/request/${encodeURIComponent(requestId)}`, {
          params: {
            include_sensitive: includeSensitiveDetail ? true : undefined,
          },
        })
        setSelectedRequest(response.data)
      } catch (e) {
        console.error('打开请求详情失败:', e)
        setSelectedRequest({ id: requestId } as any)
      } finally {
        setBodyView('text')
        setRespBodyView('text')
        setDetailModalVisible(true)
      }
    },
    [includeSensitiveDetail]
  )

  // 接收跨 Tab 联动：打开指定 request_id 的详情
  useEffect(() => {
    const handler = (e: any) => {
      const requestId = e?.detail?.requestId || e?.detail?.id
      if (requestId) openRequestDetailById(String(requestId))
    }
    window.addEventListener('proxy-capture:open-request-detail', handler as any)
    return () => window.removeEventListener('proxy-capture:open-request-detail', handler as any)
  }, [openRequestDetailById])

  // sessionStorage 联动（避免事件先于组件挂载）
  useEffect(() => {
    const requestId = sessionStorage.getItem('proxy_capture_request_id')
    if (!requestId) return
    sessionStorage.removeItem('proxy_capture_request_id')
    openRequestDetailById(requestId)
  }, [openRequestDetailById])

  const downloadArtifact = (artifactId: string) => {
    if (!artifactId) return
    window.open(`/api/v1/proxy/artifacts/${encodeURIComponent(artifactId)}`, '_blank')
  }

  // 获取来源图标
  const getSourceIcon = (source: string) => {
    switch (source) {
      case 'web_browser':
        return <ChromeOutlined style={{ color: '#1890ff' }} />
      case 'desktop_app':
        return <DesktopOutlined style={{ color: '#52c41a' }} />
      case 'mobile_ios':
        return <AppleOutlined style={{ color: '#000000' }} />
      case 'mobile_android':
        return <AndroidOutlined style={{ color: '#3ddc84' }} />
      default:
        return <GlobalOutlined />
    }
  }

  // 获取来源标签
  const getSourceTag = (source: string) => {
    const config = {
      web_browser: { color: 'blue', text: '浏览器' },
      desktop_app: { color: 'green', text: '桌面应用' },
      mobile_ios: { color: 'default', text: 'iOS' },
      mobile_android: { color: 'cyan', text: 'Android' }
    }
    const { color, text } = config[source as keyof typeof config] || { color: 'default', text: source }
    return <Tag color={color}>{text}</Tag>
  }

  // 获取HTTP方法标签颜色
  const getMethodColor = (method: string) => {
    const colors: Record<string, string> = {
      GET: 'blue',
      POST: 'green',
      PUT: 'orange',
      DELETE: 'red',
      PATCH: 'purple',
      HEAD: 'cyan',
      OPTIONS: 'default'
    }
    return colors[method] || 'default'
  }

  // 获取状态码标签颜色
  const getStatusColor = (status?: number) => {
    if (!status) return 'default'
    if (status >= 200 && status < 300) return 'success'
    if (status >= 300 && status < 400) return 'processing'
    if (status >= 400 && status < 500) return 'warning'
    if (status >= 500) return 'error'
    return 'default'
  }

  // 格式化文件大小
  const formatSize = (bytes?: number) => {
    if (!bytes) return '-'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  // 格式化时间
  const formatTime = (timestamp: number | string) => {
    const date = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp)
    return date.toLocaleTimeString('zh-CN', { hour12: false })
  }

  const columns: ColumnsType<ProxyRequest> = [
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 100,
      render: (source: string, record) => (
        <Tooltip title={record.device_info?.device || record.device_info?.platform || source}>
          <Space>
            {getSourceIcon(source)}
            {getSourceTag(source)}
          </Space>
        </Tooltip>
      )
    },
    {
      title: '进程',
      dataIndex: 'client_process',
      key: 'client_process',
      width: 120,
      render: (proc?: any) => <Text type="secondary">{proc?.name || '-'}</Text>
    },
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => (
        <Tag color={getMethodColor(method)}>{method}</Tag>
      )
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Tooltip title={url}>
          <Text style={{ fontSize: '12px' }}>{url}</Text>
        </Tooltip>
      )
    },
    {
      title: '协议',
      dataIndex: 'is_websocket_handshake',
      key: 'protocol',
      width: 70,
      render: (isWs?: boolean) => (
        isWs ? <Tag color="purple">WS</Tag> : <Tag>HTTP</Tag>
      )
    },
    {
      title: 'Tags',
      dataIndex: 'tags',
      key: 'tags',
      width: 140,
      render: (tags?: string[]) =>
        tags?.length ? (
          <Space wrap size={4}>
            {tags.slice(0, 3).map((t) => (
              <Tag key={t} color={t === 'grpc' ? 'blue' : t === 'sse' ? 'purple' : t === 'protobuf' ? 'geekblue' : 'default'}>
                {t}
              </Tag>
            ))}
            {tags.length > 3 ? <Text type="secondary">+{tags.length - 3}</Text> : null}
          </Space>
        ) : (
          <Text type="secondary">-</Text>
        ),
    },
    {
      title: '状态码',
      dataIndex: 'status_code',
      key: 'status_code',
      width: 80,
      render: (status?: number, record?: ProxyRequest) =>
        status ? (
          <Badge status={getStatusColor(status)} text={status} />
        ) : record?.error ? (
          <Tooltip title={record.error?.message || record.error?.type || 'error'}>
            <Tag color="red">ERROR</Tag>
          </Tooltip>
        ) : (
          <Text type="secondary">-</Text>
        ),
    },
    {
      title: '大小',
      dataIndex: 'response_size',
      key: 'response_size',
      width: 100,
      render: (size?: number) => (
        <Text type="secondary">{formatSize(size)}</Text>
      )
    },
    {
      title: '响应时间',
      dataIndex: 'response_time',
      key: 'response_time',
      width: 100,
      render: (time?: number) => (
        time ? (
          <Text type="secondary">{(time * 1000).toFixed(0)}ms</Text>
        ) : (
          <Text type="secondary">-</Text>
        )
      )
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 100,
      render: (timestamp: number) => (
        <Text type="secondary">{formatTime(timestamp)}</Text>
      )
    },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          onClick={() => handleViewDetail(record)}
        >
          详情
        </Button>
      )
    }
  ]

  return (
    <>
      <Card
        title={
          <Space>
            <span>代理请求列表</span>
            <Badge count={total} showZero style={{ backgroundColor: '#52c41a' }} />
            {overallTotal && overallTotal !== total ? <Text type="secondary">/ 总 {overallTotal}</Text> : null}
          </Space>
        }
        extra={
          <Space>
            <Select
              value={sourceFilter}
              onChange={(v) => {
                setPage(1)
                setSourceFilter(v)
              }}
              style={{ width: 120 }}
              size="small"
            >
              <Option value="all">全部来源</Option>
              <Option value="web_browser">
                <Space><ChromeOutlined />浏览器</Space>
              </Option>
              <Option value="desktop_app">
                <Space><DesktopOutlined />桌面应用</Space>
              </Option>
              <Option value="mobile_ios">
                <Space><AppleOutlined />iOS</Space>
              </Option>
              <Option value="mobile_android">
                <Space><AndroidOutlined />Android</Space>
              </Option>
            </Select>
            <Select
              value={processFilter}
              onChange={(v) => {
                setPage(1)
                setProcessFilter((v as string) || 'all')
              }}
              style={{ width: 150 }}
              size="small"
              showSearch
              optionFilterProp="children"
            >
              <Option value="all">全部进程</Option>
              {processOptions.map((p) => (
                <Option key={p} value={p}>
                  {p}
                </Option>
              ))}
            </Select>
            <Select
              value={protocolFilter}
              onChange={(v) => {
                setPage(1)
                setProtocolFilter(v)
              }}
              style={{ width: 110 }}
              size="small"
            >
              <Option value="all">全部协议</Option>
              <Option value="http">HTTP</Option>
              <Option value="ws">WebSocket</Option>
            </Select>
            <Select
              value={statusGroupFilter}
              onChange={(v) => {
                setPage(1)
                setStatusGroupFilter(v)
              }}
              style={{ width: 120 }}
              size="small"
            >
              <Option value="all">全部状态</Option>
              <Option value="2xx">2xx</Option>
              <Option value="3xx">3xx</Option>
              <Option value="4xx">4xx</Option>
              <Option value="5xx">5xx</Option>
              <Option value="no_status">无状态</Option>
            </Select>
            <Select
              value={contentTypeFilter}
              onChange={(v) => {
                setPage(1)
                setContentTypeFilter(v)
              }}
              style={{ width: 120 }}
              size="small"
            >
              <Option value="all">全部类型</Option>
              <Option value="json">JSON</Option>
              <Option value="html">HTML</Option>
              <Option value="text">Text/JS/XML</Option>
              <Option value="image">Image</Option>
              <Option value="other">Other/Unknown</Option>
            </Select>
            <Select
              value={proxyStackFilter}
              onChange={(v) => {
                setPage(1)
                setProxyStackFilter(v)
              }}
              style={{ width: 160 }}
              size="small"
            >
              <Option value="all">全部代理栈</Option>
              <Option value="wininet">仅 WinINet 开</Option>
              <Option value="winhttp">仅 WinHTTP 开</Option>
              <Option value="both">WinINet + WinHTTP</Option>
              <Option value="none">均未开启</Option>
            </Select>
            <Select
              value={tagFilter}
              onChange={(v) => {
                setPage(1)
                setTagFilter(v)
              }}
              style={{ width: 120 }}
              size="small"
            >
              <Option value="all">全部Tag</Option>
              <Option value="grpc">gRPC</Option>
              <Option value="protobuf">Protobuf</Option>
              <Option value="sse">SSE</Option>
            </Select>
            <Input
              placeholder="搜索URL或设备"
              prefix={<SearchOutlined />}
              value={searchText}
              onChange={e => setSearchText(e.target.value)}
              style={{ width: 200 }}
              size="small"
              allowClear
            />
            <Button
              icon={<ReloadOutlined />}
              onClick={() => loadRequests()}
              loading={loading}
              size="small"
            >
              刷新
            </Button>
            <Tooltip title="实时抓包：在第一页自动刷新">
              <Space size={6}>
                <Switch checked={autoRefresh} onChange={setAutoRefresh} />
                <Text type="secondary">自动刷新</Text>
              </Space>
            </Tooltip>
            <Button
              icon={<DownloadOutlined />}
              onClick={() => setExportModalVisible(true)}
              size="small"
              type="primary"
            >
              导出
            </Button>
            <Button
              icon={<ClearOutlined />}
              onClick={handleClearRequests}
              danger
              size="small"
            >
              清空
            </Button>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={requests}
          rowKey="id"
          loading={loading}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showQuickJumper: true,
            pageSizeOptions: [20, 50, 100, 200],
            onChange: (p, ps) => {
              setPage(p)
              setPageSize(ps)
            },
            showTotal: (t) => (overallTotal && overallTotal !== t ? `匹配 ${t} 条 / 总 ${overallTotal}` : `共 ${t} 条请求`)
          }}
          size="small"
          scroll={{ x: 1200, y: 650 }}
          virtual
        />
      </Card>

      {/* 导出Modal */}
      <Modal
        title="导出请求数据"
        open={exportModalVisible}
        onCancel={() => setExportModalVisible(false)}
        onOk={handleExport}
        confirmLoading={exportLoading}
        okText="导出"
        cancelText="取消"
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <div>
            <Text strong>选择导出格式：</Text>
          </div>
          <Select
            value={exportFormat}
            onChange={setExportFormat}
            style={{ width: '100%' }}
          >
            <Option value="har">
              <Space>
                <DownloadOutlined />
                <span>HAR 格式 (HTTP Archive)</span>
              </Space>
              <div style={{ fontSize: '12px', color: '#999', marginLeft: 24 }}>
                可导入到 Chrome DevTools、Postman 等工具
              </div>
            </Option>
            <Option value="csv">
              <Space>
                <DownloadOutlined />
                <span>CSV 格式 (逗号分隔)</span>
              </Space>
              <div style={{ fontSize: '12px', color: '#999', marginLeft: 24 }}>
                适合用于数据分析和报表生成
              </div>
            </Option>
            <Option value="json">
              <Space>
                <DownloadOutlined />
                <span>JSON 格式</span>
              </Space>
              <div style={{ fontSize: '12px', color: '#999', marginLeft: 24 }}>
                结构化字段齐全（含进程/TLS/artifact_id/tags）
              </div>
            </Option>
          </Select>
          <Alert
            type="info"
            showIcon
            message="字段导出选项"
            description={
              <Space direction="vertical" size={4}>
                <Text type="secondary">
                  本地自用默认不脱敏；如需分享给他人/排障，可关闭敏感字段导出。
                </Text>
                <Space>
                  <Switch checked={includeSensitiveExport} onChange={setIncludeSensitiveExport} />
                  <Text>导出时包含敏感字段</Text>
                </Space>
              </Space>
            }
          />
          <div style={{ marginTop: 16 }}>
            <Text type="secondary">
              将导出最多 1000 条请求记录
              {sourceFilter !== 'all' && ` (已过滤: ${sourceFilter})`}
            </Text>
          </div>
        </Space>
      </Modal>

      {/* 请求详情Modal */}
      <Modal
        title="请求详情"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>
        ]}
        width={800}
      >
        {selectedRequest && (
          <>
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="详情显示选项"
              description={
                <Space>
                  <Switch checked={includeSensitiveDetail} onChange={setIncludeSensitiveDetail} />
                  <Text>包含敏感字段（Cookie/Authorization）</Text>
                  <Button size="small" onClick={() => handleViewDetail(selectedRequest)}>
                    重新加载
                  </Button>
                </Space>
              }
            />
            <Descriptions bordered column={2} size="small">
            <Descriptions.Item label="请求ID" span={2}>
              {selectedRequest.id}
            </Descriptions.Item>
            <Descriptions.Item label="联动" span={2}>
              <Space wrap>
                <Button size="small" onClick={() => openNativeHookForRequest(selectedRequest.id)}>
                  查 Hook
                </Button>
                <Button size="small" onClick={() => openJsInjectionForRequest(selectedRequest.id)}>
                  看 JS
                </Button>
                {selectedRequest.is_websocket_handshake ? (
                  <Button size="small" onClick={() => openWebSocketTab(selectedRequest.id)}>
                    打开 WS 消息
                  </Button>
                ) : null}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="会话ID" span={2}>
              <Text type="secondary">{selectedRequest.proxy_session_id || '-'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="来源">
              <Space>
                {getSourceIcon(selectedRequest.source)}
                {getSourceTag(selectedRequest.source)}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="进程">
              <Text type="secondary">
                {selectedRequest.client_process?.name ? `${selectedRequest.client_process.name} (PID:${selectedRequest.client_process.pid || '-'})` : '-'}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="设备信息">
              {selectedRequest.device_info?.device || selectedRequest.device_info?.platform || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="HTTP方法">
              <Tag color={getMethodColor(selectedRequest.method)}>
                {selectedRequest.method}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="状态码">
              {selectedRequest.status_code ? (
                <Badge status={getStatusColor(selectedRequest.status_code)} text={selectedRequest.status_code} />
              ) : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="URL" span={2}>
              <Text copyable style={{ wordBreak: 'break-all' }}>
                {selectedRequest.url}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="HTTP版本">
              <Text type="secondary">{selectedRequest.http_version || '-'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="远端地址">
              <Text type="secondary">
                {selectedRequest.server_address?.host ? `${selectedRequest.server_address.host}:${selectedRequest.server_address.port}` : '-'}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="代理栈快照" span={2}>
              {selectedRequest.proxy_state ? (
                <Text type="secondary">
                  WinINet: {selectedRequest.proxy_state.wininet_enabled ? 'ON' : 'OFF'} | WinHTTP:{' '}
                  {selectedRequest.proxy_state.winhttp_enabled ? 'ON' : 'OFF'}
                </Text>
              ) : (
                <Text type="secondary">-</Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="TLS" span={2}>
              {selectedRequest.tls ? (
                <pre style={{ maxHeight: '160px', overflow: 'auto', fontSize: '12px' }}>
                  {JSON.stringify(selectedRequest.tls, null, 2)}
                </pre>
              ) : (
                <Text type="secondary">-</Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="Tags" span={2}>
              {selectedRequest.tags?.length ? (
                <Space wrap size={4}>
                  {selectedRequest.tags.map((t) => (
                    <Tag key={t} color={t === 'grpc' ? 'blue' : t === 'sse' ? 'purple' : t === 'protobuf' ? 'geekblue' : 'default'}>
                      {t}
                    </Tag>
                  ))}
                </Space>
              ) : (
                <Text type="secondary">-</Text>
              )}
            </Descriptions.Item>
            {selectedRequest.streaming ? (
              <Descriptions.Item label="Streaming/SSE" span={2}>
                <pre style={{ maxHeight: '160px', overflow: 'auto', fontSize: '12px' }}>
                  {JSON.stringify(selectedRequest.streaming, null, 2)}
                </pre>
              </Descriptions.Item>
            ) : null}
            {selectedRequest.grpc ? (
              <Descriptions.Item label="gRPC" span={2}>
                <pre style={{ maxHeight: '160px', overflow: 'auto', fontSize: '12px' }}>
                  {JSON.stringify(selectedRequest.grpc, null, 2)}
                </pre>
              </Descriptions.Item>
            ) : null}
            {selectedRequest.js_events?.length ? (
              <Descriptions.Item label="JS 注入" span={2}>
                <Space style={{ marginBottom: 8 }} wrap>
                  <Text type="secondary">共 {selectedRequest.js_events.length} 条</Text>
                  <Button size="small" onClick={() => openJsInjectionForRequest(selectedRequest.id)}>
                    打开 JS 注入并过滤
                  </Button>
                </Space>
                <pre style={{ maxHeight: '200px', overflow: 'auto', fontSize: '12px' }}>
                  {JSON.stringify(selectedRequest.js_events, null, 2)}
                </pre>
              </Descriptions.Item>
            ) : null}
            <Descriptions.Item label="响应大小">
              {formatSize(selectedRequest.response_size)}
            </Descriptions.Item>
            <Descriptions.Item label="响应时间">
              {selectedRequest.response_time ? `${(selectedRequest.response_time * 1000).toFixed(0)}ms` : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="时间戳" span={2}>
              {new Date(selectedRequest.timestamp * 1000).toLocaleString('zh-CN')}
            </Descriptions.Item>
            {selectedRequest.headers && (
              <Descriptions.Item label="请求头" span={2}>
                <pre style={{ maxHeight: '200px', overflow: 'auto', fontSize: '12px' }}>
                  {JSON.stringify(selectedRequest.headers, null, 2)}
                </pre>
              </Descriptions.Item>
            )}
            {(selectedRequest.body || selectedRequest.body_preview_hex) && (
              <Descriptions.Item label="请求体" span={2}>
                <Space style={{ marginBottom: 8 }} wrap>
                  <Text type="secondary">预览</Text>
                  <Select size="small" value={bodyView} onChange={(v) => setBodyView(v)} style={{ width: 90 }}>
                    <Option value="text">文本</Option>
                    <Option value="hex">HEX</Option>
                  </Select>
                  {selectedRequest.body_artifact?.artifact_id && (
                    <Space>
                      <Button size="small" onClick={() => downloadArtifact(selectedRequest.body_artifact.artifact_id)}>
                        下载完整请求体
                      </Button>
                      <Text type="secondary">
                        {selectedRequest.body_artifact.is_binary ? '二进制已落盘' : selectedRequest.body_artifact.truncated ? '已截断并落盘' : '已落盘'}
                      </Text>
                    </Space>
                  )}
                </Space>
                <pre style={{ maxHeight: '200px', overflow: 'auto', fontSize: '12px' }}>
                  {bodyView === 'hex' ? selectedRequest.body_preview_hex || '' : selectedRequest.body}
                </pre>
              </Descriptions.Item>
            )}
            {selectedRequest.response_headers && (
              <Descriptions.Item label="响应头" span={2}>
                <pre style={{ maxHeight: '200px', overflow: 'auto', fontSize: '12px' }}>
                  {JSON.stringify(selectedRequest.response_headers, null, 2)}
                </pre>
              </Descriptions.Item>
            )}
            {(selectedRequest.response_body || selectedRequest.response_body_preview_hex) && (
              <Descriptions.Item label="响应体" span={2}>
                <Space style={{ marginBottom: 8 }} wrap>
                  <Text type="secondary">预览</Text>
                  <Select size="small" value={respBodyView} onChange={(v) => setRespBodyView(v)} style={{ width: 90 }}>
                    <Option value="text">文本</Option>
                    <Option value="hex">HEX</Option>
                  </Select>
                  {selectedRequest.response_body_artifact?.artifact_id && (
                    <Space>
                      <Button size="small" onClick={() => downloadArtifact(selectedRequest.response_body_artifact.artifact_id)}>
                        下载完整响应体
                      </Button>
                      <Text type="secondary">
                        {selectedRequest.response_body_artifact.is_binary ? '二进制已落盘' : selectedRequest.response_body_artifact.truncated ? '已截断并落盘' : '已落盘'}
                      </Text>
                    </Space>
                  )}
                </Space>
                <pre style={{ maxHeight: '200px', overflow: 'auto', fontSize: '12px' }}>
                  {respBodyView === 'hex' ? selectedRequest.response_body_preview_hex || '' : selectedRequest.response_body}
                </pre>
              </Descriptions.Item>
            )}
          </Descriptions>
          </>
        )}
      </Modal>
    </>
  )
}

export default ProxyRequestList
