import React, { useState, useEffect, useMemo, useCallback } from 'react'
import {
  Card,
  Table,
  Button,
  Space,
  Input,
  InputNumber,
  Switch,
  message,
  Modal,
  Select,
  Tag,
  Badge,
  Descriptions,
  Alert,
  Divider,
  Tabs,
  Popconfirm,
  Form,
  Tooltip,
  Typography
} from 'antd'
import {
  SearchOutlined,
  ReloadOutlined,
  PlayCircleOutlined,
  PauseCircleOutlined,
  CodeOutlined,
  ClearOutlined,
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  FileTextOutlined,
  DownloadOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { useLocation, useNavigate } from 'react-router-dom'

const { Option, OptGroup } = Select
const { TextArea } = Input
const { TabPane } = Tabs
const { Text } = Typography

interface Process {
  pid: number
  name: string
  parameters?: any
}

interface HookRecord {
  hook_id: string
  session_id?: string
  process_name: string
  pid: number
  hook_type: string
  api_name: string
  args: any
  timestamp: string
  stack_trace?: string
  thread_id?: number
  correlated_request_id?: string
}

interface HookSession {
  session_id: string
  process_name: string
  pid: number
  script_name: string
  started_at: string
  status: string
  record_count: number
}

interface HookTemplate {
  name: string
  description: string
  script_code: string
  category?: string
  default_params?: any
  created_at?: string
  updated_at?: string
}

const NativeHook: React.FC = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const [processes, setProcesses] = useState<Process[]>([])
  const [sessions, setSessions] = useState<HookSession[]>([])
  const [records, setRecords] = useState<HookRecord[]>([])
  const [templates, setTemplates] = useState<HookTemplate[]>([])
  const [loading, setLoading] = useState(false)
  const [searchText, setSearchText] = useState('')
  const [attachModalVisible, setAttachModalVisible] = useState(false)
  const [injectModalVisible, setInjectModalVisible] = useState(false)
  const [templateModalVisible, setTemplateModalVisible] = useState(false)
  const [templateDetailModalVisible, setTemplateDetailModalVisible] = useState(false)
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null)
  const [selectedSession, setSelectedSession] = useState<string>('')
  const [scriptTemplate, setScriptTemplate] = useState('windows_api_hooks')
  const [templateParams, setTemplateParams] = useState<Record<string, any>>({})
  const [templateParamsJson, setTemplateParamsJson] = useState<string>('{}')
  const [templateParamsJsonError, setTemplateParamsJsonError] = useState<string>('')
  const [editingTemplateParamsJson, setEditingTemplateParamsJson] = useState<boolean>(false)
  const [exportFormat, setExportFormat] = useState<'json' | 'csv'>('json')
  const [exporting, setExporting] = useState(false)
  const [linkedRequest, setLinkedRequest] = useState<any>(null)
  const [linkedRequestVisible, setLinkedRequestVisible] = useState(false)
  const [fridaStatus, setFridaStatus] = useState<any>(null)
  const [editingTemplate, setEditingTemplate] = useState<HookTemplate | null>(null)
  const [viewingTemplate, setViewingTemplate] = useState<HookTemplate | null>(null)
  const [correlatedRequestId, setCorrelatedRequestId] = useState<string>(() => {
    try {
      const params = new URLSearchParams(window.location.search)
      return params.get('correlated_request_id') || ''
    } catch {
      return ''
    }
  })
  const [activeTab, setActiveTab] = useState<string>(() => (correlatedRequestId ? 'records' : 'sessions'))
  const [recommendations, setRecommendations] = useState<any>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    try {
      const params = new URLSearchParams(location.search)
      const rid = params.get('correlated_request_id') || ''
      setCorrelatedRequestId(rid)
      if (rid) setActiveTab('records')
    } catch {
      setCorrelatedRequestId('')
    }
  }, [location.search])

  const recordStats = useMemo(() => {
    const byType: Record<string, number> = {}
    const byApi: Record<string, number> = {}
    records.forEach((r) => {
      byType[r.hook_type] = (byType[r.hook_type] || 0) + 1
      byApi[r.api_name] = (byApi[r.api_name] || 0) + 1
    })
    const topApi = Object.entries(byApi)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
    return { byType, topApi, total: records.length }
  }, [records])

  const templatesByCategory = useMemo(() => {
    const groups: Record<string, HookTemplate[]> = {}
    templates.forEach((t) => {
      const c = t.category || 'unknown'
      if (!groups[c]) groups[c] = []
      groups[c].push(t)
    })
    // 固定排序更好用
    const order = ['network', 'security', 'crypto', 'file', 'registry', 'custom', 'unknown']
    const sorted: Record<string, HookTemplate[]> = {}
    order.forEach((k) => {
      if (groups[k]) sorted[k] = groups[k]
    })
    Object.keys(groups)
      .filter((k) => !sorted[k])
      .sort()
      .forEach((k) => (sorted[k] = groups[k]))
    return sorted
  }, [templates])

  const selectedTemplateMeta = useMemo(() => templates.find((t) => t.name === scriptTemplate), [templates, scriptTemplate])

  useEffect(() => {
    // 当用户切换模板时，默认加载该模板的 default_params 作为可编辑参数
    if (selectedTemplateMeta?.default_params && typeof selectedTemplateMeta.default_params === 'object') {
      try {
        setTemplateParams({ ...(selectedTemplateMeta.default_params || {}) })
      } catch {
        setTemplateParams({})
      }
      return
    }
    // 未知/自定义模板默认不传参
    setTemplateParams({})
  }, [selectedTemplateMeta?.name, selectedTemplateMeta?.default_params])

  useEffect(() => {
    if (editingTemplateParamsJson) return
    try {
      setTemplateParamsJson(JSON.stringify(templateParams || {}, null, 2))
      setTemplateParamsJsonError('')
    } catch {
      setTemplateParamsJson('{}')
      setTemplateParamsJsonError('')
    }
  }, [templateParams, editingTemplateParamsJson])

  const checkFridaStatus = useCallback(async () => {
    try {
      const response = await axios.get('/api/v1/native-hook/status')
      setFridaStatus(response.data)
    } catch (error) {
      console.error('检查Frida状态失败:', error)
    }
  }, [])

  const loadSessions = useCallback(async () => {
    try {
      const response = await axios.get('/api/v1/native-hook/sessions')
      setSessions(response.data.sessions)
    } catch (error) {
      console.error('加载会话失败:', error)
    }
  }, [])

  const loadRecords = useCallback(
    async (sessionId?: string) => {
      try {
        const response = await axios.get('/api/v1/native-hook/records', {
          params: {
            session_id: sessionId || undefined,
            correlated_request_id: correlatedRequestId || undefined,
            limit: 200
          }
        })
        setRecords(response.data.records)
      } catch (error) {
        console.error('加载记录失败:', error)
      }
    },
    [correlatedRequestId]
  )

  const loadTemplates = useCallback(async () => {
    try {
      const response = await axios.get('/api/v1/native-hook/templates')
      setTemplates(response.data.templates || [])
    } catch (error) {
      console.error('加载模板失败:', error)
    }
  }, [])

  useEffect(() => {
    checkFridaStatus()
    loadSessions()
    loadTemplates()
    const interval = setInterval(() => {
      loadSessions()
      if (selectedSession || correlatedRequestId) loadRecords(selectedSession)
    }, 5000)
    return () => clearInterval(interval)
  }, [checkFridaStatus, loadSessions, loadTemplates, loadRecords, selectedSession, correlatedRequestId])

  useEffect(() => {
    const loadRecs = async () => {
      if (!selectedSession) {
        setRecommendations(null)
        return
      }
      try {
        const res = await axios.get(`/api/v1/native-hook/sessions/${selectedSession}/recommendations`)
        setRecommendations(res.data)
      } catch (e) {
        setRecommendations(null)
      }
    }
    loadRecs()
  }, [selectedSession])

  const loadProcesses = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/native-hook/processes')
      setProcesses(response.data.processes)
      setAttachModalVisible(true)
    } catch (error: any) {
      message.error(error.response?.data?.detail || '加载进程列表失败')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (correlatedRequestId) {
      loadRecords(selectedSession)
    }
  }, [correlatedRequestId, selectedSession, loadRecords])

  const clearCorrelatedFilter = () => {
    const params = new URLSearchParams(location.search)
    params.delete('correlated_request_id')
    const search = params.toString()
    navigate({ pathname: location.pathname, search: search ? `?${search}` : '' })
  }

  const handleExportRecords = async () => {
    if (!selectedSession) {
      message.warning('请先选择一个会话')
      return
    }
    setExporting(true)
    try {
      const res = await axios.get('/api/v1/native-hook/records/export', {
        params: { format: exportFormat, session_id: selectedSession, limit: 5000 },
        responseType: 'blob'
      })
      const blob = new Blob([res.data])
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '-')
      link.download = `hook_records_${selectedSession}_${ts}.${exportFormat}`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      message.success('导出成功')
    } catch (e) {
      console.error('导出失败:', e)
      message.error('导出失败')
    } finally {
      setExporting(false)
    }
  }

  const viewCorrelatedRequest = async (requestId: string) => {
    if (!requestId) return
    try {
      const res = await axios.get(`/api/v1/proxy/request/${requestId}`)
      setLinkedRequest(res.data)
      setLinkedRequestVisible(true)
    } catch (e) {
      console.error('加载关联请求失败:', e)
      message.error('加载关联请求失败（可能未通过代理捕获或已被清理）')
    }
  }

  const handleClearRecords = async () => {
    try {
      await axios.delete('/api/v1/native-hook/records')
      setRecords([])
      message.success('Hook记录已清空')
      loadSessions() // 刷新会话以更新记录数
    } catch (error: any) {
      message.error(error.response?.data?.detail || '清空记录失败')
    }
  }

  const handleAttach = async () => {
    if (!selectedProcess) {
      message.warning('请选择一个进程')
      return
    }

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/native-hook/attach', {
        pid: selectedProcess.pid
      })
      message.success('成功附加到进程')
      setSelectedSession(response.data.session_id)
      setAttachModalVisible(false)
      setInjectModalVisible(true)
      loadSessions()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '附加进程失败')
    } finally {
      setLoading(false)
    }
  }

  const handleInjectScript = async () => {
    if (!selectedSession) {
      message.warning('请先附加到进程')
      return
    }

    setLoading(true)
    try {
      await axios.post(`/api/v1/native-hook/inject-script/${selectedSession}`, {
        template_name: scriptTemplate,
        template_params: templateParams
      })
      message.success('脚本注入成功，开始监控...')
      setInjectModalVisible(false)
      setTimeout(() => loadRecords(selectedSession), 1000)
    } catch (error: any) {
      message.error(error.response?.data?.detail || '注入脚本失败')
    } finally {
      setLoading(false)
    }
  }

  const handleDetach = async (sessionId: string) => {
    try {
      await axios.post(`/api/v1/native-hook/detach/${sessionId}`)
      message.success('已分离进程')
      setSelectedSession('')
      setRecords([])
      loadSessions()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '分离进程失败')
    }
  }

  const handleCreateTemplate = () => {
    setEditingTemplate(null)
    form.resetFields()
    setTemplateModalVisible(true)
  }

  const handleEditTemplate = async (templateName: string) => {
    try {
      const response = await axios.get(`/api/v1/native-hook/templates/${templateName}`)
      setEditingTemplate(response.data)
      form.setFieldsValue(response.data)
      setTemplateModalVisible(true)
    } catch (error: any) {
      message.error(error.response?.data?.detail || '加载模板失败')
    }
  }

  const handleViewTemplate = async (templateName: string) => {
    try {
      const response = await axios.get(`/api/v1/native-hook/templates/${templateName}`)
      setViewingTemplate(response.data)
      setTemplateDetailModalVisible(true)
    } catch (error: any) {
      message.error(error.response?.data?.detail || '加载模板失败')
    }
  }

  const handleSaveTemplate = async () => {
    try {
      const values = await form.validateFields()

      if (editingTemplate) {
        // 更新模板（先删除再创建）
        await axios.delete(`/api/v1/native-hook/templates/${editingTemplate.name}`)
      }

      await axios.post('/api/v1/native-hook/templates', values)
      message.success(editingTemplate ? '模板更新成功' : '模板创建成功')
      setTemplateModalVisible(false)
      loadTemplates()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '保存模板失败')
    }
  }

  const handleDeleteTemplate = async (templateName: string) => {
    try {
      await axios.delete(`/api/v1/native-hook/templates/${templateName}`)
      message.success('模板删除成功')
      loadTemplates()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '删除模板失败')
    }
  }

  const processColumns: ColumnsType<Process> = [
    {
      title: 'PID',
      dataIndex: 'pid',
      key: 'pid',
      width: 100
    },
    {
      title: '进程名',
      dataIndex: 'name',
      key: 'name',
      filteredValue: searchText ? [searchText] : null,
      onFilter: (value, record) =>
        record.name.toLowerCase().includes(value.toString().toLowerCase())
    },
    {
      title: '操作',
      key: 'action',
      width: 100,
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          onClick={() => setSelectedProcess(record)}
        >
          选择
        </Button>
      )
    }
  ]

  const recordColumns: ColumnsType<HookRecord> = [
    {
      title: '类型',
      dataIndex: 'hook_type',
      key: 'hook_type',
      width: 100,
      render: (type: string) => {
        const colors: Record<string, string> = {
          network: 'blue',
          crypto: 'green',
          file: 'orange',
          registry: 'purple'
        }
        return <Tag color={colors[type] || 'default'}>{type}</Tag>
      }
    },
    {
      title: 'API',
      dataIndex: 'api_name',
      key: 'api_name',
      width: 150
    },
    {
      title: '关联请求',
      dataIndex: 'correlated_request_id',
      key: 'correlated_request_id',
      width: 140,
      render: (rid?: string) =>
        rid ? (
          <Button type="link" size="small" onClick={() => viewCorrelatedRequest(rid)}>
            查看请求
          </Button>
        ) : (
          <Text type="secondary">-</Text>
        )
    },
    {
      title: '参数',
      dataIndex: 'args',
      key: 'args',
      ellipsis: true,
      render: (args: any) => {
        const text = JSON.stringify(args)
        return text.length > 120 ? `${text.substring(0, 120)}...` : text
      }
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (time: string) => new Date(time).toLocaleString('zh-CN')
    }
  ]

  const templateColumns: ColumnsType<HookTemplate> = [
    {
      title: '模板名称',
      dataIndex: 'name',
      key: 'name',
      width: 200
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true
    },
    {
      title: '分类',
      dataIndex: 'category',
      key: 'category',
      width: 120,
      render: (c?: string) => <Tag color={c === 'security' ? 'red' : c === 'network' ? 'blue' : c === 'crypto' ? 'green' : 'default'}>{c || '-'}</Tag>
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (time: string) => time ? new Date(time).toLocaleString('zh-CN') : '-'
    },
    {
      title: '操作',
      key: 'action',
      width: 200,
      render: (_, record) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<FileTextOutlined />}
            onClick={() => handleViewTemplate(record.name)}
          >
            查看
          </Button>
          {record.category === 'custom' && (
            <>
              <Button
                type="link"
                size="small"
                icon={<EditOutlined />}
                onClick={() => handleEditTemplate(record.name)}
              >
                编辑
              </Button>
              <Popconfirm
                title="确定要删除这个模板吗？"
                onConfirm={() => handleDeleteTemplate(record.name)}
                okText="确定"
                cancelText="取消"
              >
                <Button
                  type="link"
                  size="small"
                  danger
                  icon={<DeleteOutlined />}
                >
                  删除
                </Button>
              </Popconfirm>
            </>
          )}
        </Space>
      )
    }
  ]

  return (
    <div style={{ padding: '0' }}>
      {/* Frida状态 */}
      {fridaStatus && (
        <Alert
          message={
            fridaStatus.frida_installed
              ? `Frida已安装 (版本: ${fridaStatus.frida_version})`
              : 'Frida未安装'
          }
          description={
            fridaStatus.frida_installed
              ? `活动会话: ${fridaStatus.active_sessions} | 总记录: ${fridaStatus.total_records}`
              : '请先安装Frida: pip install frida frida-tools'
          }
          type={fridaStatus.frida_installed ? 'success' : 'warning'}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}

      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        <TabPane tab="Hook会话" key="sessions">
          {/* 会话管理 */}
          <Card
            title="Hook会话"
            extra={
              <Space>
                <Button
                  type="primary"
                  icon={<PlayCircleOutlined />}
                  onClick={loadProcesses}
                  loading={loading}
                  disabled={!fridaStatus?.frida_installed}
                >
                  附加进程
                </Button>
                <Button
                  icon={<ReloadOutlined />}
                  onClick={loadSessions}
                >
                  刷新
                </Button>
              </Space>
            }
            style={{ marginBottom: 16 }}
          >
            {sessions.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px 0', color: '#999' }}>
                暂无活动会话，请点击"附加进程"开始
              </div>
            ) : (
              <Space direction="vertical" style={{ width: '100%' }}>
                {sessions.map(session => (
                  <Card
                    key={session.session_id}
                    size="small"
                    style={{
                      background: selectedSession === session.session_id ? '#f0f5ff' : undefined
                    }}
                  >
                    <Descriptions size="small" column={4}>
                      <Descriptions.Item label="进程">
                        {session.process_name} (PID: {session.pid})
                      </Descriptions.Item>
                      <Descriptions.Item label="状态">
                        <Badge
                          status={session.status === 'active' ? 'processing' : 'default'}
                          text={session.status === 'active' ? '运行中' : '已停止'}
                        />
                      </Descriptions.Item>
                      <Descriptions.Item label="记录数">
                        {session.record_count}
                      </Descriptions.Item>
                      <Descriptions.Item label="操作">
                        <Space>
                          <Button
                            size="small"
                            onClick={() => {
                              setSelectedSession(session.session_id)
                              loadRecords(session.session_id)
                              setActiveTab('records')
                            }}
                          >
                            查看记录
                          </Button>
                          {session.status === 'active' && (
                            <Button
                              size="small"
                              danger
                              icon={<PauseCircleOutlined />}
                              onClick={() => handleDetach(session.session_id)}
                            >
                              分离
                            </Button>
                          )}
                        </Space>
                      </Descriptions.Item>
                    </Descriptions>
                  </Card>
                ))}
              </Space>
            )}
          </Card>
        </TabPane>

        <TabPane tab="Hook记录" key="records">
          {(selectedSession || correlatedRequestId) ? (
            <Card
              title={
                <Space>
                  <span>Hook记录</span>
                  {selectedSession ? <Tag>会话: {selectedSession}</Tag> : null}
                  {correlatedRequestId ? <Tag color="blue">关联请求: {correlatedRequestId}</Tag> : null}
                </Space>
              }
              extra={
                <Space>
                  {correlatedRequestId ? (
                    <Button size="small" onClick={clearCorrelatedFilter}>
                      清除关联过滤
                    </Button>
                  ) : null}
                  <Select value={exportFormat} onChange={setExportFormat} size="small" style={{ width: 120 }}>
                    <Option value="json">导出 JSON</Option>
                    <Option value="csv">导出 CSV</Option>
                  </Select>
                  <Button
                    icon={<DownloadOutlined />}
                    size="small"
                    onClick={handleExportRecords}
                    loading={exporting}
                  >
                    导出
                  </Button>
                  <Popconfirm
                    title="确定要清空所有Hook记录吗？"
                    onConfirm={handleClearRecords}
                    okText="确定"
                    cancelText="取消"
                  >
                    <Button
                      danger
                      icon={<ClearOutlined />}
                      size="small"
                    >
                      清空记录
                    </Button>
                  </Popconfirm>
                </Space>
              }
              style={{ marginBottom: 16 }}
            >
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 12 }}
                message={`当前加载 ${recordStats.total} 条记录（分页/检索请在后端扩展）`}
                description={
                  <Space wrap>
                    {Object.entries(recordStats.byType).map(([k, v]) => (
                      <Tag key={k} color={k === 'network' ? 'blue' : k === 'crypto' ? 'green' : k === 'file' ? 'orange' : 'purple'}>
                        {k}:{v}
                      </Tag>
                    ))}
                    {recordStats.topApi.length > 0 && (
                      <Text type="secondary">Top API: {recordStats.topApi.map(([k, v]) => `${k}(${v})`).join(', ')}</Text>
                    )}
                  </Space>
                }
              />
              <Table
                columns={recordColumns}
                dataSource={records}
                rowKey="hook_id"
                size="small"
                pagination={{ pageSize: 20 }}
                expandable={{
                  expandedRowRender: (record) => (
                    <div style={{ padding: 8 }}>
                      {(() => {
                        const raw = record?.args?._raw_buffer_artifact
                        if (!raw || !raw.artifact_id) return null
                        const artifactId = String(raw.artifact_id || '')
                        const size = Number(raw.size || 0)
                        const contentType = String(raw.content_type || '')
                        return (
                          <Alert
                            type="info"
                            showIcon
                            style={{ marginBottom: 8 }}
                            message="原始 Buffer 已落盘（可选）"
                            description={
                              <Space wrap>
                                <Text code>{artifactId}</Text>
                                {Number.isFinite(size) && size > 0 ? <Text type="secondary">{size} bytes</Text> : null}
                                {contentType ? <Tag>{contentType}</Tag> : null}
                                <Button
                                  size="small"
                                  icon={<DownloadOutlined />}
                                  onClick={() => window.open(`/api/v1/native-hook/artifacts/${encodeURIComponent(artifactId)}`, '_blank')}
                                >
                                  下载
                                </Button>
                              </Space>
                            }
                          />
                        )
                      })()}
                      <Text strong>Args</Text>
                      <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, marginTop: 8 }}>
                        {JSON.stringify(record.args, null, 2)}
                      </pre>
                      {record.stack_trace && (
                        <>
                          <Text strong>Stack</Text>
                          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, marginTop: 8 }}>
                            {record.stack_trace}
                          </pre>
                        </>
                      )}
                    </div>
                  ),
                }}
              />
            </Card>
          ) : (
            <Alert type="info" showIcon message="请选择一个 Hook 会话以查看记录" />
          )}
        </TabPane>

        <TabPane tab="模板管理" key="templates">
          <Card
            title="Hook脚本模板"
            extra={
              <Space>
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={handleCreateTemplate}
                >
                  创建模板
                </Button>
                <Button
                  icon={<ReloadOutlined />}
                  onClick={loadTemplates}
                >
                  刷新
                </Button>
              </Space>
            }
          >
            <Table
              columns={templateColumns}
              dataSource={templates}
              rowKey="name"
              size="small"
              pagination={{ pageSize: 10 }}
            />
          </Card>
        </TabPane>
      </Tabs>

      {/* 附加进程Modal */}
      <Modal
        title="选择要附加的进程"
        open={attachModalVisible}
        onCancel={() => setAttachModalVisible(false)}
        onOk={handleAttach}
        width={800}
        confirmLoading={loading}
      >
        <Input
          placeholder="搜索进程名"
          prefix={<SearchOutlined />}
          value={searchText}
          onChange={e => setSearchText(e.target.value)}
          style={{ marginBottom: 16 }}
        />
        <Table
          columns={processColumns}
          dataSource={processes}
          rowKey="pid"
          size="small"
          pagination={{ pageSize: 10 }}
          rowSelection={{
            type: 'radio',
            selectedRowKeys: selectedProcess ? [selectedProcess.pid] : [],
            onChange: (_, selectedRows) => setSelectedProcess(selectedRows[0])
          }}
        />
      </Modal>

      {/* 注入脚本Modal */}
      <Modal
        title="注入Hook脚本"
        open={injectModalVisible}
        onCancel={() => setInjectModalVisible(false)}
        onOk={handleInjectScript}
        confirmLoading={loading}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          {recommendations?.recommendations?.length ? (
            <Alert
              type="info"
              showIcon
              message="推荐模板（基于已加载模块 best-effort）"
              description={
                <Space wrap>
                  {recommendations.recommendations.map((r: any) => (
                    <Tooltip key={r.template_name} title={r.reason}>
                      <Button size="small" onClick={() => setScriptTemplate(r.template_name)}>
                        {r.template_name}
                      </Button>
                    </Tooltip>
                  ))}
                </Space>
              }
            />
          ) : null}
          <div>
            <label>选择Hook模板：</label>
            <Select
              value={scriptTemplate}
              onChange={setScriptTemplate}
              style={{ width: '100%', marginTop: 8 }}
            >
              {Object.entries(templatesByCategory).map(([category, list]) => (
                <OptGroup key={category} label={category}>
                  {list.map((t) => (
                    <Option key={t.name} value={t.name}>
                      {t.name} - {t.description}
                    </Option>
                  ))}
                </OptGroup>
              ))}
              {templates.length === 0 && (
                <Option value="windows_api_hooks">Windows API Hook (网络+加密)</Option>
              )}
            </Select>
          </div>
          <Alert
            message="风险提示"
            description={
              <div>
                <div>脚本将 Hook 目标进程 API 调用。建议先用 network/crypto 等低风险模板。</div>
                {selectedTemplateMeta?.category === 'security' && (
                  <div style={{ marginTop: 8 }}>
                    <Text strong>注意：</Text>
                    <Text>SSL Unpin 会改变证书校验结果，可能影响应用安全策略，仅用于抓包/排障。</Text>
                  </div>
                )}
                {selectedTemplateMeta?.category && selectedTemplateMeta.category !== 'custom' && (
                  <div style={{ marginTop: 8 }}>
                    <Text type="secondary">内置模板支持默认参数渲染；如需自定义可复制后创建 custom 模板。</Text>
                  </div>
                )}
              </div>
            }
            type={selectedTemplateMeta?.category === 'security' ? 'warning' : 'info'}
            showIcon
          />

          {selectedTemplateMeta?.default_params && typeof selectedTemplateMeta.default_params === 'object' ? (
            <Card
              size="small"
              title="模板参数（可选）"
              extra={
                <Button
                  size="small"
                  onClick={() => setTemplateParams({ ...(selectedTemplateMeta.default_params || {}) })}
                >
                  恢复默认
                </Button>
              }
            >
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 12 }}
                message="参数说明"
                description="参数将用于渲染脚本中的 {{param}} 占位符；不改动则使用模板默认值。"
              />

              {Object.keys(selectedTemplateMeta.default_params || {}).length === 0 ? (
                <Text type="secondary">该模板未提供默认参数。</Text>
              ) : (
                <Space direction="vertical" style={{ width: '100%' }} size={10}>
                  {Object.keys(selectedTemplateMeta.default_params || {})
                    .sort((a, b) => {
                      // enable_* 优先展示
                      const aa = a.startsWith('enable_') ? `0_${a}` : a
                      const bb = b.startsWith('enable_') ? `0_${b}` : b
                      return aa.localeCompare(bb)
                    })
                    .map((key) => {
                      const current = Object.prototype.hasOwnProperty.call(templateParams, key)
                        ? templateParams[key]
                        : (selectedTemplateMeta.default_params || {})[key]
                      const valueType = typeof current

                      if (valueType === 'boolean') {
                        return (
                          <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <Space direction="vertical" size={0}>
                              <Text>{key}</Text>
                              <Text type="secondary" style={{ fontSize: 12 }}>
                                {key === 'dump_raw_buffers'
                                  ? '启用后可选将 Hook 到的原始 buffer 落盘（建议配合总量预算）'
                                  : key === 'capture_stack_trace'
                                  ? '开启调用栈采集会增加开销'
                                  : ''}
                              </Text>
                            </Space>
                            <Switch
                              checked={Boolean(current)}
                              onChange={(checked) => setTemplateParams((prev) => ({ ...prev, [key]: checked }))}
                            />
                          </div>
                        )
                      }

                      if (valueType === 'number') {
                        const isRate = key === 'sample_rate'
                        return (
                          <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <Space direction="vertical" size={0}>
                              <Text>{key}</Text>
                              <Text type="secondary" style={{ fontSize: 12 }}>
                                {key === 'raw_total_budget_bytes'
                                  ? 'raw buffer 总预算（字节）。=0 表示不落盘'
                                  : key === 'raw_max_bytes'
                                  ? '单条 raw buffer 最大落盘字节数'
                                  : key === 'max_preview'
                                  ? '单条事件预览长度（字节/字符）'
                                  : isRate
                                  ? '采样率 0~1（越小噪音越少）'
                                  : ''}
                              </Text>
                            </Space>
                            <InputNumber
                              value={Number(current)}
                              min={isRate ? 0 : undefined}
                              max={isRate ? 1 : undefined}
                              step={isRate ? 0.05 : 1}
                              style={{ width: 200 }}
                              onChange={(v) => setTemplateParams((prev) => ({ ...prev, [key]: Number(v ?? 0) }))}
                            />
                          </div>
                        )
                      }

                      return (
                        <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <Space direction="vertical" size={0}>
                            <Text>{key}</Text>
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              string / other
                            </Text>
                          </Space>
                          <Input
                            value={String(current ?? '')}
                            style={{ width: 260 }}
                            onChange={(e) => setTemplateParams((prev) => ({ ...prev, [key]: e.target.value }))}
                          />
                        </div>
                      )
                    })}

                  <Divider style={{ margin: '8px 0' }} />
                  <div>
                    <Text type="secondary">高级：直接编辑 JSON（需为对象）</Text>
                    <TextArea
                      rows={6}
                      value={templateParamsJson}
                      onFocus={() => setEditingTemplateParamsJson(true)}
                      onBlur={() => {
                        setEditingTemplateParamsJson(false)
                        try {
                          const obj = JSON.parse(templateParamsJson || '{}')
                          if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
                            setTemplateParamsJsonError('JSON 必须为对象（Object）')
                            return
                          }
                          setTemplateParams(obj)
                          setTemplateParamsJsonError('')
                        } catch {
                          setTemplateParamsJsonError('JSON 解析失败，请检查格式')
                        }
                      }}
                      onChange={(e) => setTemplateParamsJson(e.target.value)}
                      style={{ fontFamily: 'monospace', fontSize: 12, marginTop: 6 }}
                    />
                    {templateParamsJsonError ? (
                      <Text type="danger" style={{ display: 'block', marginTop: 6 }}>
                        {templateParamsJsonError}
                      </Text>
                    ) : null}
                  </div>
                </Space>
              )}
            </Card>
          ) : null}
        </Space>
      </Modal>

      {/* 创建/编辑模板Modal */}
      <Modal
        title={editingTemplate ? '编辑模板' : '创建模板'}
        open={templateModalVisible}
        onCancel={() => setTemplateModalVisible(false)}
        onOk={handleSaveTemplate}
        width={800}
        confirmLoading={loading}
      >
        <Form
          form={form}
          layout="vertical"
        >
          <Form.Item
            name="name"
            label="模板名称"
            rules={[{ required: true, message: '请输入模板名称' }]}
          >
            <Input placeholder="例如: my_custom_hook" disabled={!!editingTemplate} />
          </Form.Item>
          <Form.Item
            name="description"
            label="模板描述"
            rules={[{ required: true, message: '请输入模板描述' }]}
          >
            <Input placeholder="简要描述这个Hook模板的功能" />
          </Form.Item>
          <Form.Item
            name="script_code"
            label="Frida脚本代码"
            rules={[{ required: true, message: '请输入脚本代码' }]}
          >
            <TextArea
              rows={15}
              placeholder="// Frida JavaScript代码&#10;// 例如:&#10;Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {&#10;  onEnter: function(args) {&#10;    console.log('CreateFileW called');&#10;  }&#10;});"
              style={{ fontFamily: 'monospace', fontSize: '12px' }}
            />
          </Form.Item>
        </Form>
      </Modal>

      {/* 查看模板详情Modal */}
      <Modal
        title={`模板详情: ${viewingTemplate?.name}`}
        open={templateDetailModalVisible}
        onCancel={() => setTemplateDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setTemplateDetailModalVisible(false)}>
            关闭
          </Button>
        ]}
        width={900}
      >
        {viewingTemplate && (
          <Space direction="vertical" style={{ width: '100%' }}>
            <Descriptions bordered size="small">
              <Descriptions.Item label="模板名称" span={3}>
                {viewingTemplate.name}
              </Descriptions.Item>
              <Descriptions.Item label="描述" span={3}>
                {viewingTemplate.description}
              </Descriptions.Item>
              <Descriptions.Item label="分类" span={3}>
                {viewingTemplate.category ? <Tag>{viewingTemplate.category}</Tag> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间" span={3}>
                {viewingTemplate.created_at ? new Date(viewingTemplate.created_at).toLocaleString('zh-CN') : '-'}
              </Descriptions.Item>
            </Descriptions>
            <div>
              <div style={{ marginBottom: 8, fontWeight: 'bold' }}>脚本代码：</div>
              <SyntaxHighlighter
                language="javascript"
                style={vscDarkPlus}
                showLineNumbers
                customStyle={{ fontSize: '12px', maxHeight: '400px' }}
              >
                {viewingTemplate.script_code}
              </SyntaxHighlighter>
            </div>
          </Space>
        )}
      </Modal>

      {/* 关联请求详情 */}
      <Modal
        title="关联的代理请求"
        open={linkedRequestVisible}
        onCancel={() => setLinkedRequestVisible(false)}
        footer={[
          <Button key="close" onClick={() => setLinkedRequestVisible(false)}>
            关闭
          </Button>
        ]}
        width={900}
      >
        {linkedRequest ? (
          <Descriptions bordered column={2} size="small">
            <Descriptions.Item label="ID" span={2}>
              <Text copyable>{linkedRequest.id}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Method">
              <Tag>{linkedRequest.method}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Status">{linkedRequest.status_code ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="URL" span={2}>
              <Text copyable style={{ wordBreak: 'break-all' }}>
                {linkedRequest.url}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="请求头" span={2}>
              <pre style={{ maxHeight: 200, overflow: 'auto', fontSize: 12 }}>{JSON.stringify(linkedRequest.headers || {}, null, 2)}</pre>
            </Descriptions.Item>
            {linkedRequest.body && (
              <Descriptions.Item label="请求体" span={2}>
                <pre style={{ maxHeight: 200, overflow: 'auto', fontSize: 12 }}>{linkedRequest.body}</pre>
              </Descriptions.Item>
            )}
            {linkedRequest.response_headers && (
              <Descriptions.Item label="响应头" span={2}>
                <pre style={{ maxHeight: 200, overflow: 'auto', fontSize: 12 }}>
                  {JSON.stringify(linkedRequest.response_headers || {}, null, 2)}
                </pre>
              </Descriptions.Item>
            )}
            {linkedRequest.response_body && (
              <Descriptions.Item label="响应体" span={2}>
                <pre style={{ maxHeight: 200, overflow: 'auto', fontSize: 12 }}>{linkedRequest.response_body}</pre>
              </Descriptions.Item>
            )}
          </Descriptions>
        ) : (
          <Text type="secondary">无数据</Text>
        )}
      </Modal>
    </div>
  )
}

export default NativeHook
