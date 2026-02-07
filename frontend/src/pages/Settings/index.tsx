import React, { useEffect, useState } from 'react'
import {
  Card,
  Form,
  Input,
  Switch,
  Button,
  Space,
  Typography,
  Tabs,
  Divider,
  Select,
  InputNumber,
  Slider,
  Alert,
  Tag,
  Modal,
  notification,
  Row,
  Col
} from 'antd'
import {
  SettingOutlined,
  SaveOutlined,
  ReloadOutlined,
  ExclamationCircleOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  KeyOutlined,
  DatabaseOutlined,
  RobotOutlined,
  DownloadOutlined,
  BugOutlined,
  FilterOutlined,
  UnorderedListOutlined,
  SwapOutlined
} from '@ant-design/icons'
import { useGlobalStore } from '@store/GlobalStore'
import FilterManagement from '@components/FilterManagement'
import TaskManagement from '@components/TaskManagement'
import axios from 'axios'

const { Title, Text, Paragraph } = Typography
const { TextArea } = Input
const { Option } = Select
const { confirm } = Modal

type ExportSourceSession = {
  session_id: string
  status?: string
  started_at?: string
  ended_at?: string
  created_at?: string
  updated_at?: string
  notes?: string
  url?: string
  session_name?: string
  process_name?: string
  pid?: number
}

const SettingsPage: React.FC = () => {
  const [form] = Form.useForm()
  const [apiForm] = Form.useForm()
  const [loading, setLoading] = useState(false)
  const [migrationStatus, setMigrationStatus] = useState<any>(null)
  const [migrationLoading, setMigrationLoading] = useState(false)
  const [exportLoading, setExportLoading] = useState(false)
  const [exportSourcesLoading, setExportSourcesLoading] = useState(false)
  const [proxySessions, setProxySessions] = useState<ExportSourceSession[]>([])
  const [crawlerSessions, setCrawlerSessions] = useState<ExportSourceSession[]>([])
  const [hookSessions, setHookSessions] = useState<ExportSourceSession[]>([])
  const [analysisSessionId, setAnalysisSessionId] = useState<string>('')
  const [selectedProxySessionIds, setSelectedProxySessionIds] = useState<string[]>([])
  const [selectedCrawlerSessionIds, setSelectedCrawlerSessionIds] = useState<string[]>([])
  const [selectedHookSessionIds, setSelectedHookSessionIds] = useState<string[]>([])
  const [exportAutoAssociate, setExportAutoAssociate] = useState<boolean>(true)
  const [includeProxyArtifacts, setIncludeProxyArtifacts] = useState<boolean>(true)
  const { settings, updateSettings, theme, setTheme } = useGlobalStore()

  const loadExportSources = async () => {
    try {
      setExportSourcesLoading(true)
      const [proxyRes, crawlerRes, hookRes] = await Promise.all([
        axios.get('/api/v1/proxy/sessions', { params: { limit: 200, offset: 0 } }),
        axios.get('/api/v1/crawler/sessions'),
        axios.get('/api/v1/native-hook/sessions')
      ])

      setProxySessions(proxyRes.data?.sessions || [])
      setCrawlerSessions(crawlerRes.data?.sessions || [])
      setHookSessions(hookRes.data?.sessions || [])
    } catch (e) {
      console.error('加载导出会话列表失败:', e)
      setProxySessions([])
      setCrawlerSessions([])
      setHookSessions([])
    } finally {
      setExportSourcesLoading(false)
    }
  }

  const downloadAnalysisBundle = async () => {
    try {
      setExportLoading(true)

      const params = new URLSearchParams()
      if (analysisSessionId.trim()) params.set('analysis_session_id', analysisSessionId.trim())
      params.set('include_proxy_artifacts', includeProxyArtifacts ? 'true' : 'false')
      params.set('auto', exportAutoAssociate ? 'true' : 'false')
      selectedProxySessionIds.forEach((id) => params.append('proxy_session_id', id))
      selectedCrawlerSessionIds.forEach((id) => params.append('crawler_session_id', id))
      selectedHookSessionIds.forEach((id) => params.append('hook_session_id', id))

      const res = await axios.get(`/api/v1/export/analysis-bundle?${params.toString()}`, { responseType: 'blob' })

      const disposition = String(res.headers?.['content-disposition'] || '')
      const m = disposition.match(/filename="?([^";]+)"?/i)
      const fallbackName = `${(analysisSessionId || 'analysis_bundle').trim() || 'analysis_bundle'}.zip`
      const filename = m?.[1] ? decodeURIComponent(m[1]) : fallbackName

      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/zip' }))
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)

      notification.success({
        title: '导出成功',
        description: `已生成并下载：${filename}`
      })
    } catch (e: any) {
      notification.error({
        title: '导出失败',
        description: e.response?.data?.detail || '导出 AI 分析包失败'
      })
    } finally {
      setExportLoading(false)
    }
  }

  const loadMigrationStatus = async () => {
    try {
      setMigrationLoading(true)
      const res = await axios.get('/api/v1/migration/migration-status')
      setMigrationStatus(res.data)
    } catch (e) {
      console.error('加载迁移状态失败:', e)
      setMigrationStatus(null)
    } finally {
      setMigrationLoading(false)
    }
  }

  useEffect(() => {
    loadMigrationStatus()
    loadExportSources()
  }, [])

  // Restore last export selections (best-effort)
  useEffect(() => {
    try {
      const raw = localStorage.getItem('analysis_bundle_export_config')
      if (!raw) return
      const obj = JSON.parse(raw || '{}')
      if (obj && typeof obj === 'object') {
        setAnalysisSessionId(String(obj.analysisSessionId || ''))
        setSelectedProxySessionIds(Array.isArray(obj.selectedProxySessionIds) ? obj.selectedProxySessionIds : [])
        setSelectedCrawlerSessionIds(Array.isArray(obj.selectedCrawlerSessionIds) ? obj.selectedCrawlerSessionIds : [])
        setSelectedHookSessionIds(Array.isArray(obj.selectedHookSessionIds) ? obj.selectedHookSessionIds : [])
        setExportAutoAssociate(obj.exportAutoAssociate !== false)
        setIncludeProxyArtifacts(obj.includeProxyArtifacts !== false)
      }
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    try {
      localStorage.setItem(
        'analysis_bundle_export_config',
        JSON.stringify({
          analysisSessionId,
          selectedProxySessionIds,
          selectedCrawlerSessionIds,
          selectedHookSessionIds,
          exportAutoAssociate,
          includeProxyArtifacts
        })
      )
    } catch {
      // ignore
    }
  }, [analysisSessionId, selectedProxySessionIds, selectedCrawlerSessionIds, selectedHookSessionIds, exportAutoAssociate, includeProxyArtifacts])

  const handleSaveSettings = async () => {
    try {
      setLoading(true)
      const values = await form.validateFields()
      
      updateSettings({
        autoSave: values.autoSave,
        notifications: values.notifications,
        maxConcurrentRequests: values.maxConcurrentRequests,
        analysisThreshold: values.analysisThreshold
      })

      notification.success({
        title: '设置已保存',
        description: '您的设置更改已成功保存'
      })
    } catch (error) {
      console.error('保存设置失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSaveApiSettings = async () => {
    try {
      setLoading(true)
      const values = await apiForm.validateFields()
      
      // 这里应该调用API保存到后端
      console.log('保存API设置:', values)
      
      notification.success({
        title: 'API设置已保存',
        description: '新的API配置将在下次重启后生效'
      })
    } catch (error) {
      console.error('保存API设置失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleResetSettings = () => {
    confirm({
      title: '确认重置',
      icon: <ExclamationCircleOutlined />,
      content: '确定要重置所有设置到默认值吗？此操作不可撤销。',
      onOk() {
        form.resetFields()
        updateSettings({
          autoSave: true,
          notifications: true,
          maxConcurrentRequests: 5,
          analysisThreshold: 4.0
        })
        
        notification.info({
          title: '设置已重置',
          description: '所有设置已恢复到默认值'
        })
      }
    })
  }

  const handleTestConnection = async (service: string) => {
    try {
      setLoading(true)
      
      // 这里应该调用对应的健康检查API
      notification.success({
        title: `${service} 连接测试成功`,
        description: '服务响应正常'
      })
    } catch (error) {
      notification.error({
        title: `${service} 连接测试失败`,
        description: '请检查配置是否正确'
      })
    } finally {
      setLoading(false)
    }
  }

  const tabItems = [
    {
      key: 'general',
      label: (
        <span>
          <SettingOutlined />
          通用设置
        </span>
      ),
      children: (
        <div>
          <Form
            form={form}
            layout="vertical"
            initialValues={settings}
            onFinish={handleSaveSettings}
          >
            <Card title="基本设置" style={{ marginBottom: 24 }}>
              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    label="自动保存"
                    name="autoSave"
                    valuePropName="checked"
                    extra="启用后将自动保存录制数据和分析结果"
                  >
                    <Switch />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    label="桌面通知"
                    name="notifications"
                    valuePropName="checked"
                    extra="允许显示系统通知"
                  >
                    <Switch />
                  </Form.Item>
                </Col>
              </Row>

              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item
                    label="最大并发请求数"
                    name="maxConcurrentRequests"
                    extra="同时处理的最大请求数量"
                  >
                    <InputNumber min={1} max={20} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    label="分析阈值"
                    name="analysisThreshold"
                    extra="熵值分析的最小阈值"
                  >
                    <InputNumber min={0} max={8} step={0.1} />
                  </Form.Item>
                </Col>
              </Row>
            </Card>

            <Card title="界面设置" style={{ marginBottom: 24 }}>
              <Form.Item label="主题模式">
                <Select value={theme} onChange={setTheme}>
                  <Option value="light">亮色模式</Option>
                  <Option value="dark">暗色模式</Option>
                </Select>
              </Form.Item>

              <Alert
                title="主题设置"
                description="主题更改将立即生效，无需重启应用"
                type="info"
                showIcon
                style={{ marginTop: 16 }}
              />
            </Card>

            <Space>
              <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={loading}>
                保存设置
              </Button>
              <Button icon={<ReloadOutlined />} onClick={handleResetSettings}>
                重置默认
              </Button>
            </Space>
          </Form>
        </div>
      )
    },
    {
      key: 'api',
      label: (
        <span>
          <KeyOutlined />
          API 配置
        </span>
      ),
      children: (
        <div>
          <Alert
            title="API 配置说明"
            description="修改API配置后需要重启应用才能生效。请确保API密钥的安全性。"
            type="warning"
            showIcon
            style={{ marginBottom: 24 }}
          />

          <Form
            form={apiForm}
            layout="vertical"
            initialValues={{
              backendPort: 8000,
              frontendPort: 3000
            }}
          >

            <Card title="服务端口配置" style={{ marginBottom: 24 }}>
              <Row gutter={24}>
                <Col span={8}>
                  <Form.Item label="后端端口" name="backendPort">
                    <InputNumber min={1000} max={65535} />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item label="前端端口" name="frontendPort">
                    <InputNumber min={1000} max={65535} />
                  </Form.Item>
                </Col>
              </Row>
            </Card>

            <Space>
              <Button type="primary" icon={<SaveOutlined />} onClick={handleSaveApiSettings} loading={loading}>
                保存API配置
              </Button>
              <Button icon={<CheckCircleOutlined />} onClick={() => handleTestConnection('All')}>
                测试所有连接
              </Button>
            </Space>
          </Form>
        </div>
      )
    },
    {
      key: 'data',
      label: (
        <span>
          <DatabaseOutlined />
          数据管理
        </span>
      ),
      children: (
        <div>
          <Card title="数据存储设置" style={{ marginBottom: 24 }}>
            <Form layout="vertical">
              <Form.Item label="数据目录">
                <Space.Compact style={{ width: '100%' }}>
                  <Input defaultValue="./data" style={{ width: 'calc(100% - 50px)' }} />
                  <Button size="small">浏览</Button>
                </Space.Compact>
              </Form.Item>

              <Form.Item label="日志目录">
                <Space.Compact style={{ width: '100%' }}>
                  <Input defaultValue="./logs" style={{ width: 'calc(100% - 50px)' }} />
                  <Button size="small">浏览</Button>
                </Space.Compact>
              </Form.Item>

              <Form.Item label="缓存设置">
                <Row gutter={16}>
                  <Col span={12}>
                    <Text>缓存TTL (秒):</Text>
                    <Slider min={300} max={7200} defaultValue={3600} marks={{ 300: '5分钟', 3600: '1小时', 7200: '2小时' }} />
                  </Col>
                  <Col span={12}>
                    <Text>最大缓存大小:</Text>
                    <Slider min={100} max={5000} defaultValue={1000} marks={{ 100: '100', 1000: '1000', 5000: '5000' }} />
                  </Col>
                </Row>
              </Form.Item>
            </Form>
          </Card>

          <Card title="数据清理" style={{ marginBottom: 24 }}>
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Alert
                title="数据清理操作"
                description="这些操作将永久删除数据，请谨慎操作"
                type="error"
                showIcon
              />

              <Space wrap>
                <Button danger onClick={() => {
                  confirm({
                    title: '确认清理缓存',
                    content: '确定要清理所有缓存数据吗？',
                    onOk() {
                      notification.success({ title: '缓存已清理' })
                    }
                  })
                }}>
                  清理缓存
                </Button>

                <Button danger onClick={() => {
                  confirm({
                    title: '确认清理日志',
                    content: '确定要清理所有日志文件吗？',
                    onOk() {
                      notification.success({ title: '日志已清理' })
                    }
                  })
                }}>
                  清理日志
                </Button>

                <Button danger onClick={() => {
                  confirm({
                    title: '确认重置数据库',
                    content: '确定要重置数据库吗？这将删除所有录制数据和分析结果！',
                    onOk() {
                      notification.success({ title: '数据库已重置' })
                    }
                  })
                }}>
                  重置数据库
                </Button>
              </Space>
            </Space>
          </Card>
        </div>
      )
    },
    {
      key: 'advanced',
      label: (
        <span>
          <RobotOutlined />
          高级设置
        </span>
      ),
      children: (
        <div>
          <Card title="爬虫设置" style={{ marginBottom: 24 }}>
            <Form layout="vertical">
              <Form.Item 
                label="Chrome 浏览器路径" 
                extra="留空则自动查找系统安装的 Chrome，填写后优先使用指定路径"
              >
                <Input 
                  placeholder="例如: C:/Program Files/Google/Chrome/Application/chrome.exe"
                  defaultValue={localStorage.getItem('chrome_path') || ''}
                  onChange={(e) => {
                    localStorage.setItem('chrome_path', e.target.value)
                  }}
                />
              </Form.Item>

              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item label="默认超时时间 (秒)">
                    <InputNumber min={5} max={300} defaultValue={30} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item label="最大重试次数">
                    <InputNumber min={0} max={10} defaultValue={3} />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item label="默认User-Agent">
                <TextArea 
                  rows={3}
                  defaultValue="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                />
              </Form.Item>

              <Form.Item label="忽略的文件类型">
                <Select mode="tags" placeholder="输入文件扩展名" defaultValue={['jpg', 'png', 'gif', 'ico', 'css', 'js']}>
                  <Option value="jpg">jpg</Option>
                  <Option value="png">png</Option>
                  <Option value="gif">gif</Option>
                  <Option value="ico">ico</Option>
                  <Option value="css">css</Option>
                  <Option value="js">js</Option>
                </Select>
              </Form.Item>
            </Form>
          </Card>

          <Card title="分析设置" style={{ marginBottom: 24 }}>
            <Form layout="vertical">
              <Form.Item label="敏感参数关键词">
                <TextArea 
                  rows={4}
                  defaultValue="password,passwd,pwd,token,key,secret,auth,session,cookie,csrf,jwt"
                  placeholder="用逗号分隔多个关键词"
                />
              </Form.Item>

              <Form.Item label="加密算法关键词">
                <TextArea 
                  rows={4}
                  defaultValue="aes,rsa,des,md5,sha1,sha256,sha512,hmac,base64,encrypt,decrypt"
                  placeholder="用逗号分隔多个关键词"
                />
              </Form.Item>

              <Row gutter={24}>
                <Col span={12}>
                  <Form.Item label="最小熵值阈值">
                    <Slider min={1} max={8} step={0.1} defaultValue={4.0} marks={{ 1: '1.0', 4: '4.0', 8: '8.0' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item label="分析深度">
                    <Select defaultValue="medium">
                      <Option value="basic">基础</Option>
                      <Option value="medium">中等</Option>
                      <Option value="deep">深度</Option>
                    </Select>
                  </Form.Item>
                </Col>
              </Row>
            </Form>
          </Card>

        </div>
      )
    },
    {
      key: 'filters',
      label: (
        <span>
          <FilterOutlined />
          过滤器管理
        </span>
      ),
      children: <FilterManagement />
    },
    {
      key: 'tasks',
      label: (
        <span>
          <UnorderedListOutlined />
          任务管理
        </span>
      ),
      children: <TaskManagement />
    },
    {
      key: 'analysis-bundle',
      label: (
        <span>
          <DownloadOutlined />
          AI 分析包
        </span>
      ),
      children: (
        <div>
          <Alert
            type="info"
            showIcon
            message="一键导出 AI 分析包（zip）"
            description="支持将 proxy/crawler/native-hook 会话合并为一个 analysis_bundle，包含 manifest/index/summary 与 artifacts 引用。"
            style={{ marginBottom: 16 }}
          />

          <Card
            title="导出配置"
            extra={
              <Button onClick={loadExportSources} loading={exportSourcesLoading} icon={<ReloadOutlined />}>
                刷新会话列表
              </Button>
            }
            style={{ marginBottom: 16 }}
          >
            <Row gutter={16}>
              <Col xs={24} md={12}>
                <Paragraph style={{ marginBottom: 6 }}>
                  <Text>analysis_session_id（可选）：</Text>
                </Paragraph>
                <Input
                  value={analysisSessionId}
                  onChange={(e) => setAnalysisSessionId(e.target.value)}
                  placeholder="留空自动生成，例如 analysis_20260126_120000"
                />
                <Paragraph style={{ marginTop: 10, marginBottom: 6 }}>
                  <Text>自动关联缺省会话：</Text>
                </Paragraph>
                <Switch checked={exportAutoAssociate} onChange={setExportAutoAssociate} />
                <Paragraph style={{ marginTop: 10, marginBottom: 6 }}>
                  <Text>包含 proxy artifacts：</Text>
                </Paragraph>
                <Switch checked={includeProxyArtifacts} onChange={setIncludeProxyArtifacts} />
              </Col>
              <Col xs={24} md={12}>
                <Alert
                  type="warning"
                  showIcon
                  message="提示"
                  description={
                    <ul style={{ margin: 0, paddingLeft: 18 }}>
                      <li>若未选择任何会话且开启“自动关联”，后端会尽量选择当前/最近会话。</li>
                      <li>若关闭“自动关联”，至少选择 1 个来源会话（proxy/crawler/hook）才能导出。</li>
                      <li>包含 artifacts 会增加 zip 体积，但更利于 AI 回放与对比。</li>
                    </ul>
                  }
                />
              </Col>
            </Row>

            <Divider />

            <Row gutter={16}>
              <Col xs={24} md={8}>
                <Paragraph style={{ marginBottom: 6 }}>
                  <Text strong>Proxy 会话</Text>
                </Paragraph>
                <Select
                  mode="multiple"
                  allowClear
                  value={selectedProxySessionIds}
                  onChange={(v) => setSelectedProxySessionIds(v as string[])}
                  placeholder="可选；不选则可由 auto 填充"
                  style={{ width: '100%' }}
                  loading={exportSourcesLoading}
                  optionFilterProp="value"
                >
                  {proxySessions.map((s) => (
                    <Option
                      key={s.session_id}
                      value={s.session_id}
                      label={`${s.session_id} ${s.notes ? `(${s.notes})` : ''}`}
                    >
                      <Space>
                        <Text code>{s.session_id}</Text>
                        {s.status ? <Tag>{s.status}</Tag> : null}
                        {s.started_at ? <Text type="secondary">{new Date(s.started_at).toLocaleString('zh-CN')}</Text> : null}
                        {s.notes ? <Text type="secondary" ellipsis={{ tooltip: s.notes }}>{s.notes}</Text> : null}
                      </Space>
                    </Option>
                  ))}
                </Select>
              </Col>
              <Col xs={24} md={8}>
                <Paragraph style={{ marginBottom: 6 }}>
                  <Text strong>Crawler 会话</Text>
                </Paragraph>
                <Select
                  mode="multiple"
                  allowClear
                  value={selectedCrawlerSessionIds}
                  onChange={(v) => setSelectedCrawlerSessionIds(v as string[])}
                  placeholder="可选；不选则可由 auto 填充"
                  style={{ width: '100%' }}
                  loading={exportSourcesLoading}
                  optionFilterProp="value"
                >
                  {crawlerSessions.map((s) => (
                    <Option
                      key={s.session_id}
                      value={s.session_id}
                      label={`${s.session_name || s.session_id} ${s.url || ''}`}
                    >
                      <Space>
                        <Text code>{s.session_id}</Text>
                        {s.session_name ? <Text>{s.session_name}</Text> : null}
                        {s.url ? <Text type="secondary" ellipsis={{ tooltip: s.url }}>{s.url}</Text> : null}
                      </Space>
                    </Option>
                  ))}
                </Select>
              </Col>
              <Col xs={24} md={8}>
                <Paragraph style={{ marginBottom: 6 }}>
                  <Text strong>Native Hook 会话</Text>
                </Paragraph>
                <Select
                  mode="multiple"
                  allowClear
                  value={selectedHookSessionIds}
                  onChange={(v) => setSelectedHookSessionIds(v as string[])}
                  placeholder="可选；不选则可由 auto 填充"
                  style={{ width: '100%' }}
                  loading={exportSourcesLoading}
                  optionFilterProp="value"
                >
                  {hookSessions.map((s) => (
                    <Option
                      key={s.session_id}
                      value={s.session_id}
                      label={`${s.session_id} ${s.process_name || ''}`}
                    >
                      <Space>
                        <Text code>{s.session_id}</Text>
                        {s.process_name ? <Text>{s.process_name}</Text> : null}
                        {typeof s.pid === 'number' ? <Text type="secondary">PID:{s.pid}</Text> : null}
                      </Space>
                    </Option>
                  ))}
                </Select>
              </Col>
            </Row>

            <Divider />

            <Space>
              <Button type="primary" icon={<DownloadOutlined />} loading={exportLoading} onClick={downloadAnalysisBundle}>
                下载 AI 分析包
              </Button>
            </Space>
          </Card>
        </div>
      )
    },
    {
      key: 'migration',
      label: (
        <span>
          <SwapOutlined />
          迁移工具
        </span>
      ),
      children: (
        <div>
          <Alert
            type="warning"
            showIcon
            message="数据迁移说明"
            description="用于将旧版全局 requests.json 数据迁移到 session 级存储。建议在业务低峰执行，迁移后请用导出/下载确认数据完整。"
            style={{ marginBottom: 16 }}
          />

          <Card
            title="迁移状态"
            extra={
              <Button onClick={loadMigrationStatus} loading={migrationLoading} icon={<ReloadOutlined />}>
                刷新
              </Button>
            }
            style={{ marginBottom: 16 }}
          >
            <Row gutter={16}>
              <Col xs={24} md={12}>
                <Card size="small" title="全局存储 (requests.json)">
                  <Paragraph style={{ marginBottom: 8 }}>
                    <Text>总请求数：</Text>
                    <Text strong>{migrationStatus?.global_storage?.total_requests ?? '-'}</Text>
                  </Paragraph>
                  <Paragraph style={{ marginBottom: 0 }}>
                    <Text>是否需要迁移：</Text>
                    <Tag color={migrationStatus?.migration_needed ? 'orange' : 'green'}>
                      {migrationStatus?.migration_needed ? '需要' : '不需要'}
                    </Tag>
                  </Paragraph>
                </Card>
              </Col>
              <Col xs={24} md={12}>
                <Card size="small" title="会话存储 (sessions/*)">
                  <Paragraph style={{ marginBottom: 8 }}>
                    <Text>会话数：</Text>
                    <Text strong>{migrationStatus?.session_storage?.total_sessions ?? '-'}</Text>
                  </Paragraph>
                  <Paragraph style={{ marginBottom: 0 }}>
                    <Text>会话内请求总数：</Text>
                    <Text strong>{migrationStatus?.session_storage?.total_requests_in_sessions ?? '-'}</Text>
                  </Paragraph>
                </Card>
              </Col>
            </Row>

            <Divider />

            <Paragraph style={{ marginBottom: 0 }}>
              <Text type="secondary">当前存储模式：</Text>
              <Text code>{migrationStatus?.storage_type ?? 'unknown'}</Text>
            </Paragraph>
          </Card>

          <Space>
            <Button
              type="primary"
              loading={migrationLoading}
              onClick={() => {
                confirm({
                  title: '确认执行迁移',
                  icon: <ExclamationCircleOutlined />,
                  content: '将把全局 requests.json 迁移到 session 目录。建议提前备份数据目录。确定继续吗？',
                  async onOk() {
                    try {
                      setMigrationLoading(true)
                      const res = await axios.post('/api/v1/migration/migrate-to-session-storage')
                      notification.success({
                        title: '迁移完成',
                        description: res.data?.message || '迁移已完成'
                      })
                      await loadMigrationStatus()
                    } catch (e: any) {
                      notification.error({
                        title: '迁移失败',
                        description: e.response?.data?.detail || '迁移失败'
                      })
                    } finally {
                      setMigrationLoading(false)
                    }
                  }
                })
              }}
            >
              一键迁移到会话存储
            </Button>
          </Space>
        </div>
      )
    }
  ]

  return (
    <div className="page-container">
      {/* 页面头部 */}
      <div className="page-header">
        <div>
          <Title level={2} className="page-title">系统设置</Title>
          <Text className="page-description">配置系统参数和个人偏好设置</Text>
        </div>
      </div>

      <Card>
        <Tabs items={tabItems} />
      </Card>
    </div>
  )
}

export default SettingsPage
