import React, { useState, useEffect } from 'react'
import {
  Card,
  Table,
  Button,
  Space,
  Input,
  message,
  Modal,
  Select,
  Tag,
  Badge,
  Descriptions,
  Alert,
  Tabs,
  Popconfirm,
  Form,
  Tooltip
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
  FileTextOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'

const { Option } = Select
const { TextArea } = Input
const { TabPane } = Tabs

interface Process {
  pid: number
  name: string
  parameters?: any
}

interface HookRecord {
  hook_id: string
  process_name: string
  pid: number
  hook_type: string
  api_name: string
  args: any
  timestamp: string
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
  created_at?: string
  updated_at?: string
}

const NativeHook: React.FC = () => {
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
  const [fridaStatus, setFridaStatus] = useState<any>(null)
  const [editingTemplate, setEditingTemplate] = useState<HookTemplate | null>(null)
  const [viewingTemplate, setViewingTemplate] = useState<HookTemplate | null>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    checkFridaStatus()
    loadSessions()
    loadTemplates()
    const interval = setInterval(() => {
      loadSessions()
      if (selectedSession) {
        loadRecords(selectedSession)
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [selectedSession])

  const checkFridaStatus = async () => {
    try {
      const response = await axios.get('/api/v1/native-hook/status')
      setFridaStatus(response.data)
    } catch (error) {
      console.error('检查Frida状态失败:', error)
    }
  }

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

  const loadSessions = async () => {
    try {
      const response = await axios.get('/api/v1/native-hook/sessions')
      setSessions(response.data.sessions)
    } catch (error) {
      console.error('加载会话失败:', error)
    }
  }

  const loadRecords = async (sessionId: string) => {
    try {
      const response = await axios.get('/api/v1/native-hook/records', {
        params: { session_id: sessionId, limit: 100 }
      })
      setRecords(response.data.records)
    } catch (error) {
      console.error('加载记录失败:', error)
    }
  }

  const loadTemplates = async () => {
    try {
      const response = await axios.get('/api/v1/native-hook/templates')
      setTemplates(response.data.templates || [])
    } catch (error) {
      console.error('加载模板失败:', error)
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
        template_name: scriptTemplate
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
      title: '参数',
      dataIndex: 'args',
      key: 'args',
      ellipsis: true,
      render: (args: any) => JSON.stringify(args).substring(0, 100)
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

      <Tabs defaultActiveKey="sessions">
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

          {/* Hook记录 */}
          {selectedSession && (
            <Card
              title="Hook记录"
              extra={
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
              }
            >
              <Table
                columns={recordColumns}
                dataSource={records}
                rowKey="hook_id"
                size="small"
                pagination={{ pageSize: 20 }}
              />
            </Card>
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
          <div>
            <label>选择Hook模板：</label>
            <Select
              value={scriptTemplate}
              onChange={setScriptTemplate}
              style={{ width: '100%', marginTop: 8 }}
            >
              {templates.map(t => (
                <Option key={t.name} value={t.name}>
                  {t.name} - {t.description}
                </Option>
              ))}
              {templates.length === 0 && (
                <Option value="windows_api_hooks">Windows API Hook (网络+加密)</Option>
              )}
            </Select>
          </div>
          <Alert
            message="提示"
            description="脚本将Hook目标进程的API调用，监控应用的行为。请确保选择正确的模板。"
            type="info"
            showIcon
          />
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
    </div>
  )
}

export default NativeHook
