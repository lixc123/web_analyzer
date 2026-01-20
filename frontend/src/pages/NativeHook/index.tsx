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
  Alert
} from 'antd'
import {
  SearchOutlined,
  ReloadOutlined,
  PlayCircleOutlined,
  PauseCircleOutlined,
  CodeOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'

const { Option } = Select
const { TextArea } = Input

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

const NativeHook: React.FC = () => {
  const [processes, setProcesses] = useState<Process[]>([])
  const [sessions, setSessions] = useState<HookSession[]>([])
  const [records, setRecords] = useState<HookRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [searchText, setSearchText] = useState('')
  const [attachModalVisible, setAttachModalVisible] = useState(false)
  const [injectModalVisible, setInjectModalVisible] = useState(false)
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null)
  const [selectedSession, setSelectedSession] = useState<string>('')
  const [scriptTemplate, setScriptTemplate] = useState('windows_api_hooks')
  const [fridaStatus, setFridaStatus] = useState<any>(null)

  useEffect(() => {
    checkFridaStatus()
    loadSessions()
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
        <Card title="Hook记录">
          <Table
            columns={recordColumns}
            dataSource={records}
            rowKey="hook_id"
            size="small"
            pagination={{ pageSize: 20 }}
          />
        </Card>
      )}

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
              <Option value="windows_api_hooks">Windows API Hook (网络+加密)</Option>
            </Select>
          </div>
          <Alert
            message="提示"
            description="脚本将Hook Windows网络API（WinHTTP、WinINet、Socket）和加密API（CryptEncrypt/Decrypt），监控应用的网络和加密操作。"
            type="info"
            showIcon
          />
        </Space>
      </Modal>
    </div>
  )
}

export default NativeHook
