import React, { useState, useEffect } from 'react'
import {
  Card,
  Table,
  Button,
  Space,
  Modal,
  message,
  Typography,
  Input,
  Tag,
  Tooltip,
  Statistic,
  Row,
  Col,
  Divider,
  Progress,
  Descriptions,
  Badge
} from 'antd'
import {
  CodeOutlined,
  DownloadOutlined,
  CopyOutlined,
  ReloadOutlined,
  SearchOutlined,
  EyeOutlined,
  FileTextOutlined,
  ThunderboltOutlined,
  BarChartOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'

const { Text, Title } = Typography

interface Session {
  name: string
  path: string
  created_at: string
  request_count?: number
}

interface SessionStats {
  session_name: string
  total_requests: number
  api_requests_count: number
  domains_count: number
  domains: string[]
  methods: Record<string, number>
  status_codes: Record<string, number>
  js_calls_count: number
  has_js_analysis: boolean
}

const CodeGenerator: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedSessions, setSelectedSessions] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [generatedCode, setGeneratedCode] = useState<string>('')
  const [codeModalVisible, setCodeModalVisible] = useState(false)
  const [statsModalVisible, setStatsModalVisible] = useState(false)
  const [currentStats, setCurrentStats] = useState<SessionStats | null>(null)
  const [searchText, setSearchText] = useState('')
  const [batchProgress, setBatchProgress] = useState<number>(0)
  const [currentSessionName, setCurrentSessionName] = useState<string>('')

  useEffect(() => {
    loadSessions()
  }, [])

  const loadSessions = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/crawler/sessions')
      setSessions(response.data.sessions || [])
    } catch (error) {
      console.error('加载会话列表失败:', error)
      message.error('加载会话列表失败')
    } finally {
      setLoading(false)
    }
  }

  // 预览代码
  const previewCode = async (sessionName: string) => {
    setGenerating(true)
    try {
      const response = await axios.get(`/api/v1/code-generator/preview/${sessionName}`)
      setGeneratedCode(response.data)
      setCurrentSessionName(sessionName)
      setCodeModalVisible(true)
      message.success('代码预览加载成功')
    } catch (error: any) {
      console.error('预览代码失败:', error)
      message.error(error.response?.data?.detail || '预览代码失败')
    } finally {
      setGenerating(false)
    }
  }

  // 生成并保存代码
  const generateCode = async (sessionName: string) => {
    setGenerating(true)
    try {
      const session = sessions.find(s => s.name === sessionName)
      if (!session) {
        message.error('会话不存在')
        return
      }

      const response = await axios.post('/api/v1/code-generator/generate', {
        session_path: session.path,
        include_js_analysis: true,
        output_format: 'python'
      })

      if (response.data.success) {
        message.success(response.data.message)
        setGeneratedCode(response.data.code_preview || '')
        setCurrentSessionName(sessionName)
        setCodeModalVisible(true)
      }
    } catch (error: any) {
      console.error('生成代码失败:', error)
      message.error(error.response?.data?.detail || '生成代码失败')
    } finally {
      setGenerating(false)
    }
  }

  // 下载代码
  const downloadCode = async (sessionName: string) => {
    try {
      const response = await axios.get(`/api/v1/code-generator/download/${sessionName}`, {
        responseType: 'blob'
      })

      const blob = new Blob([response.data], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `session_${sessionName}_${Date.now()}.py`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      message.success('代码已下载')
    } catch (error: any) {
      console.error('下载代码失败:', error)
      message.error(error.response?.data?.detail || '下载代码失败')
    }
  }

  // 查看会话统计
  const viewStats = async (sessionName: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/api/v1/code-generator/stats/${sessionName}`)
      setCurrentStats(response.data)
      setStatsModalVisible(true)
    } catch (error: any) {
      console.error('获取统计信息失败:', error)
      message.error(error.response?.data?.detail || '获取统计信息失败')
    } finally {
      setLoading(false)
    }
  }

  // 批量生成代码
  const batchGenerate = async () => {
    if (selectedSessions.length === 0) {
      message.warning('请至少选择一个会话')
      return
    }

    Modal.confirm({
      title: '批量生成代码',
      content: `确定要为选中的 ${selectedSessions.length} 个会话生成代码吗？`,
      onOk: async () => {
        setGenerating(true)
        setBatchProgress(0)
        try {
          const response = await axios.post('/api/v1/code-generator/batch-generate',
            selectedSessions
          )

          const { summary } = response.data
          setBatchProgress(100)

          Modal.success({
            title: '批量生成任务已启动',
            content: (
              <div>
                <p>成功: {summary.success_count} 个</p>
                <p>失败: {summary.failed_count} 个</p>
                <p>{summary.status}</p>
              </div>
            )
          })

          setSelectedSessions([])
        } catch (error: any) {
          console.error('批量生成失败:', error)
          message.error(error.response?.data?.detail || '批量生成失败')
        } finally {
          setGenerating(false)
          setBatchProgress(0)
        }
      }
    })
  }

  // 复制代码
  const copyCode = () => {
    navigator.clipboard.writeText(generatedCode)
    message.success('代码已复制到剪贴板')
  }

  // 下载当前预览的代码
  const downloadCurrentCode = () => {
    const blob = new Blob([generatedCode], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `session_${currentSessionName}_${Date.now()}.py`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    message.success('代码已下载')
  }

  const filteredSessions = sessions.filter(s =>
    searchText ? s.name.toLowerCase().includes(searchText.toLowerCase()) : true
  )

  const columns: ColumnsType<Session> = [
    {
      title: '会话名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => (
        <Text strong style={{ fontSize: '13px' }}>{name}</Text>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (time: string) => (
        <Text type="secondary">
          {new Date(time).toLocaleString('zh-CN')}
        </Text>
      )
    },
    {
      title: '请求数量',
      dataIndex: 'request_count',
      key: 'request_count',
      width: 100,
      render: (count: number) => (
        <Tag color="blue">{count || 0} 个</Tag>
      )
    },
    {
      title: '操作',
      key: 'actions',
      width: 350,
      render: (_, record) => (
        <Space size="small">
          <Tooltip title="查看统计信息">
            <Button
              icon={<BarChartOutlined />}
              size="small"
              onClick={() => viewStats(record.name)}
            >
              统计
            </Button>
          </Tooltip>
          <Tooltip title="预览生成的代码">
            <Button
              icon={<EyeOutlined />}
              size="small"
              onClick={() => previewCode(record.name)}
              loading={generating}
            >
              预览
            </Button>
          </Tooltip>
          <Tooltip title="生成并保存代码">
            <Button
              icon={<CodeOutlined />}
              size="small"
              type="primary"
              onClick={() => generateCode(record.name)}
              loading={generating}
            >
              生成
            </Button>
          </Tooltip>
          <Tooltip title="直接下载代码">
            <Button
              icon={<DownloadOutlined />}
              size="small"
              onClick={() => downloadCode(record.name)}
            >
              下载
            </Button>
          </Tooltip>
        </Space>
      )
    }
  ]

  const rowSelection = {
    selectedRowKeys: selectedSessions,
    onChange: (selectedRowKeys: React.Key[]) => {
      setSelectedSessions(selectedRowKeys as string[])
    }
  }

  return (
    <div style={{ padding: '24px' }}>
      <Card
        title={
          <Space>
            <CodeOutlined />
            <span>代码生成器</span>
            {selectedSessions.length > 0 && (
              <Tag color="blue">{selectedSessions.length} 个会话已选择</Tag>
            )}
          </Space>
        }
        extra={
          <Space>
            <Input
              placeholder="搜索会话名称"
              prefix={<SearchOutlined />}
              value={searchText}
              onChange={e => setSearchText(e.target.value)}
              style={{ width: 200 }}
              size="small"
              allowClear
            />
            <Button
              icon={<ReloadOutlined />}
              onClick={loadSessions}
              loading={loading}
              size="small"
            >
              刷新
            </Button>
            <Button
              type="primary"
              icon={<ThunderboltOutlined />}
              onClick={batchGenerate}
              loading={generating}
              disabled={selectedSessions.length === 0}
              size="small"
            >
              批量生成 ({selectedSessions.length})
            </Button>
          </Space>
        }
      >
        {batchProgress > 0 && (
          <div style={{ marginBottom: 16 }}>
            <Progress percent={batchProgress} status="active" />
          </div>
        )}

        <Table
          rowSelection={rowSelection}
          columns={columns}
          dataSource={filteredSessions}
          rowKey="name"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个会话`
          }}
          size="small"
        />
      </Card>

      {/* 代码预览Modal */}
      <Modal
        title={
          <Space>
            <CodeOutlined />
            <span>生成的Python代码</span>
            <Tag color="blue">{currentSessionName}</Tag>
          </Space>
        }
        open={codeModalVisible}
        onCancel={() => setCodeModalVisible(false)}
        width={1200}
        footer={[
          <Button key="copy" icon={<CopyOutlined />} onClick={copyCode}>
            复制代码
          </Button>,
          <Button key="download" icon={<DownloadOutlined />} onClick={downloadCurrentCode} type="primary">
            下载代码
          </Button>,
          <Button key="close" onClick={() => setCodeModalVisible(false)}>
            关闭
          </Button>
        ]}
      >
        <div style={{ maxHeight: '600px', overflow: 'auto' }}>
          <SyntaxHighlighter
            language="python"
            style={vscDarkPlus}
            showLineNumbers
            customStyle={{ fontSize: '12px', margin: 0 }}
          >
            {generatedCode}
          </SyntaxHighlighter>
        </div>
      </Modal>

      {/* 统计信息Modal */}
      <Modal
        title={
          <Space>
            <BarChartOutlined />
            <span>会话统计信息</span>
          </Space>
        }
        open={statsModalVisible}
        onCancel={() => setStatsModalVisible(false)}
        width={800}
        footer={[
          <Button key="close" type="primary" onClick={() => setStatsModalVisible(false)}>
            关闭
          </Button>
        ]}
      >
        {currentStats && (
          <div>
            <Row gutter={16} style={{ marginBottom: 24 }}>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="总请求数"
                    value={currentStats.total_requests}
                    prefix={<FileTextOutlined />}
                  />
                </Card>
              </Col>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="API请求"
                    value={currentStats.api_requests_count}
                    prefix={<CodeOutlined />}
                    valueStyle={{ color: '#3f8600' }}
                  />
                </Card>
              </Col>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="域名数量"
                    value={currentStats.domains_count}
                    prefix={<ThunderboltOutlined />}
                  />
                </Card>
              </Col>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="JS调用栈"
                    value={currentStats.js_calls_count}
                    prefix={<CodeOutlined />}
                    valueStyle={{ color: currentStats.has_js_analysis ? '#cf1322' : '#999' }}
                  />
                </Card>
              </Col>
            </Row>

            <Divider titlePlacement="left">请求方法统计</Divider>
            <Space wrap>
              {Object.entries(currentStats.methods).map(([method, count]) => {
                const colors: Record<string, string> = {
                  GET: 'blue',
                  POST: 'green',
                  PUT: 'orange',
                  DELETE: 'red',
                  PATCH: 'purple'
                }
                return (
                  <Tag key={method} color={colors[method] || 'default'}>
                    {method}: {count}
                  </Tag>
                )
              })}
            </Space>

            <Divider titlePlacement="left">状态码统计</Divider>
            <Space wrap>
              {Object.entries(currentStats.status_codes).map(([code, count]) => {
                const color = code.startsWith('2') ? 'success' :
                             code.startsWith('3') ? 'processing' :
                             code.startsWith('4') ? 'warning' : 'error'
                return (
                  <Badge key={code} count={count} showZero>
                    <Tag color={color}>{code}</Tag>
                  </Badge>
                )
              })}
            </Space>

            <Divider titlePlacement="left">涉及域名</Divider>
            <div style={{ maxHeight: 200, overflow: 'auto' }}>
              {currentStats.domains.map((domain, index) => (
                <Tag key={index} style={{ marginBottom: 8 }}>
                  {domain}
                </Tag>
              ))}
            </div>

            <Divider titlePlacement="left">会话信息</Divider>
            <Descriptions bordered size="small" column={1}>
              <Descriptions.Item label="会话名称">
                {currentStats.session_name}
              </Descriptions.Item>
              <Descriptions.Item label="JS分析">
                {currentStats.has_js_analysis ? (
                  <Tag color="success">已启用</Tag>
                ) : (
                  <Tag color="default">未启用</Tag>
                )}
              </Descriptions.Item>
            </Descriptions>
          </div>
        )}
      </Modal>
    </div>
  )
}

export default CodeGenerator
