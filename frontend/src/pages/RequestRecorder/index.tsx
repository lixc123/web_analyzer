import React, { useState, useEffect } from 'react'
import {
  Card,
  Button,
  Space,
  Table,
  Tag,
  Typography,
  message,
  Modal,
  Descriptions,
  Tabs,
  Input,
  Select,
  Form,
  Switch,
  Statistic,
  Row,
  Col,
  Alert,
  Divider
} from 'antd'
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  DeleteOutlined,
  ReloadOutlined,
  EyeOutlined,
  ThunderboltOutlined,
  HistoryOutlined,
  CodeOutlined
} from '@ant-design/icons'
import axios from 'axios'
import type { ColumnsType } from 'antd/es/table'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'

const { Title, Text } = Typography
const { TextArea } = Input
const { Option } = Select

interface RecordedRequest {
  id: string
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  response?: {
    status: number
    headers: Record<string, string>
    body: string
  }
  timestamp: number
  call_stack?: any[]
}

interface ReplayResult {
  success: boolean
  status_code?: number
  response_body?: string
  error?: string
  duration_ms?: number
}

const RequestRecorder: React.FC = () => {
  const [recording, setRecording] = useState(false)
  const [requests, setRequests] = useState<RecordedRequest[]>([])
  const [selectedRequest, setSelectedRequest] = useState<RecordedRequest | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)
  const [replayModalVisible, setReplayModalVisible] = useState(false)
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [statistics, setStatistics] = useState<any>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    loadRequests()
    loadStatistics()
  }, [])

  // 加载请求列表
  const loadRequests = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/request-analysis/requests')
      setRequests(response.data.requests || [])
    } catch (error) {
      console.error('加载请求列表失败:', error)
      message.error('加载请求列表失败')
    } finally {
      setLoading(false)
    }
  }

  // 加载统计信息
  const loadStatistics = async () => {
    try {
      const response = await axios.get('/api/v1/request-analysis/statistics')
      setStatistics(response.data)
    } catch (error) {
      console.error('加载统计信息失败:', error)
    }
  }

  // 开始录制
  const startRecording = async () => {
    try {
      await axios.post('/api/v1/request-analysis/start-recording')
      setRecording(true)
      message.success('开始录制请求')
    } catch (error: any) {
      console.error('开始录制失败:', error)
      message.error(error.response?.data?.detail || '开始录制失败')
    }
  }

  // 停止录制
  const stopRecording = async () => {
    try {
      await axios.post('/api/v1/request-analysis/stop-recording')
      setRecording(false)
      message.success('停止录制请求')
      loadRequests()
      loadStatistics()
    } catch (error: any) {
      console.error('停止录制失败:', error)
      message.error(error.response?.data?.detail || '停止录制失败')
    }
  }

  // 清空请求
  const clearRequests = () => {
    Modal.confirm({
      title: '确认清空',
      content: '确定要清空所有录制的请求吗？此操作不可恢复。',
      onOk: async () => {
        try {
          await axios.delete('/api/v1/request-analysis/requests')
          setRequests([])
          message.success('已清空所有请求')
          loadStatistics()
        } catch (error: any) {
          console.error('清空请求失败:', error)
          message.error(error.response?.data?.detail || '清空请求失败')
        }
      }
    })
  }

  // 查看请求详情
  const viewRequestDetail = async (requestId: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/api/v1/request-analysis/request/${requestId}`)
      setSelectedRequest(response.data)
      setDetailModalVisible(true)
    } catch (error: any) {
      console.error('获取请求详情失败:', error)
      message.error(error.response?.data?.detail || '获取请求详情失败')
    } finally {
      setLoading(false)
    }
  }

  // 重放请求
  const replayRequest = async (values: any) => {
    if (!selectedRequest) return

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/request-analysis/replay-request', {
        request_id: selectedRequest.id,
        modify_headers: values.modify_headers || {},
        modify_body: values.modify_body,
        follow_redirects: values.follow_redirects !== false,
        verify_ssl: values.verify_ssl !== false
      })

      setReplayResult(response.data)
      message.success('请求重放成功')
    } catch (error: any) {
      console.error('重放请求失败:', error)
      setReplayResult({
        success: false,
        error: error.response?.data?.detail || '重放请求失败'
      })
      message.error(error.response?.data?.detail || '重放请求失败')
    } finally {
      setLoading(false)
    }
  }

  const columns: ColumnsType<RecordedRequest> = [
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => {
        const colors: Record<string, string> = {
          GET: 'blue',
          POST: 'green',
          PUT: 'orange',
          DELETE: 'red',
          PATCH: 'purple'
        }
        return <Tag color={colors[method] || 'default'}>{method}</Tag>
      }
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Text style={{ fontSize: '12px' }} ellipsis={{ tooltip: url }}>
          {url}
        </Text>
      )
    },
    {
      title: '状态码',
      dataIndex: ['response', 'status'],
      key: 'status',
      width: 80,
      render: (status: number) => {
        if (!status) return <Tag>-</Tag>
        const color = status >= 200 && status < 300 ? 'success' :
                     status >= 300 && status < 400 ? 'processing' :
                     status >= 400 && status < 500 ? 'warning' : 'error'
        return <Tag color={color}>{status}</Tag>
      }
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (timestamp: number) => (
        <Text type="secondary">
          {new Date(timestamp * 1000).toLocaleString('zh-CN')}
        </Text>
      )
    },
    {
      title: '调用栈',
      dataIndex: 'call_stack',
      key: 'call_stack',
      width: 80,
      render: (callStack: any[]) => (
        callStack && callStack.length > 0 ? (
          <Tag color="purple">{callStack.length} 层</Tag>
        ) : (
          <Tag>无</Tag>
        )
      )
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      render: (_, record) => (
        <Space size="small">
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => viewRequestDetail(record.id)}
          >
            详情
          </Button>
          <Button
            type="link"
            size="small"
            icon={<ThunderboltOutlined />}
            onClick={() => {
              setSelectedRequest(record)
              setReplayModalVisible(true)
              setReplayResult(null)
              form.resetFields()
            }}
          >
            重放
          </Button>
        </Space>
      )
    }
  ]

  return (
    <div style={{ padding: '24px' }}>
      {/* 统计卡片 */}
      {statistics && (
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={6}>
            <Card>
              <Statistic
                title="录制的请求"
                value={statistics.total_requests || 0}
                prefix={<HistoryOutlined />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="API请求"
                value={statistics.api_requests || 0}
                prefix={<CodeOutlined />}
                valueStyle={{ color: '#3f8600' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="成功率"
                value={statistics.success_rate || 0}
                suffix="%"
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="平均响应时间"
                value={statistics.avg_response_time || 0}
                suffix="ms"
                valueStyle={{ color: '#1890ff' }}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* 主卡片 */}
      <Card
        title={
          <Space>
            <HistoryOutlined />
            <span>请求录制器</span>
            {recording && <Tag color="red">录制中...</Tag>}
          </Space>
        }
        extra={
          <Space>
            {!recording ? (
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={startRecording}
              >
                开始录制
              </Button>
            ) : (
              <Button
                danger
                icon={<PauseCircleOutlined />}
                onClick={stopRecording}
              >
                停止录制
              </Button>
            )}
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                loadRequests()
                loadStatistics()
              }}
              loading={loading}
            >
              刷新
            </Button>
            <Button
              danger
              icon={<DeleteOutlined />}
              onClick={clearRequests}
              disabled={requests.length === 0}
            >
              清空
            </Button>
          </Space>
        }
      >
        <Alert
          message="请求录制说明"
          description="开始录制后，系统将自动捕获所有HTTP/HTTPS请求。您可以查看请求详情、重放请求或导出为代码。"
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          closable
        />

        <Table
          columns={columns}
          dataSource={requests}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个请求`
          }}
          size="small"
        />
      </Card>

      {/* 请求详情Modal */}
      <Modal
        title={
          <Space>
            <EyeOutlined />
            <span>请求详情</span>
          </Space>
        }
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        width={1000}
        footer={[
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>
        ]}
      >
        {selectedRequest && (
          <Tabs
            items={[
              {
                key: 'general',
                label: '基本信息',
                children: (
                  <Descriptions bordered column={1} size="small">
                    <Descriptions.Item label="请求方法">
                      <Tag color="blue">{selectedRequest.method}</Tag>
                    </Descriptions.Item>
                    <Descriptions.Item label="请求URL">
                      {selectedRequest.url}
                    </Descriptions.Item>
                    <Descriptions.Item label="时间戳">
                      {new Date(selectedRequest.timestamp * 1000).toLocaleString('zh-CN')}
                    </Descriptions.Item>
                    {selectedRequest.response && (
                      <Descriptions.Item label="响应状态">
                        <Tag color="success">{selectedRequest.response.status}</Tag>
                      </Descriptions.Item>
                    )}
                  </Descriptions>
                )
              },
              {
                key: 'headers',
                label: '请求头',
                children: (
                  <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ fontSize: '12px' }}>
                    {JSON.stringify(selectedRequest.headers, null, 2)}
                  </SyntaxHighlighter>
                )
              },
              {
                key: 'body',
                label: '请求体',
                children: selectedRequest.body ? (
                  <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ fontSize: '12px' }}>
                    {typeof selectedRequest.body === 'string' ? selectedRequest.body : JSON.stringify(selectedRequest.body, null, 2)}
                  </SyntaxHighlighter>
                ) : (
                  <Text type="secondary">无请求体</Text>
                )
              },
              {
                key: 'response',
                label: '响应',
                children: selectedRequest.response ? (
                  <div>
                    <Divider orientation="left">响应头</Divider>
                    <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ fontSize: '12px' }}>
                      {JSON.stringify(selectedRequest.response.headers, null, 2)}
                    </SyntaxHighlighter>
                    <Divider orientation="left">响应体</Divider>
                    <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ fontSize: '12px', maxHeight: '300px' }}>
                      {selectedRequest.response.body}
                    </SyntaxHighlighter>
                  </div>
                ) : (
                  <Text type="secondary">无响应数据</Text>
                )
              },
              {
                key: 'callstack',
                label: '调用栈',
                children: selectedRequest.call_stack && selectedRequest.call_stack.length > 0 ? (
                  <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ fontSize: '12px' }}>
                    {JSON.stringify(selectedRequest.call_stack, null, 2)}
                  </SyntaxHighlighter>
                ) : (
                  <Text type="secondary">无调用栈信息</Text>
                )
              }
            ]}
          />
        )}
      </Modal>

      {/* 重放请求Modal */}
      <Modal
        title={
          <Space>
            <ThunderboltOutlined />
            <span>重放请求</span>
          </Space>
        }
        open={replayModalVisible}
        onCancel={() => setReplayModalVisible(false)}
        width={800}
        footer={null}
      >
        {selectedRequest && (
          <div>
            <Alert
              message={`${selectedRequest.method} ${selectedRequest.url}`}
              type="info"
              style={{ marginBottom: 16 }}
            />

            <Form
              form={form}
              layout="vertical"
              onFinish={replayRequest}
              initialValues={{
                follow_redirects: true,
                verify_ssl: true
              }}
            >
              <Form.Item label="修改请求头（JSON格式）" name="modify_headers">
                <TextArea
                  rows={4}
                  placeholder='{"Authorization": "Bearer new_token"}'
                />
              </Form.Item>

              <Form.Item label="修改请求体" name="modify_body">
                <TextArea
                  rows={6}
                  placeholder="留空则使用原始请求体"
                />
              </Form.Item>

              <Row gutter={16}>
                <Col span={12}>
                  <Form.Item label="跟随重定向" name="follow_redirects" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item label="验证SSL证书" name="verify_ssl" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item>
                <Space>
                  <Button type="primary" htmlType="submit" loading={loading} icon={<ThunderboltOutlined />}>
                    执行重放
                  </Button>
                  <Button onClick={() => setReplayModalVisible(false)}>
                    取消
                  </Button>
                </Space>
              </Form.Item>
            </Form>

            {replayResult && (
              <div style={{ marginTop: 24 }}>
                <Divider orientation="left">重放结果</Divider>
                {replayResult.success ? (
                  <Alert
                    message="重放成功"
                    description={
                      <div>
                        <p>状态码: <Tag color="success">{replayResult.status_code}</Tag></p>
                        <p>耗时: {replayResult.duration_ms}ms</p>
                        <Divider orientation="left">响应内容</Divider>
                        <SyntaxHighlighter language="json" style={vscDarkPlus} customStyle={{ fontSize: '11px', maxHeight: '200px' }}>
                          {replayResult.response_body || ''}
                        </SyntaxHighlighter>
                      </div>
                    }
                    type="success"
                  />
                ) : (
                  <Alert
                    message="重放失败"
                    description={replayResult.error}
                    type="error"
                  />
                )}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

export default RequestRecorder
