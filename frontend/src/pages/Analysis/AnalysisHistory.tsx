import React, { useCallback, useState, useEffect } from 'react'
import {
  Card,
  Table,
  Button,
  Space,
  Select,
  Tag,
  Modal,
  Descriptions,
  List,
  Typography,
  message,
  Alert,
  Statistic,
  Row,
  Col,
  Divider,
  Empty
} from 'antd'
import {
  EyeOutlined,
  DownloadOutlined,
  ReloadOutlined,
  DiffOutlined,
  ExclamationCircleOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  HistoryOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'

const { Option } = Select
const { Text, Title } = Typography

interface AnalysisRecord {
  analysis_id: string
  session_id: string
  analysis_type: string
  timestamp: string
  suspicious_count: number
  suspicious_requests?: any[]
  summary?: any
  config?: any
  risk_levels?: {
    high: number
    medium: number
    low: number
  }
}

interface Session {
  session_id: string
  session_name?: string
}

const AnalysisHistory: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedSession, setSelectedSession] = useState<string | null>(null)
  const [history, setHistory] = useState<AnalysisRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [detailModalVisible, setDetailModalVisible] = useState(false)
  const [compareModalVisible, setCompareModalVisible] = useState(false)
  const [selectedRecord, setSelectedRecord] = useState<AnalysisRecord | null>(null)
  const [compareRecords, setCompareRecords] = useState<AnalysisRecord[]>([])
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([])

  const loadSessions = useCallback(async () => {
    try {
      const response = await axios.get('/api/v1/crawler/sessions')
      setSessions(response.data.sessions || [])
    } catch (error: any) {
      console.error('加载会话列表失败:', error)
      message.error('加载会话列表失败')
    }
  }, [])

  const loadHistory = useCallback(async (sessionId: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/api/v1/analysis/history/${sessionId}`, {
        params: { limit: 100 }
      })
      setHistory(response.data.history || [])
    } catch (error: any) {
      console.error('加载分析历史失败:', error)
      message.error(error.response?.data?.detail || '加载分析历史失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadSessions()
  }, [loadSessions])

  useEffect(() => {
    if (selectedSession) {
      loadHistory(selectedSession)
    }
  }, [selectedSession, loadHistory])

  const handleViewDetail = (record: AnalysisRecord) => {
    setSelectedRecord(record)
    setDetailModalVisible(true)
  }

  const handleExport = (record: AnalysisRecord) => {
    const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `analysis_${record.analysis_id}_${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    message.success('分析结果已导出')
  }

  const handleCompare = () => {
    if (selectedRowKeys.length < 2) {
      message.warning('请至少选择两条记录进行对比')
      return
    }
    if (selectedRowKeys.length > 3) {
      message.warning('最多只能对比三条记录')
      return
    }

    const records = history.filter(r => selectedRowKeys.includes(r.analysis_id))
    setCompareRecords(records)
    setCompareModalVisible(true)
  }

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'high': return <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
      case 'medium': return <WarningOutlined style={{ color: '#faad14' }} />
      case 'low': return <CheckCircleOutlined style={{ color: '#52c41a' }} />
      default: return null
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'high': return 'red'
      case 'medium': return 'orange'
      case 'low': return 'blue'
      default: return 'default'
    }
  }

  const getAnalysisTypeTag = (type: string) => {
    const typeMap: Record<string, { color: string; text: string }> = {
      all: { color: 'purple', text: '综合分析' },
      entropy: { color: 'blue', text: '熵值分析' },
      sensitive_params: { color: 'green', text: '敏感参数' },
      encryption_keywords: { color: 'orange', text: '加密关键词' }
    }
    const config = typeMap[type] || { color: 'default', text: type }
    return <Tag color={config.color}>{config.text}</Tag>
  }

  const columns: ColumnsType<AnalysisRecord> = [
    {
      title: '分析ID',
      dataIndex: 'analysis_id',
      key: 'analysis_id',
      width: 120,
      render: (id: string) => (
        <Text code style={{ fontSize: '11px' }}>{id.slice(-8)}</Text>
      )
    },
    {
      title: '分析类型',
      dataIndex: 'analysis_type',
      key: 'analysis_type',
      width: 120,
      render: (type: string) => getAnalysisTypeTag(type)
    },
    {
      title: '可疑请求',
      dataIndex: 'suspicious_count',
      key: 'suspicious_count',
      width: 100,
      render: (count: number) => (
        <Text style={{ color: count > 0 ? '#ff4d4f' : '#52c41a', fontWeight: 'bold' }}>
          {count || 0}
        </Text>
      ),
      sorter: (a, b) => (a.suspicious_count || 0) - (b.suspicious_count || 0)
    },
    {
      title: '风险等级',
      key: 'risk_levels',
      width: 180,
      render: (record: AnalysisRecord) => {
        if (!record.risk_levels) return '-'
        return (
          <Space size="small">
            {record.risk_levels.high > 0 && (
              <Tag color="red" icon={getRiskIcon('high')}>
                高: {record.risk_levels.high}
              </Tag>
            )}
            {record.risk_levels.medium > 0 && (
              <Tag color="orange" icon={getRiskIcon('medium')}>
                中: {record.risk_levels.medium}
              </Tag>
            )}
            {record.risk_levels.low > 0 && (
              <Tag color="blue" icon={getRiskIcon('low')}>
                低: {record.risk_levels.low}
              </Tag>
            )}
          </Space>
        )
      }
    },
    {
      title: '分析时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (time: string) => new Date(time).toLocaleString('zh-CN'),
      sorter: (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      defaultSortOrder: 'descend'
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (record: AnalysisRecord) => (
        <Space>
          <Button
            type="text"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetail(record)}
            size="small"
          >
            查看
          </Button>
          <Button
            type="text"
            icon={<DownloadOutlined />}
            onClick={() => handleExport(record)}
            size="small"
          >
            导出
          </Button>
        </Space>
      )
    }
  ]

  const rowSelection = {
    selectedRowKeys,
    onChange: (selectedRowKeys: React.Key[]) => {
      setSelectedRowKeys(selectedRowKeys)
    }
  }

  return (
    <div>
      <Alert
        message="分析历史记录"
        description="查看历史分析记录，对比不同时间的分析结果，导出分析数据。"
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      <Card
        title={
          <Space>
            <HistoryOutlined />
            <span>历史记录</span>
            {selectedSession && <Tag color="blue">{history.length} 条记录</Tag>}
          </Space>
        }
        extra={
          <Space>
            <Select
              placeholder="选择会话"
              value={selectedSession}
              onChange={setSelectedSession}
              style={{ width: 200 }}
              size="small"
            >
              {sessions.map((session) => (
                <Option key={session.session_id} value={session.session_id}>
                  {session.session_name || `会话-${session.session_id.slice(-8)}`}
                </Option>
              ))}
            </Select>
            <Button
              icon={<DiffOutlined />}
              onClick={handleCompare}
              disabled={selectedRowKeys.length < 2}
              size="small"
            >
              对比 ({selectedRowKeys.length})
            </Button>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => selectedSession && loadHistory(selectedSession)}
              disabled={!selectedSession}
              loading={loading}
              size="small"
            >
              刷新
            </Button>
          </Space>
        }
      >
        {selectedSession ? (
          <Table
            rowSelection={rowSelection}
            columns={columns}
            dataSource={history}
            rowKey="analysis_id"
            loading={loading}
            pagination={{
              pageSize: 10,
              showSizeChanger: true,
              showTotal: (total) => `共 ${total} 条记录`
            }}
            scroll={{ x: 1200 }}
          />
        ) : (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="请选择一个会话查看分析历史"
          />
        )}
      </Card>

      {/* 详情Modal */}
      <Modal
        title="分析详情"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        width={900}
        footer={[
          <Button key="export" icon={<DownloadOutlined />} onClick={() => selectedRecord && handleExport(selectedRecord)}>
            导出
          </Button>,
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>
        ]}
      >
        {selectedRecord && (
          <div>
            <Descriptions title="基本信息" bordered style={{ marginBottom: 24 }}>
              <Descriptions.Item label="分析ID" span={2}>
                <Text code>{selectedRecord.analysis_id}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="分析类型">
                {getAnalysisTypeTag(selectedRecord.analysis_type)}
              </Descriptions.Item>
              <Descriptions.Item label="会话ID" span={2}>
                <Text code>{selectedRecord.session_id}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="分析时间">
                {new Date(selectedRecord.timestamp).toLocaleString('zh-CN')}
              </Descriptions.Item>
            </Descriptions>

            <Row gutter={16} style={{ marginBottom: 24 }}>
              <Col span={8}>
                <Card>
                  <Statistic
                    title="可疑请求"
                    value={selectedRecord.suspicious_count || 0}
                    valueStyle={{ color: selectedRecord.suspicious_count > 0 ? '#ff4d4f' : '#52c41a' }}
                    prefix={<ExclamationCircleOutlined />}
                  />
                </Card>
              </Col>
              {selectedRecord.risk_levels && (
                <>
                  <Col span={5}>
                    <Card>
                      <Statistic
                        title="高风险"
                        value={selectedRecord.risk_levels.high || 0}
                        valueStyle={{ color: '#ff4d4f' }}
                        prefix={getRiskIcon('high')}
                      />
                    </Card>
                  </Col>
                  <Col span={5}>
                    <Card>
                      <Statistic
                        title="中等风险"
                        value={selectedRecord.risk_levels.medium || 0}
                        valueStyle={{ color: '#faad14' }}
                        prefix={getRiskIcon('medium')}
                      />
                    </Card>
                  </Col>
                  <Col span={6}>
                    <Card>
                      <Statistic
                        title="低风险"
                        value={selectedRecord.risk_levels.low || 0}
                        valueStyle={{ color: '#52c41a' }}
                        prefix={getRiskIcon('low')}
                      />
                    </Card>
                  </Col>
                </>
              )}
            </Row>

            {selectedRecord.suspicious_requests && selectedRecord.suspicious_requests.length > 0 && (
              <Card title="可疑请求列表" style={{ marginBottom: 24 }}>
                <List
                  dataSource={selectedRecord.suspicious_requests}
                  renderItem={(item: any, index: number) => (
                    <List.Item>
                      <List.Item.Meta
                        title={
                          <Space>
                            <Tag color={getRiskColor(item.risk_level || 'medium')}>
                              {item.method || 'GET'}
                            </Tag>
                            <Text ellipsis style={{ maxWidth: 500 }}>
                              {item.url}
                            </Text>
                          </Space>
                        }
                        description={item.reason || '检测到可疑模式'}
                      />
                      <div>{getRiskIcon(item.risk_level || 'medium')}</div>
                    </List.Item>
                  )}
                />
              </Card>
            )}

            {selectedRecord.summary && (
              <Card title="分析摘要">
                <pre style={{
                  background: '#f5f5f5',
                  padding: 16,
                  borderRadius: 4,
                  overflow: 'auto',
                  maxHeight: 300
                }}>
                  {JSON.stringify(selectedRecord.summary, null, 2)}
                </pre>
              </Card>
            )}
          </div>
        )}
      </Modal>

      {/* 对比Modal */}
      <Modal
        title="分析结果对比"
        open={compareModalVisible}
        onCancel={() => setCompareModalVisible(false)}
        width={1200}
        footer={[
          <Button key="close" onClick={() => setCompareModalVisible(false)}>
            关闭
          </Button>
        ]}
      >
        <Row gutter={16}>
          {compareRecords.map((record, index) => (
            <Col span={24 / compareRecords.length} key={record.analysis_id}>
              <Card
                title={
                  <Space direction="vertical" size="small" style={{ width: '100%' }}>
                    <Text strong>记录 {index + 1}</Text>
                    {getAnalysisTypeTag(record.analysis_type)}
                  </Space>
                }
                size="small"
              >
                <Space direction="vertical" style={{ width: '100%' }} size="middle">
                  <div>
                    <Text type="secondary">分析时间：</Text>
                    <br />
                    <Text>{new Date(record.timestamp).toLocaleString('zh-CN')}</Text>
                  </div>

                  <Divider style={{ margin: '8px 0' }} />

                  <Statistic
                    title="可疑请求"
                    value={record.suspicious_count || 0}
                    valueStyle={{
                      color: record.suspicious_count > 0 ? '#ff4d4f' : '#52c41a',
                      fontSize: 24
                    }}
                  />

                  {record.risk_levels && (
                    <>
                      <Divider style={{ margin: '8px 0' }} />
                      <Space direction="vertical" size="small" style={{ width: '100%' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <Text type="secondary">高风险：</Text>
                          <Text strong style={{ color: '#ff4d4f' }}>
                            {record.risk_levels.high || 0}
                          </Text>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <Text type="secondary">中等风险：</Text>
                          <Text strong style={{ color: '#faad14' }}>
                            {record.risk_levels.medium || 0}
                          </Text>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <Text type="secondary">低风险：</Text>
                          <Text strong style={{ color: '#52c41a' }}>
                            {record.risk_levels.low || 0}
                          </Text>
                        </div>
                      </Space>
                    </>
                  )}

                  <Divider style={{ margin: '8px 0' }} />

                  <Button
                    type="link"
                    size="small"
                    onClick={() => {
                      setSelectedRecord(record)
                      setCompareModalVisible(false)
                      setDetailModalVisible(true)
                    }}
                  >
                    查看详情
                  </Button>
                </Space>
              </Card>
            </Col>
          ))}
        </Row>
      </Modal>
    </div>
  )
}

export default AnalysisHistory
