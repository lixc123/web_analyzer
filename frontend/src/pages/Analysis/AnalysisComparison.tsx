import React, { useState } from 'react'
import {
  Card,
  Select,
  Button,
  Space,
  Table,
  Tag,
  Typography,
  Row,
  Col,
  Statistic,
  Divider,
  Alert,
  Spin,
  Empty,
  Tooltip,
  Badge,
  Progress
} from 'antd'
import {
  CompareOutlined,
  BarChartOutlined,
  ExclamationCircleOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  InfoCircleOutlined
} from '@ant-design/icons'
import axios from 'axios'
import type { ColumnsType } from 'antd/es/table'

const { Title, Text } = Typography
const { Option } = Select

interface AnalysisRecord {
  id: string
  session_id: string
  timestamp: string
  suspicious_count: number
  high_entropy_count: number
  sensitive_params_count: number
}

interface ComparisonResult {
  analysis_ids: string[]
  comparison: {
    common_suspicious: any[]
    unique_suspicious: Record<string, any[]>
    entropy_comparison: any
    sensitive_params_comparison: any
    summary: {
      total_analyses: number
      common_issues: number
      unique_issues_per_analysis: Record<string, number>
    }
  }
}

const AnalysisComparison: React.FC = () => {
  const [sessions, setSessions] = useState<any[]>([])
  const [selectedSession, setSelectedSession] = useState<string>('')
  const [analysisHistory, setAnalysisHistory] = useState<AnalysisRecord[]>([])
  const [selectedAnalyses, setSelectedAnalyses] = useState<string[]>([])
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [comparing, setComparing] = useState(false)

  // 加载会话列表
  const loadSessions = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/crawler/sessions')
      setSessions(response.data.sessions || [])
    } catch (error) {
      console.error('加载会话列表失败:', error)
    } finally {
      setLoading(false)
    }
  }

  // 加载分析历史
  const loadAnalysisHistory = async (sessionId: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/api/v1/analysis/history/${sessionId}`)
      // 映射 analysis_id 到 id 字段
      const history = (response.data.history || []).map((item: any) => ({
        ...item,
        id: item.analysis_id || item.id
      }))
      setAnalysisHistory(history)
    } catch (error) {
      console.error('加载分析历史失败:', error)
    } finally {
      setLoading(false)
    }
  }

  // 执行比较
  const compareAnalyses = async () => {
    if (selectedAnalyses.length < 2) {
      return
    }

    setComparing(true)
    try {
      const response = await axios.post('/api/v1/analysis/compare', selectedAnalyses)
      setComparisonResult(response.data)
    } catch (error) {
      console.error('比较分析结果失败:', error)
    } finally {
      setComparing(false)
    }
  }

  React.useEffect(() => {
    loadSessions()
  }, [])

  React.useEffect(() => {
    if (selectedSession) {
      loadAnalysisHistory(selectedSession)
      setSelectedAnalyses([])
      setComparisonResult(null)
    }
  }, [selectedSession])

  const columns: ColumnsType<AnalysisRecord> = [
    {
      title: '分析ID',
      dataIndex: 'id',
      key: 'id',
      width: 200,
      render: (id: string) => (
        <Text code style={{ fontSize: '11px' }}>{id.substring(0, 16)}...</Text>
      )
    },
    {
      title: '分析时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (time: string) => (
        <Text type="secondary">{new Date(time).toLocaleString('zh-CN')}</Text>
      )
    },
    {
      title: '可疑请求',
      dataIndex: 'suspicious_count',
      key: 'suspicious_count',
      width: 100,
      render: (count: number) => (
        <Tag color={count > 0 ? 'red' : 'green'}>{count}</Tag>
      )
    },
    {
      title: '高熵字段',
      dataIndex: 'high_entropy_count',
      key: 'high_entropy_count',
      width: 100,
      render: (count: number) => (
        <Tag color={count > 0 ? 'orange' : 'default'}>{count}</Tag>
      )
    },
    {
      title: '敏感参数',
      dataIndex: 'sensitive_params_count',
      key: 'sensitive_params_count',
      width: 100,
      render: (count: number) => (
        <Tag color={count > 0 ? 'purple' : 'default'}>{count}</Tag>
      )
    }
  ]

  const rowSelection = {
    selectedRowKeys: selectedAnalyses,
    onChange: (selectedRowKeys: React.Key[]) => {
      setSelectedAnalyses(selectedRowKeys as string[])
    },
    getCheckboxProps: (record: AnalysisRecord) => ({
      disabled: selectedAnalyses.length >= 5 && !selectedAnalyses.includes(record.id)
    })
  }

  return (
    <div style={{ padding: '24px' }}>
      <Card
        title={
          <Space>
            <CompareOutlined />
            <span>分析结果比较</span>
          </Space>
        }
      >
        <Alert
          message="分析结果比较功能"
          description="选择同一会话的多个分析结果进行对比，找出共同问题和差异。最多可同时比较5个分析结果。"
          type="info"
          showIcon
          icon={<InfoCircleOutlined />}
          style={{ marginBottom: 24 }}
        />

        <Space direction="vertical" style={{ width: '100%' }} size="large">
          {/* 会话选择 */}
          <Card size="small" title="1. 选择会话">
            <Select
              style={{ width: '100%' }}
              placeholder="请选择要比较的会话"
              value={selectedSession}
              onChange={setSelectedSession}
              loading={loading}
              showSearch
              filterOption={(input, option) =>
                (option?.children as string).toLowerCase().includes(input.toLowerCase())
              }
            >
              {sessions.map((session: any) => (
                <Option key={session.name} value={session.name}>
                  {session.name} - {new Date(session.created_at).toLocaleString('zh-CN')}
                </Option>
              ))}
            </Select>
          </Card>

          {/* 分析历史选择 */}
          {selectedSession && (
            <Card
              size="small"
              title={
                <Space>
                  <span>2. 选择要比较的分析结果</span>
                  {selectedAnalyses.length > 0 && (
                    <Tag color="blue">{selectedAnalyses.length} 个已选择</Tag>
                  )}
                </Space>
              }
              extra={
                <Button
                  type="primary"
                  icon={<CompareOutlined />}
                  onClick={compareAnalyses}
                  disabled={selectedAnalyses.length < 2}
                  loading={comparing}
                >
                  开始比较 ({selectedAnalyses.length}/5)
                </Button>
              }
            >
              <Table
                rowSelection={rowSelection}
                columns={columns}
                dataSource={analysisHistory}
                rowKey="id"
                loading={loading}
                pagination={{
                  pageSize: 10,
                  showTotal: (total) => `共 ${total} 条分析记录`
                }}
                size="small"
              />
            </Card>
          )}

          {/* 比较结果 */}
          {comparisonResult && (
            <Card
              size="small"
              title={
                <Space>
                  <BarChartOutlined />
                  <span>3. 比较结果</span>
                </Space>
              }
            >
              <Spin spinning={comparing}>
                {/* 统计概览 */}
                <Row gutter={16} style={{ marginBottom: 24 }}>
                  <Col span={8}>
                    <Card>
                      <Statistic
                        title="比较的分析数量"
                        value={comparisonResult.comparison.summary.total_analyses}
                        prefix={<BarChartOutlined />}
                      />
                    </Card>
                  </Col>
                  <Col span={8}>
                    <Card>
                      <Statistic
                        title="共同问题"
                        value={comparisonResult.comparison.summary.common_issues}
                        prefix={<ExclamationCircleOutlined />}
                        valueStyle={{ color: '#cf1322' }}
                      />
                    </Card>
                  </Col>
                  <Col span={8}>
                    <Card>
                      <Statistic
                        title="独特问题总数"
                        value={Object.values(
                          comparisonResult.comparison.summary.unique_issues_per_analysis
                        ).reduce((a, b) => a + b, 0)}
                        prefix={<WarningOutlined />}
                        valueStyle={{ color: '#faad14' }}
                      />
                    </Card>
                  </Col>
                </Row>

                <Divider orientation="left">共同可疑请求</Divider>
                {comparisonResult.comparison.common_suspicious.length > 0 ? (
                  <Table
                    dataSource={comparisonResult.comparison.common_suspicious}
                    columns={[
                      {
                        title: 'URL',
                        dataIndex: 'url',
                        key: 'url',
                        ellipsis: true
                      },
                      {
                        title: '方法',
                        dataIndex: 'method',
                        key: 'method',
                        width: 80,
                        render: (method: string) => <Tag color="blue">{method}</Tag>
                      },
                      {
                        title: '风险等级',
                        dataIndex: 'risk_level',
                        key: 'risk_level',
                        width: 100,
                        render: (level: string) => {
                          const colors: Record<string, string> = {
                            high: 'red',
                            medium: 'orange',
                            low: 'yellow'
                          }
                          return <Tag color={colors[level] || 'default'}>{level}</Tag>
                        }
                      },
                      {
                        title: '出现次数',
                        dataIndex: 'occurrence_count',
                        key: 'occurrence_count',
                        width: 100,
                        render: (count: number) => (
                          <Badge count={count} showZero style={{ backgroundColor: '#52c41a' }} />
                        )
                      }
                    ]}
                    pagination={false}
                    size="small"
                  />
                ) : (
                  <Empty description="没有共同的可疑请求" />
                )}

                <Divider orientation="left">独特问题分布</Divider>
                <Row gutter={16}>
                  {Object.entries(comparisonResult.comparison.summary.unique_issues_per_analysis).map(
                    ([analysisId, count]) => (
                      <Col span={8} key={analysisId}>
                        <Card size="small">
                          <Statistic
                            title={
                              <Tooltip title={analysisId}>
                                <Text ellipsis style={{ width: 150 }}>
                                  {analysisId.substring(0, 12)}...
                                </Text>
                              </Tooltip>
                            }
                            value={count}
                            suffix="个独特问题"
                          />
                          <Progress
                            percent={
                              (count /
                                Math.max(
                                  ...Object.values(
                                    comparisonResult.comparison.summary.unique_issues_per_analysis
                                  )
                                )) *
                              100
                            }
                            size="small"
                            showInfo={false}
                          />
                        </Card>
                      </Col>
                    )
                  )}
                </Row>

                <Divider orientation="left">熵值对比</Divider>
                {comparisonResult.comparison.entropy_comparison ? (
                  <Alert
                    message="熵值分析对比"
                    description={JSON.stringify(comparisonResult.comparison.entropy_comparison, null, 2)}
                    type="info"
                  />
                ) : (
                  <Empty description="无熵值对比数据" />
                )}

                <Divider orientation="left">敏感参数对比</Divider>
                {comparisonResult.comparison.sensitive_params_comparison ? (
                  <Alert
                    message="敏感参数对比"
                    description={JSON.stringify(
                      comparisonResult.comparison.sensitive_params_comparison,
                      null,
                      2
                    )}
                    type="warning"
                  />
                ) : (
                  <Empty description="无敏感参数对比数据" />
                )}
              </Spin>
            </Card>
          )}
        </Space>
      </Card>
    </div>
  )
}

export default AnalysisComparison
