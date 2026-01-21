import React, { useState } from 'react'
import {
  Card,
  Select,
  Button,
  Space,
  Table,
  Tag,
  Progress,
  Typography,
  Form,
  InputNumber,
  Input,
  Drawer,
  Descriptions,
  Alert,
  Statistic,
  Row,
  Col,
  Tabs,
  List,
  notification
} from 'antd'
import {
  BarChartOutlined,
  EyeOutlined,
  DownloadOutlined,
  ExclamationCircleOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  ReloadOutlined
} from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { analysisApi, crawlerApi, AnalysisConfig } from '@services/api'
import AdvancedAnalysis from './AdvancedAnalysis'
import RuleManagement from './RuleManagement'
import AnalysisHistory from './AnalysisHistory'
import AnalysisComparison from './AnalysisComparison'

const { Title, Text } = Typography
const { Option } = Select
const { TextArea } = Input

const AnalysisPage: React.FC = () => {
  const [form] = Form.useForm()
  const [selectedSession, setSelectedSession] = useState<string | null>(null)
  const [analysisType, setAnalysisType] = useState<string>('all')
  const [resultDrawerVisible, setResultDrawerVisible] = useState(false)
  const [selectedResult, setSelectedResult] = useState<any>(null)
  const queryClient = useQueryClient()

  // 获取会话列表
  const { data: sessions, isLoading: sessionsLoading } = useQuery({
    queryKey: ['crawler-sessions'],
    queryFn: crawlerApi.getSessions,
  })

  // 获取分析历史
  const { data: analysisHistory, isLoading: historyLoading } = useQuery({
    queryKey: ['analysis-history', selectedSession],
    queryFn: () => selectedSession ? analysisApi.getAnalysisHistory(selectedSession) : Promise.resolve([]),
    enabled: !!selectedSession,
  })

  // 获取分析摘要
  const { data: analysisSummary } = useQuery({
    queryKey: ['analysis-summary', selectedSession],
    queryFn: () => selectedSession ? analysisApi.getAnalysisSummary(selectedSession) : Promise.resolve(null),
    enabled: !!selectedSession,
  })

  // 执行分析
  const analysisMutation = useMutation({
    mutationFn: (config: AnalysisConfig & { sessionId?: string }) =>
      analysisApi.analyze(config.sessionId, undefined, config),
    onSuccess: (data) => {
      notification.success({
        title: '分析完成',
        description: `发现 ${data.suspicious_requests?.length || 0} 个可疑请求`
      })
      setSelectedResult(data)
      setResultDrawerVisible(true)
      queryClient.invalidateQueries({ queryKey: ['analysis-history'] })
      queryClient.invalidateQueries({ queryKey: ['analysis-summary'] })
    },
    onError: (error: Error) => {
      notification.error({
        title: '分析失败',
        description: error.message
      })
    }
  })

  // 单独分析类型
  const entropyMutation = useMutation({
    mutationFn: ({ sessionId, minEntropy }: { sessionId: string; minEntropy: number }) =>
      analysisApi.analyzeEntropy(sessionId, minEntropy),
    onSuccess: (data) => {
      notification.success({
        title: '熵值分析完成',
        description: `发现 ${data.high_entropy_fields?.length || 0} 个高熵字段`
      })
    }
  })

  const sensitiveParamsMutation = useMutation({
    mutationFn: ({ sessionId, keywords }: { sessionId: string; keywords?: string }) =>
      analysisApi.analyzeSensitiveParams(sessionId, keywords),
    onSuccess: (data) => {
      notification.success({
        title: '敏感参数分析完成',
        description: `发现 ${data.results?.length || 0} 个敏感参数`
      })
    }
  })

  const handleAnalysis = async () => {
    if (!selectedSession) {
      notification.warning({ title: '请先选择会话' })
      return
    }

    try {
      const values = await form.validateFields()
      const config: AnalysisConfig = {
        analysis_type: analysisType as any,
        min_entropy: values.min_entropy || 4.0,
        sensitive_keywords: values.sensitive_keywords ? values.sensitive_keywords.split(',').map((k: string) => k.trim()) : [],
        custom_rules: {}
      }

      analysisMutation.mutate({ ...config, sessionId: selectedSession })
    } catch (error) {
      console.error('表单验证失败:', error)
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

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'high': return <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
      case 'medium': return <WarningOutlined style={{ color: '#faad14' }} />
      case 'low': return <CheckCircleOutlined style={{ color: '#52c41a' }} />
      default: return null
    }
  }

  // 分析历史表格列
  const historyColumns = [
    {
      title: '分析类型',
      dataIndex: 'analysis_type',
      key: 'analysis_type',
      render: (type: string) => (
        <Tag color="blue">
          {type === 'all' ? '综合分析' : 
           type === 'entropy' ? '熵值分析' :
           type === 'sensitive_params' ? '敏感参数' :
           type === 'encryption_keywords' ? '加密关键词' : type}
        </Tag>
      )
    },
    {
      title: '可疑请求数',
      dataIndex: 'suspicious_count',
      key: 'suspicious_count',
      render: (count: number) => (
        <span style={{ color: count > 0 ? '#ff4d4f' : '#52c41a' }}>
          {count || 0}
        </span>
      )
    },
    {
      title: '分析时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (time: string) => new Date(time).toLocaleString()
    },
    {
      title: '操作',
      key: 'actions',
      render: (record: any) => (
        <Space>
          <Button
            type="text"
            icon={<EyeOutlined />}
            onClick={() => {
              setSelectedResult(record)
              setResultDrawerVisible(true)
            }}
          />
          <Button
            type="text"
            icon={<DownloadOutlined />}
            onClick={() => {
              // 导出分析结果
              const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = `analysis_${record.analysis_id}.json`
              a.click()
              URL.revokeObjectURL(url)
            }}
          />
        </Space>
      )
    }
  ]

  const tabItems = [
    {
      key: 'overview',
      label: '分析概览',
      children: (
        <div>
          {analysisSummary && (
            <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="总分析次数"
                    value={analysisSummary.total_analyses || 0}
                    prefix={<BarChartOutlined />}
                  />
                </Card>
              </Col>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="可疑请求"
                    value={analysisSummary.total_suspicious_requests || 0}
                    prefix={<ExclamationCircleOutlined />}
                    valueStyle={{ color: '#ff4d4f' }}
                  />
                </Card>
              </Col>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="高风险"
                    value={analysisSummary.risk_levels?.high || 0}
                    prefix={getRiskIcon('high')}
                    valueStyle={{ color: '#ff4d4f' }}
                  />
                </Card>
              </Col>
              <Col span={6}>
                <Card>
                  <Statistic
                    title="中等风险"
                    value={analysisSummary.risk_levels?.medium || 0}
                    prefix={getRiskIcon('medium')}
                    valueStyle={{ color: '#faad14' }}
                  />
                </Card>
              </Col>
            </Row>
          )}

          <Table
            columns={historyColumns}
            dataSource={analysisHistory}
            rowKey="analysis_id"
            loading={historyLoading}
            pagination={{ pageSize: 10 }}
          />
        </div>
      )
    },
    {
      key: 'entropy',
      label: '熵值分析',
      children: (
        <Card>
          <Form layout="inline" style={{ marginBottom: 16 }}>
            <Form.Item label="最小熵值">
              <InputNumber
                min={1}
                max={8}
                step={0.1}
                defaultValue={4.0}
                onChange={(value) => form.setFieldValue('min_entropy', value)}
              />
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                onClick={() => selectedSession && entropyMutation.mutate({ 
                  sessionId: selectedSession, 
                  minEntropy: form.getFieldValue('min_entropy') || 4.0 
                })}
                loading={entropyMutation.isPending}
                disabled={!selectedSession}
              >
                开始熵值分析
              </Button>
            </Form.Item>
          </Form>

          <Alert
            title="熵值分析说明"
            description="熵值分析用于检测高随机性的字段，如加密数据、Token、会话ID等。熵值越高，数据越随机。"
            type="info"
            showIcon
          />
        </Card>
      )
    },
    {
      key: 'sensitive',
      label: '敏感参数',
      children: (
        <Card>
          <Form layout="vertical" style={{ marginBottom: 16 }}>
            <Form.Item
              label="自定义关键词"
              name="custom_keywords"
              help="用逗号分隔多个关键词，如：password,token,key"
            >
              <TextArea
                rows={3}
                placeholder="password,token,key,secret,auth"
              />
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                onClick={() => selectedSession && sensitiveParamsMutation.mutate({
                  sessionId: selectedSession,
                  keywords: form.getFieldValue('custom_keywords')
                })}
                loading={sensitiveParamsMutation.isPending}
                disabled={!selectedSession}
              >
                开始敏感参数分析
              </Button>
            </Form.Item>
          </Form>

          <Alert
            title="敏感参数分析说明"
            description="检测请求参数中可能包含敏感信息的字段，如密码、令牌、密钥等。"
            type="info"
            showIcon
          />
        </Card>
      )
    },
    {
      key: 'advanced',
      label: '高级分析',
      children: <AdvancedAnalysis sessionId={selectedSession || undefined} />
    },
    {
      key: 'rules',
      label: '规则管理',
      children: <RuleManagement />
    },
    {
      key: 'history',
      label: '历史记录',
      children: <AnalysisHistory />
    },
    {
      key: 'comparison',
      label: '结果比较',
      children: <AnalysisComparison />
    }
  ]

  return (
    <div className="page-container">
      {/* 页面头部 */}
      <div className="page-header">
        <div>
          <Title level={2} className="page-title">数据分析</Title>
          <Text className="page-description">智能分析网络流量数据，发现潜在的安全风险</Text>
        </div>
        <Button icon={<ReloadOutlined />} onClick={() => queryClient.invalidateQueries()}>
          刷新数据
        </Button>
      </div>

      {/* 分析配置 */}
      <Card title="分析配置" className="mb-24">
        <Form
          form={form}
          layout="inline"
          initialValues={{
            min_entropy: 4.0,
            sensitive_keywords: 'password,token,key,secret,auth'
          }}
        >
          <Form.Item label="选择会话" style={{ minWidth: 200 }}>
            <Select
              placeholder="请选择要分析的会话"
              value={selectedSession}
              onChange={setSelectedSession}
              loading={sessionsLoading}
            >
              {sessions?.map((session: any) => (
                <Option key={session.session_id} value={session.session_id}>
                  {session.session_name || `会话-${session.session_id.slice(-8)}`}
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item label="分析类型" style={{ minWidth: 150 }}>
            <Select value={analysisType} onChange={setAnalysisType}>
              <Option value="all">综合分析</Option>
              <Option value="entropy">熵值分析</Option>
              <Option value="sensitive_params">敏感参数</Option>
              <Option value="encryption_keywords">加密关键词</Option>
            </Select>
          </Form.Item>

          {analysisType === 'entropy' && (
            <Form.Item label="最小熵值" name="min_entropy">
              <InputNumber min={1} max={8} step={0.1} />
            </Form.Item>
          )}

          {analysisType === 'sensitive_params' && (
            <Form.Item label="关键词" name="sensitive_keywords" style={{ minWidth: 200 }}>
              <Input placeholder="password,token,key" />
            </Form.Item>
          )}

          <Form.Item>
            <Button
              type="primary"
              icon={<BarChartOutlined />}
              onClick={handleAnalysis}
              loading={analysisMutation.isPending}
              disabled={!selectedSession}
            >
              开始分析
            </Button>
          </Form.Item>
        </Form>
      </Card>

      {/* 分析结果 */}
      {selectedSession ? (
        <Card title="分析结果">
          <Tabs items={tabItems} />
        </Card>
      ) : (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <BarChartOutlined style={{ fontSize: 64, color: '#d9d9d9', marginBottom: 16 }} />
            <Title level={4} type="secondary">请选择会话开始分析</Title>
            <Text type="secondary">选择一个爬虫会话，然后配置分析参数进行数据分析</Text>
          </div>
        </Card>
      )}

      {/* 分析结果详情抽屉 */}
      <Drawer
        title="分析结果详情"
        placement="right"
        size="large"
        onClose={() => setResultDrawerVisible(false)}
        open={resultDrawerVisible}
      >
        {selectedResult && (
          <div>
            <Descriptions title="基本信息" bordered style={{ marginBottom: 24 }}>
              <Descriptions.Item label="分析ID">{selectedResult.analysis_id}</Descriptions.Item>
              <Descriptions.Item label="分析类型">
                <Tag color="blue">{selectedResult.analysis_type}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="分析时间">
                {new Date(selectedResult.timestamp).toLocaleString()}
              </Descriptions.Item>
              <Descriptions.Item label="可疑请求数" span={3}>
                <Text style={{ color: '#ff4d4f', fontWeight: 'bold', fontSize: 16 }}>
                  {selectedResult.suspicious_requests?.length || 0}
                </Text>
              </Descriptions.Item>
            </Descriptions>

            {selectedResult.suspicious_requests?.length > 0 && (
              <Card title="可疑请求" style={{ marginBottom: 24 }}>
                <List
                  dataSource={selectedResult.suspicious_requests}
                  renderItem={(item: any, index: number) => (
                    <List.Item>
                      <List.Item.Meta
                        title={
                          <Space>
                            <Tag color={getRiskColor(item.risk_level || 'medium')}>
                              {item.method || 'GET'}
                            </Tag>
                            <Text ellipsis style={{ maxWidth: 400 }}>
                              {item.url}
                            </Text>
                          </Space>
                        }
                        description={item.reason || '检测到可疑模式'}
                      />
                      <div>
                        {getRiskIcon(item.risk_level || 'medium')}
                      </div>
                    </List.Item>
                  )}
                />
              </Card>
            )}

            <Card title="分析摘要">
              <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 4, overflow: 'auto' }}>
                {JSON.stringify(selectedResult.summary, null, 2)}
              </pre>
            </Card>
          </div>
        )}
      </Drawer>
    </div>
  )
}

export default AnalysisPage
