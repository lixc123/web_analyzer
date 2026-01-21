import React, { useState, useEffect } from 'react'
import {
  Card,
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  Select,
  message,
  Tag,
  Popconfirm,
  Typography,
  Alert,
  Divider
} from 'antd'
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  EyeOutlined,
  ReloadOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'

const { TextArea } = Input
const { Option } = Select
const { Text } = Typography

interface AnalysisRule {
  rule_id: string
  rule_name: string
  rule_type: string
  rule_config: {
    description?: string
    pattern?: string
    keywords?: string[]
    min_entropy?: number
    severity?: string
    [key: string]: any
  }
  created_at?: string
  updated_at?: string
}

const RuleManagement: React.FC = () => {
  const [rules, setRules] = useState<AnalysisRule[]>([])
  const [loading, setLoading] = useState(false)
  const [modalVisible, setModalVisible] = useState(false)
  const [viewModalVisible, setViewModalVisible] = useState(false)
  const [editingRule, setEditingRule] = useState<AnalysisRule | null>(null)
  const [viewingRule, setViewingRule] = useState<AnalysisRule | null>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/analysis/rules')
      setRules(response.data.rules || [])
    } catch (error: any) {
      console.error('加载规则列表失败:', error)
      message.error(error.response?.data?.detail || '加载规则列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = () => {
    setEditingRule(null)
    form.resetFields()
    setModalVisible(true)
  }

  const handleEdit = (record: AnalysisRule) => {
    setEditingRule(record)
    form.setFieldsValue({
      rule_name: record.rule_name,
      rule_type: record.rule_type,
      description: record.rule_config.description || '',
      pattern: record.rule_config.pattern || '',
      keywords: record.rule_config.keywords?.join(', ') || '',
      min_entropy: record.rule_config.min_entropy || 4.0,
      severity: record.rule_config.severity || 'medium'
    })
    setModalVisible(true)
  }

  const handleView = (record: AnalysisRule) => {
    setViewingRule(record)
    setViewModalVisible(true)
  }

  const handleSave = async () => {
    try {
      const values = await form.validateFields()

      const ruleConfig: any = {
        description: values.description,
        severity: values.severity
      }

      // 根据规则类型添加不同的配置
      if (values.rule_type === 'pattern') {
        ruleConfig.pattern = values.pattern
      } else if (values.rule_type === 'keyword') {
        ruleConfig.keywords = values.keywords.split(',').map((k: string) => k.trim()).filter(Boolean)
      } else if (values.rule_type === 'entropy') {
        ruleConfig.min_entropy = values.min_entropy
      }

      if (editingRule) {
        // 更新规则
        await axios.put(`/api/v1/analysis/rules/${editingRule.rule_id}`, {
          rule_name: values.rule_name,
          rule_config: ruleConfig
        })
        message.success('规则更新成功')
      } else {
        // 创建规则
        await axios.post('/api/v1/analysis/custom-rules', {
          rule_name: values.rule_name,
          rule_config: {
            type: values.rule_type,
            ...ruleConfig
          }
        })
        message.success('规则创建成功')
      }

      setModalVisible(false)
      loadRules()
    } catch (error: any) {
      console.error('保存规则失败:', error)
      message.error(error.response?.data?.detail || '保存规则失败')
    }
  }

  const handleDelete = async (ruleId: string) => {
    try {
      await axios.delete(`/api/v1/analysis/rules/${ruleId}`)
      message.success('规则删除成功')
      loadRules()
    } catch (error: any) {
      console.error('删除规则失败:', error)
      message.error(error.response?.data?.detail || '删除规则失败')
    }
  }

  const getRuleTypeTag = (type: string) => {
    const typeMap: Record<string, { color: string; text: string }> = {
      pattern: { color: 'blue', text: '模式匹配' },
      keyword: { color: 'green', text: '关键词' },
      entropy: { color: 'orange', text: '熵值检测' },
      custom: { color: 'purple', text: '自定义' }
    }
    const config = typeMap[type] || { color: 'default', text: type }
    return <Tag color={config.color}>{config.text}</Tag>
  }

  const getSeverityTag = (severity: string) => {
    const severityMap: Record<string, { color: string; text: string }> = {
      high: { color: 'red', text: '高' },
      medium: { color: 'orange', text: '中' },
      low: { color: 'blue', text: '低' }
    }
    const config = severityMap[severity] || { color: 'default', text: severity }
    return <Tag color={config.color}>{config.text}</Tag>
  }

  const columns: ColumnsType<AnalysisRule> = [
    {
      title: '规则名称',
      dataIndex: 'rule_name',
      key: 'rule_name',
      width: 200,
      render: (name: string) => <Text strong>{name}</Text>
    },
    {
      title: '规则类型',
      dataIndex: 'rule_type',
      key: 'rule_type',
      width: 120,
      render: (type: string) => getRuleTypeTag(type)
    },
    {
      title: '严重程度',
      key: 'severity',
      width: 100,
      render: (record: AnalysisRule) => getSeverityTag(record.rule_config.severity || 'medium')
    },
    {
      title: '描述',
      key: 'description',
      ellipsis: true,
      render: (record: AnalysisRule) => (
        <Text type="secondary">{record.rule_config.description || '-'}</Text>
      )
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
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (record: AnalysisRule) => (
        <Space>
          <Button
            type="text"
            icon={<EyeOutlined />}
            onClick={() => handleView(record)}
            size="small"
          >
            查看
          </Button>
          <Button
            type="text"
            icon={<EditOutlined />}
            onClick={() => handleEdit(record)}
            size="small"
          >
            编辑
          </Button>
          <Popconfirm
            title="确定要删除这个规则吗？"
            onConfirm={() => handleDelete(record.rule_id)}
            okText="确定"
            cancelText="取消"
          >
            <Button
              type="text"
              danger
              icon={<DeleteOutlined />}
              size="small"
            >
              删除
            </Button>
          </Popconfirm>
        </Space>
      )
    }
  ]

  return (
    <div>
      <Alert
        message="分析规则管理"
        description="创建和管理自定义分析规则，用于检测特定的安全模式、敏感参数或加密特征。"
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      <Card
        title={
          <Space>
            <span>规则列表</span>
            <Tag color="blue">{rules.length} 个规则</Tag>
          </Space>
        }
        extra={
          <Space>
            <Button
              icon={<ReloadOutlined />}
              onClick={loadRules}
              loading={loading}
            >
              刷新
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleCreate}
            >
              创建规则
            </Button>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={rules}
          rowKey="rule_id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条规则`
          }}
          scroll={{ x: 1200 }}
        />
      </Card>

      {/* 创建/编辑规则Modal */}
      <Modal
        title={editingRule ? '编辑规则' : '创建规则'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        onOk={handleSave}
        width={600}
        okText="保存"
        cancelText="取消"
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            rule_type: 'pattern',
            severity: 'medium',
            min_entropy: 4.0
          }}
        >
          <Form.Item
            label="规则名称"
            name="rule_name"
            rules={[{ required: true, message: '请输入规则名称' }]}
          >
            <Input placeholder="例如：检测加密Token" />
          </Form.Item>

          <Form.Item
            label="规则类型"
            name="rule_type"
            rules={[{ required: true, message: '请选择规则类型' }]}
          >
            <Select disabled={!!editingRule}>
              <Option value="pattern">模式匹配</Option>
              <Option value="keyword">关键词检测</Option>
              <Option value="entropy">熵值检测</Option>
              <Option value="custom">自定义</Option>
            </Select>
          </Form.Item>

          <Form.Item
            label="严重程度"
            name="severity"
            rules={[{ required: true, message: '请选择严重程度' }]}
          >
            <Select>
              <Option value="high">高</Option>
              <Option value="medium">中</Option>
              <Option value="low">低</Option>
            </Select>
          </Form.Item>

          <Form.Item
            label="描述"
            name="description"
          >
            <TextArea
              rows={3}
              placeholder="描述这个规则的用途和检测目标"
            />
          </Form.Item>

          <Divider />

          <Form.Item noStyle shouldUpdate={(prevValues, currentValues) => prevValues.rule_type !== currentValues.rule_type}>
            {({ getFieldValue }) => {
              const ruleType = getFieldValue('rule_type')

              if (ruleType === 'pattern') {
                return (
                  <Form.Item
                    label="匹配模式（正则表达式）"
                    name="pattern"
                    rules={[{ required: true, message: '请输入匹配模式' }]}
                  >
                    <Input placeholder="例如：^[A-Za-z0-9]{32}$" />
                  </Form.Item>
                )
              }

              if (ruleType === 'keyword') {
                return (
                  <Form.Item
                    label="关键词列表"
                    name="keywords"
                    rules={[{ required: true, message: '请输入关键词' }]}
                    help="用逗号分隔多个关键词"
                  >
                    <TextArea
                      rows={3}
                      placeholder="例如：token, secret, password, apikey"
                    />
                  </Form.Item>
                )
              }

              if (ruleType === 'entropy') {
                return (
                  <Form.Item
                    label="最小熵值阈值"
                    name="min_entropy"
                    rules={[{ required: true, message: '请输入最小熵值' }]}
                  >
                    <Input type="number" min={1} max={8} step={0.1} placeholder="4.0" />
                  </Form.Item>
                )
              }

              return null
            }}
          </Form.Item>
        </Form>
      </Modal>

      {/* 查看规则详情Modal */}
      <Modal
        title="规则详情"
        open={viewModalVisible}
        onCancel={() => setViewModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setViewModalVisible(false)}>
            关闭
          </Button>
        ]}
        width={600}
      >
        {viewingRule && (
          <div>
            <Space direction="vertical" style={{ width: '100%' }} size="large">
              <div>
                <Text type="secondary">规则名称：</Text>
                <Text strong style={{ marginLeft: 8 }}>{viewingRule.rule_name}</Text>
              </div>
              <div>
                <Text type="secondary">规则类型：</Text>
                <span style={{ marginLeft: 8 }}>{getRuleTypeTag(viewingRule.rule_type)}</span>
              </div>
              <div>
                <Text type="secondary">严重程度：</Text>
                <span style={{ marginLeft: 8 }}>{getSeverityTag(viewingRule.rule_config.severity || 'medium')}</span>
              </div>
              {viewingRule.rule_config.description && (
                <div>
                  <Text type="secondary">描述：</Text>
                  <div style={{ marginTop: 8, padding: 12, background: '#f5f5f5', borderRadius: 4 }}>
                    {viewingRule.rule_config.description}
                  </div>
                </div>
              )}
              <div>
                <Text type="secondary">规则配置：</Text>
                <pre style={{
                  marginTop: 8,
                  padding: 12,
                  background: '#f5f5f5',
                  borderRadius: 4,
                  overflow: 'auto',
                  maxHeight: 300
                }}>
                  {JSON.stringify(viewingRule.rule_config, null, 2)}
                </pre>
              </div>
              {viewingRule.created_at && (
                <div>
                  <Text type="secondary">创建时间：</Text>
                  <Text style={{ marginLeft: 8 }}>{new Date(viewingRule.created_at).toLocaleString('zh-CN')}</Text>
                </div>
              )}
            </Space>
          </div>
        )}
      </Modal>
    </div>
  )
}

export default RuleManagement
