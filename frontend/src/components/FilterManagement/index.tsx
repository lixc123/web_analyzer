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
  Switch,
  message,
  Tag,
  Popconfirm,
  Typography,
  Alert
} from 'antd'
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  FilterOutlined,
  ReloadOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'

const { Option } = Select
const { Text } = Typography
const { TextArea } = Input

interface FilterRule {
  id: string
  name: string
  type: 'include' | 'exclude'
  pattern: string
  enabled: boolean
}

const FilterManagement: React.FC = () => {
  const [rules, setRules] = useState<FilterRule[]>([])
  const [loading, setLoading] = useState(false)
  const [modalVisible, setModalVisible] = useState(false)
  const [editingRule, setEditingRule] = useState<FilterRule | null>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/filters/rules')
      setRules(response.data || [])
    } catch (error: any) {
      console.error('加载过滤规则失败:', error)
      message.error(error.response?.data?.detail || '加载过滤规则失败')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = () => {
    setEditingRule(null)
    form.resetFields()
    form.setFieldsValue({
      type: 'exclude',
      enabled: true
    })
    setModalVisible(true)
  }

  const handleEdit = (record: FilterRule) => {
    setEditingRule(record)
    form.setFieldsValue(record)
    setModalVisible(true)
  }

  const handleSave = async () => {
    try {
      const values = await form.validateFields()

      if (editingRule) {
        // 更新规则
        await axios.put(`/api/v1/filters/rules/${editingRule.id}`, {
          ...values,
          id: editingRule.id
        })
        message.success('规则更新成功')
      } else {
        // 创建规则
        await axios.post('/api/v1/filters/rules', values)
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
      await axios.delete(`/api/v1/filters/rules/${ruleId}`)
      message.success('规则删除成功')
      loadRules()
    } catch (error: any) {
      console.error('删除规则失败:', error)
      message.error(error.response?.data?.detail || '删除规则失败')
    }
  }

  const handleToggleEnabled = async (record: FilterRule) => {
    try {
      await axios.put(`/api/v1/filters/rules/${record.id}`, {
        ...record,
        enabled: !record.enabled
      })
      message.success(record.enabled ? '规则已禁用' : '规则已启用')
      loadRules()
    } catch (error: any) {
      console.error('切换规则状态失败:', error)
      message.error(error.response?.data?.detail || '切换规则状态失败')
    }
  }

  const getTypeTag = (type: string) => {
    return type === 'include' ? (
      <Tag color="green">包含</Tag>
    ) : (
      <Tag color="red">排除</Tag>
    )
  }

  const columns: ColumnsType<FilterRule> = [
    {
      title: '规则名称',
      dataIndex: 'name',
      key: 'name',
      width: 200,
      render: (name: string) => <Text strong>{name}</Text>
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (type: string) => getTypeTag(type),
      filters: [
        { text: '包含', value: 'include' },
        { text: '排除', value: 'exclude' }
      ],
      onFilter: (value, record) => record.type === value
    },
    {
      title: '匹配模式',
      dataIndex: 'pattern',
      key: 'pattern',
      ellipsis: true,
      render: (pattern: string) => (
        <Text code style={{ fontSize: '12px' }}>{pattern}</Text>
      )
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 100,
      render: (enabled: boolean, record: FilterRule) => (
        <Switch
          checked={enabled}
          onChange={() => handleToggleEnabled(record)}
          checkedChildren="启用"
          unCheckedChildren="禁用"
        />
      ),
      filters: [
        { text: '已启用', value: true },
        { text: '已禁用', value: false }
      ],
      onFilter: (value, record) => record.enabled === value
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      fixed: 'right',
      render: (record: FilterRule) => (
        <Space>
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
            onConfirm={() => handleDelete(record.id)}
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
        message="过滤器管理"
        description="配置请求过滤规则，控制哪些请求应该被录制或忽略。包含规则表示只录制匹配的请求，排除规则表示不录制匹配的请求。"
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      <Card
        title={
          <Space>
            <FilterOutlined />
            <span>过滤规则</span>
            <Tag color="blue">{rules.length} 个规则</Tag>
            <Tag color="green">{rules.filter(r => r.enabled).length} 个启用</Tag>
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
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条规则`
          }}
          scroll={{ x: 1000 }}
        />
      </Card>

      {/* 创建/编辑规则Modal */}
      <Modal
        title={editingRule ? '编辑过滤规则' : '创建过滤规则'}
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
            type: 'exclude',
            enabled: true
          }}
        >
          <Form.Item
            label="规则名称"
            name="name"
            rules={[{ required: true, message: '请输入规则名称' }]}
          >
            <Input placeholder="例如：过滤静态资源" />
          </Form.Item>

          <Form.Item
            label="规则类型"
            name="type"
            rules={[{ required: true, message: '请选择规则类型' }]}
            help="包含：只录制匹配的请求；排除：不录制匹配的请求"
          >
            <Select>
              <Option value="include">
                <Space>
                  <Tag color="green">包含</Tag>
                  <span>只录制匹配的请求</span>
                </Space>
              </Option>
              <Option value="exclude">
                <Space>
                  <Tag color="red">排除</Tag>
                  <span>不录制匹配的请求</span>
                </Space>
              </Option>
            </Select>
          </Form.Item>

          <Form.Item
            label="匹配模式（正则表达式）"
            name="pattern"
            rules={[
              { required: true, message: '请输入匹配模式' },
              {
                validator: async (_, value) => {
                  if (value) {
                    try {
                      new RegExp(value)
                    } catch (e) {
                      throw new Error('无效的正则表达式')
                    }
                  }
                }
              }
            ]}
            help="使用正则表达式匹配URL，例如：.*\.(png|jpg|css|js)$ 匹配静态资源"
          >
            <TextArea
              rows={3}
              placeholder="例如：.*\.(png|jpg|gif|css|js|woff|woff2)$"
            />
          </Form.Item>

          <Form.Item
            label="启用状态"
            name="enabled"
            valuePropName="checked"
          >
            <Switch checkedChildren="启用" unCheckedChildren="禁用" />
          </Form.Item>

          <Alert
            message="常用模式示例"
            description={
              <div style={{ marginTop: 8 }}>
                <div>• 静态资源：<Text code>.*\.(png|jpg|gif|css|js|woff|woff2)$</Text></div>
                <div>• API请求：<Text code>^https?://.*\/api\/.*</Text></div>
                <div>• 特定域名：<Text code>^https?://example\.com/.*</Text></div>
                <div>• 排除分析工具：<Text code>.*google-analytics\.com.*</Text></div>
              </div>
            }
            type="info"
            showIcon
            style={{ marginTop: 16 }}
          />
        </Form>
      </Modal>
    </div>
  )
}

export default FilterManagement
