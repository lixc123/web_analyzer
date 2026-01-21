import React, { useState, useEffect } from 'react'
import {
  Card,
  Table,
  Button,
  Space,
  Tag,
  Progress,
  Typography,
  message,
  Statistic,
  Row,
  Col,
  Popconfirm,
  Alert,
  Badge,
  Tooltip
} from 'antd'
import {
  ReloadOutlined,
  CloseCircleOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  SyncOutlined,
  DeleteOutlined,
  BarChartOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import axios from 'axios'

const { Text } = Typography

interface Task {
  task_id: string
  task_type: string
  task_name: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  created_at: string
  started_at?: string
  completed_at?: string
  error?: string
  result?: any
}

interface TaskStats {
  total: number
  pending: number
  running: number
  completed: number
  failed: number
  cancelled: number
}

const TaskManagement: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([])
  const [stats, setStats] = useState<TaskStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)

  useEffect(() => {
    loadTasks()
    loadStats()

    // 自动刷新
    const interval = setInterval(() => {
      if (autoRefresh) {
        loadTasks()
        loadStats()
      }
    }, 5000)

    return () => clearInterval(interval)
  }, [autoRefresh])

  const loadTasks = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/v1/tasks/list', {
        params: { limit: 100 }
      })
      setTasks(response.data.tasks || [])
    } catch (error: any) {
      console.error('加载任务列表失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadStats = async () => {
    try {
      const response = await axios.get('/api/v1/tasks/stats')
      setStats(response.data)
    } catch (error: any) {
      console.error('加载任务统计失败:', error)
    }
  }

  const handleCancelTask = async (taskId: string) => {
    try {
      await axios.delete(`/api/v1/tasks/cancel/${taskId}`)
      message.success('任务已取消')
      loadTasks()
      loadStats()
    } catch (error: any) {
      console.error('取消任务失败:', error)
      message.error(error.response?.data?.detail || '取消任务失败')
    }
  }

  const handleCleanupOldTasks = async () => {
    try {
      const response = await axios.post('/api/v1/tasks/cleanup', null, {
        params: { max_age_hours: 24 }
      })
      message.success(response.data.message || '旧任务已清理')
      loadTasks()
      loadStats()
    } catch (error: any) {
      console.error('清理任务失败:', error)
      message.error(error.response?.data?.detail || '清理任务失败')
    }
  }

  const getStatusTag = (status: string) => {
    const statusMap: Record<string, { color: string; icon: React.ReactNode; text: string }> = {
      pending: { color: 'default', icon: <ClockCircleOutlined />, text: '等待中' },
      running: { color: 'processing', icon: <SyncOutlined spin />, text: '运行中' },
      completed: { color: 'success', icon: <CheckCircleOutlined />, text: '已完成' },
      failed: { color: 'error', icon: <CloseCircleOutlined />, text: '失败' },
      cancelled: { color: 'warning', icon: <CloseCircleOutlined />, text: '已取消' }
    }
    const config = statusMap[status] || statusMap.pending
    return (
      <Tag color={config.color} icon={config.icon}>
        {config.text}
      </Tag>
    )
  }

  const getTaskTypeTag = (type: string) => {
    const typeMap: Record<string, { color: string; text: string }> = {
      code_generation: { color: 'blue', text: '代码生成' },
      batch_analysis: { color: 'green', text: '批量分析' },
      data_export: { color: 'orange', text: '数据导出' },
      crawler: { color: 'purple', text: '爬虫任务' }
    }
    const config = typeMap[type] || { color: 'default', text: type }
    return <Tag color={config.color}>{config.text}</Tag>
  }

  const columns: ColumnsType<Task> = [
    {
      title: '任务ID',
      dataIndex: 'task_id',
      key: 'task_id',
      width: 120,
      render: (id: string) => (
        <Tooltip title={id}>
          <Text code style={{ fontSize: '11px' }}>{id.slice(-8)}</Text>
        </Tooltip>
      )
    },
    {
      title: '任务名称',
      dataIndex: 'task_name',
      key: 'task_name',
      ellipsis: true,
      render: (name: string) => <Text strong>{name}</Text>
    },
    {
      title: '类型',
      dataIndex: 'task_type',
      key: 'task_type',
      width: 120,
      render: (type: string) => getTaskTypeTag(type),
      filters: [
        { text: '代码生成', value: 'code_generation' },
        { text: '批量分析', value: 'batch_analysis' },
        { text: '数据导出', value: 'data_export' },
        { text: '爬虫任务', value: 'crawler' }
      ],
      onFilter: (value, record) => record.task_type === value
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => getStatusTag(status),
      filters: [
        { text: '等待中', value: 'pending' },
        { text: '运行中', value: 'running' },
        { text: '已完成', value: 'completed' },
        { text: '失败', value: 'failed' },
        { text: '已取消', value: 'cancelled' }
      ],
      onFilter: (value, record) => record.status === value
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      width: 150,
      render: (progress: number, record: Task) => {
        if (record.status === 'completed') {
          return <Progress percent={100} size="small" status="success" />
        } else if (record.status === 'failed' || record.status === 'cancelled') {
          return <Progress percent={progress} size="small" status="exception" />
        } else if (record.status === 'running') {
          return <Progress percent={progress} size="small" status="active" />
        } else {
          return <Progress percent={0} size="small" />
        }
      }
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (time: string) => new Date(time).toLocaleString('zh-CN'),
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
      defaultSortOrder: 'descend'
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      fixed: 'right',
      render: (record: Task) => (
        <Space>
          {(record.status === 'pending' || record.status === 'running') && (
            <Popconfirm
              title="确定要取消这个任务吗？"
              onConfirm={() => handleCancelTask(record.task_id)}
              okText="确定"
              cancelText="取消"
            >
              <Button
                type="text"
                danger
                icon={<CloseCircleOutlined />}
                size="small"
              >
                取消
              </Button>
            </Popconfirm>
          )}
          {record.error && (
            <Tooltip title={record.error}>
              <Button type="text" danger size="small">
                查看错误
              </Button>
            </Tooltip>
          )}
        </Space>
      )
    }
  ]

  return (
    <div>
      <Alert
        message="后台任务管理"
        description="监控和管理系统中的后台任务，包括代码生成、批量分析等长时间运行的任务。"
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      {stats && (
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={4}>
            <Card>
              <Statistic
                title="总任务数"
                value={stats.total}
                prefix={<BarChartOutlined />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card>
              <Statistic
                title="等待中"
                value={stats.pending}
                valueStyle={{ color: '#8c8c8c' }}
                prefix={<ClockCircleOutlined />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card>
              <Statistic
                title="运行中"
                value={stats.running}
                valueStyle={{ color: '#1890ff' }}
                prefix={<SyncOutlined spin />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card>
              <Statistic
                title="已完成"
                value={stats.completed}
                valueStyle={{ color: '#52c41a' }}
                prefix={<CheckCircleOutlined />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card>
              <Statistic
                title="失败"
                value={stats.failed}
                valueStyle={{ color: '#ff4d4f' }}
                prefix={<CloseCircleOutlined />}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card>
              <Statistic
                title="已取消"
                value={stats.cancelled}
                valueStyle={{ color: '#faad14' }}
                prefix={<CloseCircleOutlined />}
              />
            </Card>
          </Col>
        </Row>
      )}

      <Card
        title={
          <Space>
            <span>任务列表</span>
            <Badge count={tasks.filter(t => t.status === 'running').length} style={{ backgroundColor: '#1890ff' }} />
            <Tag color={autoRefresh ? 'green' : 'default'}>
              {autoRefresh ? '自动刷新' : '手动刷新'}
            </Tag>
          </Space>
        }
        extra={
          <Space>
            <Button
              type={autoRefresh ? 'default' : 'primary'}
              onClick={() => setAutoRefresh(!autoRefresh)}
              size="small"
            >
              {autoRefresh ? '停止自动刷新' : '开启自动刷新'}
            </Button>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                loadTasks()
                loadStats()
              }}
              loading={loading}
              size="small"
            >
              刷新
            </Button>
            <Popconfirm
              title="确定要清理24小时前的旧任务吗？"
              onConfirm={handleCleanupOldTasks}
              okText="确定"
              cancelText="取消"
            >
              <Button
                icon={<DeleteOutlined />}
                danger
                size="small"
              >
                清理旧任务
              </Button>
            </Popconfirm>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={tasks}
          rowKey="task_id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个任务`
          }}
          scroll={{ x: 1200 }}
        />
      </Card>
    </div>
  )
}

export default TaskManagement
