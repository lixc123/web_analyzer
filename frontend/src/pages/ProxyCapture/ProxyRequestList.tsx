import React, { useState, useEffect } from 'react'
import {
  Card,
  Table,
  Tag,
  Space,
  Button,
  Select,
  Input,
  Badge,
  Tooltip,
  Modal,
  Descriptions,
  Typography
} from 'antd'
import {
  ReloadOutlined,
  ClearOutlined,
  SearchOutlined,
  DesktopOutlined,
  MobileOutlined,
  AppleOutlined,
  AndroidOutlined,
  ChromeOutlined,
  GlobalOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { useProxyWebSocket } from '@hooks/useProxyWebSocket'
import axios from 'axios'

const { Option } = Select
const { Text } = Typography

interface ProxyRequest {
  request_id: string
  method: string
  url: string
  source: 'browser' | 'desktop' | 'ios' | 'android'
  device_id?: string
  device_model?: string
  timestamp: string
  status_code?: number
  response_time?: number
  size?: number
}

const ProxyRequestList: React.FC = () => {
  const [requests, setRequests] = useState<ProxyRequest[]>([])
  const [filteredRequests, setFilteredRequests] = useState<ProxyRequest[]>([])
  const [loading, setLoading] = useState(false)
  const [sourceFilter, setSourceFilter] = useState<string>('all')
  const [searchText, setSearchText] = useState('')
  const [selectedRequest, setSelectedRequest] = useState<ProxyRequest | null>(null)
  const [detailModalVisible, setDetailModalVisible] = useState(false)

  // 使用WebSocket实时更新
  const { recentRequests, clearRequests } = useProxyWebSocket()

  // 初始化加载请求列表
  useEffect(() => {
    loadRequests()
  }, [])

  // 监听WebSocket新请求
  useEffect(() => {
    if (recentRequests.length > 0) {
      setRequests(prev => {
        const newRequests = [...recentRequests, ...prev]
        // 去重并限制数量
        const uniqueRequests = Array.from(
          new Map(newRequests.map(r => [r.request_id, r])).values()
        ).slice(0, 500)
        return uniqueRequests
      })
    }
  }, [recentRequests])

  // 应用过滤
  useEffect(() => {
    let filtered = requests

    // 来源过滤
    if (sourceFilter !== 'all') {
      filtered = filtered.filter(r => r.source === sourceFilter)
    }

    // 搜索过滤
    if (searchText) {
      const search = searchText.toLowerCase()
      filtered = filtered.filter(r =>
        r.url.toLowerCase().includes(search) ||
        r.method.toLowerCase().includes(search) ||
        r.device_model?.toLowerCase().includes(search)
      )
    }

    setFilteredRequests(filtered)
  }, [requests, sourceFilter, searchText])

  const loadRequests = async () => {
    setLoading(true)
    try {
      // 这里假设后端有获取代理请求列表的API
      // 如果没有，可以只依赖WebSocket实时推送
      const response = await axios.get('/api/v1/proxy/requests', {
        params: { limit: 100 }
      })
      setRequests(response.data.requests || [])
    } catch (error) {
      console.error('加载请求列表失败:', error)
      // 如果API不存在，忽略错误，只使用WebSocket数据
    } finally {
      setLoading(false)
    }
  }

  const handleClearRequests = () => {
    setRequests([])
    clearRequests()
  }

  const handleViewDetail = (record: ProxyRequest) => {
    setSelectedRequest(record)
    setDetailModalVisible(true)
  }

  // 获取来源图标
  const getSourceIcon = (source: string) => {
    switch (source) {
      case 'browser':
        return <ChromeOutlined style={{ color: '#1890ff' }} />
      case 'desktop':
        return <DesktopOutlined style={{ color: '#52c41a' }} />
      case 'ios':
        return <AppleOutlined style={{ color: '#000000' }} />
      case 'android':
        return <AndroidOutlined style={{ color: '#3ddc84' }} />
      default:
        return <GlobalOutlined />
    }
  }

  // 获取来源标签
  const getSourceTag = (source: string) => {
    const config = {
      browser: { color: 'blue', text: '浏览器' },
      desktop: { color: 'green', text: '桌面应用' },
      ios: { color: 'default', text: 'iOS' },
      android: { color: 'cyan', text: 'Android' }
    }
    const { color, text } = config[source as keyof typeof config] || { color: 'default', text: source }
    return <Tag color={color}>{text}</Tag>
  }

  // 获取HTTP方法标签颜色
  const getMethodColor = (method: string) => {
    const colors: Record<string, string> = {
      GET: 'blue',
      POST: 'green',
      PUT: 'orange',
      DELETE: 'red',
      PATCH: 'purple',
      HEAD: 'cyan',
      OPTIONS: 'default'
    }
    return colors[method] || 'default'
  }

  // 获取状态码标签颜色
  const getStatusColor = (status?: number) => {
    if (!status) return 'default'
    if (status >= 200 && status < 300) return 'success'
    if (status >= 300 && status < 400) return 'processing'
    if (status >= 400 && status < 500) return 'warning'
    if (status >= 500) return 'error'
    return 'default'
  }

  // 格式化文件大小
  const formatSize = (bytes?: number) => {
    if (!bytes) return '-'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  // 格式化时间
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('zh-CN', { hour12: false })
  }

  const columns: ColumnsType<ProxyRequest> = [
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 100,
      render: (source: string, record) => (
        <Tooltip title={record.device_model || source}>
          <Space>
            {getSourceIcon(source)}
            {getSourceTag(source)}
          </Space>
        </Tooltip>
      )
    },
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => (
        <Tag color={getMethodColor(method)}>{method}</Tag>
      )
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Tooltip title={url}>
          <Text style={{ fontSize: '12px' }}>{url}</Text>
        </Tooltip>
      )
    },
    {
      title: '状态码',
      dataIndex: 'status_code',
      key: 'status_code',
      width: 80,
      render: (status?: number) => (
        status ? (
          <Badge status={getStatusColor(status)} text={status} />
        ) : (
          <Text type="secondary">-</Text>
        )
      )
    },
    {
      title: '大小',
      dataIndex: 'size',
      key: 'size',
      width: 100,
      render: (size?: number) => (
        <Text type="secondary">{formatSize(size)}</Text>
      )
    },
    {
      title: '响应时间',
      dataIndex: 'response_time',
      key: 'response_time',
      width: 100,
      render: (time?: number) => (
        time ? (
          <Text type="secondary">{time}ms</Text>
        ) : (
          <Text type="secondary">-</Text>
        )
      )
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 100,
      render: (timestamp: string) => (
        <Text type="secondary">{formatTime(timestamp)}</Text>
      )
    },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          onClick={() => handleViewDetail(record)}
        >
          详情
        </Button>
      )
    }
  ]

  return (
    <>
      <Card
        title={
          <Space>
            <span>代理请求列表</span>
            <Badge count={filteredRequests.length} showZero style={{ backgroundColor: '#52c41a' }} />
          </Space>
        }
        extra={
          <Space>
            <Select
              value={sourceFilter}
              onChange={setSourceFilter}
              style={{ width: 120 }}
              size="small"
            >
              <Option value="all">全部来源</Option>
              <Option value="browser">
                <Space><ChromeOutlined />浏览器</Space>
              </Option>
              <Option value="desktop">
                <Space><DesktopOutlined />桌面应用</Space>
              </Option>
              <Option value="ios">
                <Space><AppleOutlined />iOS</Space>
              </Option>
              <Option value="android">
                <Space><AndroidOutlined />Android</Space>
              </Option>
            </Select>
            <Input
              placeholder="搜索URL或设备"
              prefix={<SearchOutlined />}
              value={searchText}
              onChange={e => setSearchText(e.target.value)}
              style={{ width: 200 }}
              size="small"
              allowClear
            />
            <Button
              icon={<ReloadOutlined />}
              onClick={loadRequests}
              loading={loading}
              size="small"
            >
              刷新
            </Button>
            <Button
              icon={<ClearOutlined />}
              onClick={handleClearRequests}
              danger
              size="small"
            >
              清空
            </Button>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={filteredRequests}
          rowKey="request_id"
          loading={loading}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => `共 ${total} 条请求`
          }}
          size="small"
          scroll={{ x: 1200 }}
        />
      </Card>

      {/* 请求详情Modal */}
      <Modal
        title="请求详情"
        open={detailModalVisible}
        onCancel={() => setDetailModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setDetailModalVisible(false)}>
            关闭
          </Button>
        ]}
        width={800}
      >
        {selectedRequest && (
          <Descriptions bordered column={2} size="small">
            <Descriptions.Item label="请求ID" span={2}>
              {selectedRequest.request_id}
            </Descriptions.Item>
            <Descriptions.Item label="来源">
              <Space>
                {getSourceIcon(selectedRequest.source)}
                {getSourceTag(selectedRequest.source)}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="设备型号">
              {selectedRequest.device_model || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="HTTP方法">
              <Tag color={getMethodColor(selectedRequest.method)}>
                {selectedRequest.method}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="状态码">
              {selectedRequest.status_code ? (
                <Badge status={getStatusColor(selectedRequest.status_code)} text={selectedRequest.status_code} />
              ) : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="URL" span={2}>
              <Text copyable style={{ wordBreak: 'break-all' }}>
                {selectedRequest.url}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="响应大小">
              {formatSize(selectedRequest.size)}
            </Descriptions.Item>
            <Descriptions.Item label="响应时间">
              {selectedRequest.response_time ? `${selectedRequest.response_time}ms` : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="时间戳" span={2}>
              {new Date(selectedRequest.timestamp).toLocaleString('zh-CN')}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </>
  )
}

export default ProxyRequestList
