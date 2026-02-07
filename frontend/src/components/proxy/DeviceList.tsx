import React, { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import { Card, Space, Select, Table, Tag, Tooltip, Typography, Button } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined } from '@ant-design/icons'

const { Text } = Typography
const { Option } = Select

type Device = {
  device_id?: string
  user_agent_hash?: string | null
  user_agent?: string
  platform?: string
  device?: string
  os_version?: string
  browser?: string | null
  app?: string | null
  ip?: string
  client_port?: number
  first_seen?: string
  last_seen?: string
  request_count?: number
}

const ONLINE_WINDOW_MINUTES = 5

const normalizePlatform = (d: Device): string => {
  const raw = (d.platform || (d as any).type || 'unknown').toString().trim()
  return raw.toLowerCase()
}

const toTime = (s?: string): number => {
  if (!s) return 0
  const t = new Date(s).getTime()
  return Number.isFinite(t) ? t : 0
}

const isOnline = (d: Device): boolean => {
  const last = toTime(d.last_seen || d.first_seen)
  if (!last) return false
  const diffMinutes = (Date.now() - last) / 1000 / 60
  return diffMinutes < ONLINE_WINDOW_MINUTES
}

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(false)
  const [platformFilter, setPlatformFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const fetchDevices = async () => {
    setLoading(true)
    try {
      const res = await axios.get('/api/v1/proxy/devices')
      setDevices((res.data.devices || []) as Device[])
    } catch (err) {
      console.error('获取设备列表失败:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()
    const timer = setInterval(fetchDevices, 5000)
    return () => clearInterval(timer)
  }, [])

  const filteredDevices = useMemo(() => {
    let filtered = devices

    if (platformFilter !== 'all') {
      filtered = filtered.filter((d) => {
        const p = normalizePlatform(d)
        if (platformFilter === 'mobile') return p === 'ios' || p === 'android'
        if (platformFilter === 'desktop') return p === 'windows' || p === 'macos' || p === 'linux'
        return p === platformFilter
      })
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter((d) => (statusFilter === 'online' ? isOnline(d) : !isOnline(d)))
    }

    return filtered
  }, [devices, platformFilter, statusFilter])

  const columns: ColumnsType<Device> = [
    {
      title: '状态',
      key: 'status',
      width: 86,
      render: (_: any, record) => (isOnline(record) ? <Tag color="green">在线</Tag> : <Tag>离线</Tag>),
    },
    {
      title: '平台',
      dataIndex: 'platform',
      key: 'platform',
      width: 110,
      render: (v: string, record) => <Tag color="blue">{(v || normalizePlatform(record) || 'unknown').toString()}</Tag>,
    },
    {
      title: '设备',
      dataIndex: 'device',
      key: 'device',
      width: 140,
      render: (v: string) => <Text>{v || 'Unknown'}</Text>,
    },
    {
      title: '系统',
      dataIndex: 'os_version',
      key: 'os_version',
      width: 120,
      render: (v: string) => <Text type="secondary">{v || '-'}</Text>,
    },
    {
      title: 'IP',
      dataIndex: 'ip',
      key: 'ip',
      width: 150,
      render: (v: string, r) => (
        <Text code>
          {v || '-'}
          {r.client_port ? `:${r.client_port}` : ''}
        </Text>
      ),
    },
    {
      title: '请求数',
      dataIndex: 'request_count',
      key: 'request_count',
      width: 100,
      render: (v: number) => <Text>{Number(v || 0)}</Text>,
    },
    {
      title: '首次出现',
      dataIndex: 'first_seen',
      key: 'first_seen',
      width: 180,
      render: (v: string) => (v ? <Text type="secondary">{new Date(v).toLocaleString('zh-CN')}</Text> : <Text type="secondary">-</Text>),
    },
    {
      title: '最近出现',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 180,
      render: (v: string, r) => {
        const ts = v || r.first_seen
        return ts ? <Text type="secondary">{new Date(ts).toLocaleString('zh-CN')}</Text> : <Text type="secondary">-</Text>
      },
    },
    {
      title: '标识/UA',
      key: 'identity',
      ellipsis: true,
      render: (_: any, r) => {
        const id = (r.device_id || '').toString()
        const ua = (r.user_agent || '').toString()
        const show = ua || id || '-'
        return (
          <Tooltip title={<pre style={{ margin: 0, maxWidth: 680, whiteSpace: 'pre-wrap' }}>{JSON.stringify({ device_id: id, user_agent: ua }, null, 2)}</pre>}>
            <Text ellipsis style={{ maxWidth: 260 }}>{show}</Text>
          </Tooltip>
        )
      },
    },
  ]

  return (
    <Card
      title={
        <Space>
          <span>设备列表</span>
          <Text type="secondary">({filteredDevices.length}/{devices.length})</Text>
        </Space>
      }
      extra={
        <Button icon={<ReloadOutlined />} size="small" onClick={fetchDevices} loading={loading}>
          刷新
        </Button>
      }
    >
      <Space wrap style={{ marginBottom: 12 }}>
        <span>平台：</span>
        <Select value={platformFilter} onChange={setPlatformFilter} style={{ width: 160 }}>
          <Option value="all">全部</Option>
          <Option value="mobile">移动端</Option>
          <Option value="desktop">桌面端</Option>
          <Option value="ios">iOS</Option>
          <Option value="android">Android</Option>
          <Option value="windows">Windows</Option>
          <Option value="macos">macOS</Option>
          <Option value="linux">Linux</Option>
          <Option value="unknown">Unknown</Option>
        </Select>

        <span>状态：</span>
        <Select value={statusFilter} onChange={setStatusFilter} style={{ width: 120 }}>
          <Option value="all">全部</Option>
          <Option value="online">在线</Option>
          <Option value="offline">离线</Option>
        </Select>

        <Text type="secondary">在线判定：{ONLINE_WINDOW_MINUTES} 分钟内有请求</Text>
      </Space>

      <Table<Device>
        rowKey={(r) => r.device_id || `${normalizePlatform(r)}_${r.ip || ''}_${r.user_agent_hash || ''}`}
        columns={columns}
        dataSource={filteredDevices}
        size="small"
        pagination={{ pageSize: 20, showSizeChanger: true }}
      />
    </Card>
  )
}

export default DeviceList
