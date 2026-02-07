import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, Table, Tag, Space, Button, Drawer, Typography, Tooltip, message, Alert, Select, InputNumber, Modal } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, ClearOutlined, EyeOutlined, DownloadOutlined } from '@ant-design/icons'
import axios from 'axios'
import { useProxyWebSocket, ProxyWebSocketEvent } from '@hooks/useProxyWebSocket'

const { Text } = Typography

interface WsConnection {
  id: string
  url: string
  started_at?: number | string
  ended_at?: number | string
  status?: string
  message_count?: number
  last_seen?: number | string
}

interface WsMessage {
  id: string
  connection_id: string
  url?: string
  timestamp?: number | string
  direction?: 'send' | 'receive'
  is_text?: boolean
  size?: number
  data?: string
  data_artifact?: any
}

const formatTs = (ts?: number | string) => {
  if (!ts) return '-'
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  return d.toLocaleString('zh-CN')
}

const ProxyWebSocket: React.FC = () => {
  const [connections, setConnections] = useState<WsConnection[]>([])
  const [loading, setLoading] = useState(false)
  const [connTotal, setConnTotal] = useState(0)
  const [connPage, setConnPage] = useState(1)
  const [connPageSize, setConnPageSize] = useState(50)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [selectedConnection, setSelectedConnection] = useState<WsConnection | null>(null)
  const [messagesList, setMessagesList] = useState<WsMessage[]>([])
  const [messagesLoading, setMessagesLoading] = useState(false)
  const [msgTotal, setMsgTotal] = useState(0)
  const [msgPage, setMsgPage] = useState(1)
  const [msgPageSize, setMsgPageSize] = useState(200)
  const [dirFilter, setDirFilter] = useState<'all' | 'send' | 'receive'>('all')
  const [minSize, setMinSize] = useState<number>(0)
  const [linkedRequestVisible, setLinkedRequestVisible] = useState(false)
  const [linkedRequest, setLinkedRequest] = useState<any>(null)

  const { websocketEvents } = useProxyWebSocket()

  const loadConnections = useCallback(async () => {
    setLoading(true)
    try {
      const res = await axios.get('/api/v1/proxy/websockets', {
        params: { limit: connPageSize, offset: (connPage - 1) * connPageSize },
      })
      setConnections(res.data.connections || [])
      setConnTotal(Number(res.data.total || 0))
    } catch (e) {
      console.error('加载 WebSocket 连接失败:', e)
    } finally {
      setLoading(false)
    }
  }, [connPage, connPageSize])

  const loadMessages = useCallback(async (connectionId: string) => {
    setMessagesLoading(true)
    try {
      const res = await axios.get(`/api/v1/proxy/websockets/${connectionId}/messages`, {
        params: {
          limit: msgPageSize,
          offset: (msgPage - 1) * msgPageSize,
          direction: dirFilter !== 'all' ? dirFilter : undefined,
          min_size: minSize > 0 ? minSize : undefined,
        },
      })
      setMessagesList(res.data.messages || [])
      setMsgTotal(Number(res.data.total || 0))
    } catch (e) {
      console.error('加载 WebSocket 消息失败:', e)
    } finally {
      setMessagesLoading(false)
    }
  }, [msgPage, msgPageSize, dirFilter, minSize])

  useEffect(() => {
    loadConnections()
  }, [loadConnections])

  // 来自“请求详情/联动”的自动定位
  useEffect(() => {
    const targetId = sessionStorage.getItem('proxy_capture_ws_connection_id')
    if (!targetId) return
    const found = connections.find((c) => c.id === targetId)
    if (!found) return
    setMsgPage(1)
    setSelectedConnection(found)
    setDrawerOpen(true)
    sessionStorage.removeItem('proxy_capture_ws_connection_id')
  }, [connections])

  useEffect(() => {
    if (selectedConnection?.id) {
      loadMessages(selectedConnection.id)
    }
  }, [selectedConnection?.id, loadMessages])

  // 实时事件增量更新（只做轻量合并；完整列表仍以 REST 为准）
  useEffect(() => {
    if (!websocketEvents.length) return
    const evt = websocketEvents[0] as ProxyWebSocketEvent
    if (!evt?.connection_id) return

    setConnections((prev) => {
      const map = new Map(prev.map((c) => [c.id, c]))
      const existing = map.get(evt.connection_id)
      const next: WsConnection = {
        id: evt.connection_id,
        url: evt.url || existing?.url || '',
        status: evt.event === 'ws_end' ? 'closed' : existing?.status || 'open',
        last_seen: evt.timestamp || existing?.last_seen,
        message_count: existing?.message_count || 0,
      }
      if (evt.direction) next.message_count = (next.message_count || 0) + 1
      map.set(evt.connection_id, { ...existing, ...next })
      return Array.from(map.values()).sort((a, b) => {
        const ta = typeof a.last_seen === 'number' ? a.last_seen : 0
        const tb = typeof b.last_seen === 'number' ? b.last_seen : 0
        return tb - ta
      })
    })

    if (selectedConnection?.id && selectedConnection.id === evt.connection_id && evt.direction) {
      // 当前仅在第一页做轻量增量；完整列表以 REST 为准
      if (msgPage !== 1) return
      const msg: WsMessage = {
        id: evt.id,
        connection_id: evt.connection_id,
        url: evt.url,
        timestamp: evt.timestamp,
        direction: evt.direction,
        is_text: evt.is_text,
        size: evt.size,
        data: evt.data,
        data_artifact: evt.data_artifact,
      }
      setMessagesList((prev) => [msg, ...prev].slice(0, msgPageSize))
    }
  }, [websocketEvents, selectedConnection?.id, msgPage, msgPageSize])

  const downloadArtifact = (artifactId: string) => {
    if (!artifactId) return
    window.open(`/api/v1/proxy/artifacts/${encodeURIComponent(artifactId)}`, '_blank')
  }

  const exportWs = async (format: 'json' | 'csv', connectionId?: string) => {
    try {
      const res = await axios.get('/api/v1/proxy/websockets/export', {
        params: { format, connection_id: connectionId, limit: 5000 },
        responseType: 'blob',
      })
      const blob = new Blob([res.data])
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '-')
      link.download = connectionId ? `websocket_${connectionId}_${ts}.${format}` : `websockets_${ts}.${format}`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      message.success('已开始下载')
    } catch (e) {
      console.error('导出失败:', e)
      message.error('导出失败')
    }
  }

  const bundleArtifacts = async () => {
    const ids = Array.from(
      new Set((messagesList || []).map((m) => m.data_artifact?.artifact_id).filter((id): id is string => !!id))
    )
    if (!ids.length) {
      message.info('当前连接没有落盘 artifact')
      return
    }
    try {
      const res = await axios.post('/api/v1/proxy/artifacts/bundle', { artifact_ids: ids }, { responseType: 'blob' })
      const blob = new Blob([res.data], { type: 'application/zip' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '-')
      link.download = `ws_artifacts_${selectedConnection?.id || 'bundle'}_${ts}.zip`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      message.success('已开始下载')
    } catch (e) {
      console.error('打包下载失败:', e)
      message.error('打包下载失败')
    }
  }

  const viewHandshakeRequest = async () => {
    if (!selectedConnection?.id) return
    try {
      const res = await axios.get(`/api/v1/proxy/request/${selectedConnection.id}`)
      setLinkedRequest(res.data)
      setLinkedRequestVisible(true)
    } catch (e) {
      console.error('加载握手请求失败:', e)
      message.error('加载握手请求失败（可能已被清理或不在会话中）')
    }
  }

  const clearWebSockets = async () => {
    try {
      await axios.delete('/api/v1/proxy/websockets')
      setConnections([])
      setMessagesList([])
      setDrawerOpen(false)
      setSelectedConnection(null)
      message.success('WebSocket 数据已清空')
    } catch (e) {
      console.error('清空 WebSocket 数据失败:', e)
      message.error('清空失败')
    }
  }

  const connectionColumns: ColumnsType<WsConnection> = useMemo(
    () => [
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        width: 80,
        render: (status?: string) => (status === 'closed' ? <Tag>closed</Tag> : <Tag color="green">open</Tag>),
      },
      {
        title: 'URL',
        dataIndex: 'url',
        key: 'url',
        ellipsis: true,
        render: (url: string) => (
          <Tooltip title={url}>
            <Text style={{ fontSize: 12 }}>{url}</Text>
          </Tooltip>
        ),
      },
      {
        title: '消息数',
        dataIndex: 'message_count',
        key: 'message_count',
        width: 100,
        render: (v?: number) => <Text type="secondary">{v ?? 0}</Text>,
      },
      {
        title: '最近活动',
        dataIndex: 'last_seen',
        key: 'last_seen',
        width: 180,
        render: (ts?: number | string) => <Text type="secondary">{formatTs(ts)}</Text>,
      },
      {
        title: '操作',
        key: 'action',
        width: 90,
        render: (_, record) => (
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => {
              setMsgPage(1)
              setSelectedConnection(record)
              setDrawerOpen(true)
            }}
          >
            查看
          </Button>
        ),
      },
    ],
    []
  )

  const messageColumns: ColumnsType<WsMessage> = useMemo(
    () => [
      {
        title: '方向',
        dataIndex: 'direction',
        key: 'direction',
        width: 80,
        render: (dir?: string) => (dir === 'send' ? <Tag color="blue">send</Tag> : <Tag color="purple">recv</Tag>),
      },
      {
        title: '时间',
        dataIndex: 'timestamp',
        key: 'timestamp',
        width: 180,
        render: (ts?: number | string) => <Text type="secondary">{formatTs(ts)}</Text>,
      },
      {
        title: '大小',
        dataIndex: 'size',
        key: 'size',
        width: 100,
        render: (s?: number) => <Text type="secondary">{s ?? 0} B</Text>,
      },
      {
        title: '数据预览',
        dataIndex: 'data',
        key: 'data',
        ellipsis: true,
        render: (data?: string) => <Text style={{ fontSize: 12 }}>{data || '-'}</Text>,
      },
      {
        title: '下载',
        key: 'download',
        width: 90,
        render: (_, r) =>
          r.data_artifact?.artifact_id ? (
            <Button size="small" icon={<DownloadOutlined />} onClick={() => downloadArtifact(r.data_artifact.artifact_id)} />
          ) : (
            <Text type="secondary">-</Text>
          ),
      },
    ],
    []
  )

  const filteredMessages = useMemo(() => {
    let list = messagesList || []
    // 服务端已支持方向/大小过滤，这里仅做兜底
    if (dirFilter !== 'all') list = list.filter((m) => m.direction === dirFilter)
    if (minSize > 0) list = list.filter((m) => (m.size || 0) >= minSize)
    return list
  }, [messagesList, dirFilter, minSize])

  return (
    <>
      <Card
        title="WebSocket 消息"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} size="small" onClick={loadConnections} loading={loading}>
              刷新
            </Button>
            <Button size="small" onClick={() => exportWs('json')}>
              导出JSON
            </Button>
            <Button size="small" onClick={() => exportWs('csv')}>
              导出CSV
            </Button>
            <Button icon={<ClearOutlined />} size="small" danger onClick={clearWebSockets}>
              清空
            </Button>
          </Space>
        }
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="说明"
          description="WebSocket 消息通过代理侧实时捕获。若看不到消息：确认应用是否走代理/是否使用 HTTP3(QUIC) 绕过。"
        />
        <Table
          rowKey="id"
          columns={connectionColumns}
          dataSource={connections}
          loading={loading}
          size="small"
          pagination={{
            current: connPage,
            pageSize: connPageSize,
            total: connTotal,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100, 200],
            onChange: (p, ps) => {
              setConnPage(p)
              setConnPageSize(ps)
            },
          }}
          scroll={{ y: 650 }}
          virtual
        />
      </Card>

      <Drawer
        title={selectedConnection ? `连接：${selectedConnection.url}` : '连接详情'}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={900}
        extra={
          <Space>
            <Button
              size="small"
              icon={<ReloadOutlined />}
              onClick={() => selectedConnection?.id && loadMessages(selectedConnection.id)}
              loading={messagesLoading}
            >
              刷新消息
            </Button>
          </Space>
        }
      >
        {selectedConnection && (
          <Space wrap style={{ marginBottom: 12 }}>
            <Button size="small" onClick={() => exportWs('json', selectedConnection.id)}>
              导出该连接(JSON)
            </Button>
            <Button size="small" onClick={() => exportWs('csv', selectedConnection.id)}>
              导出该连接(CSV)
            </Button>
            <Button size="small" onClick={bundleArtifacts}>
              打包下载落盘消息(zip)
            </Button>
            <Button size="small" onClick={viewHandshakeRequest}>
              查看握手请求
            </Button>
            <Select
              value={dirFilter}
              onChange={(v) => {
                setMsgPage(1)
                setDirFilter(v)
              }}
              style={{ width: 140 }}
              size="small"
            >
              <Select.Option value="all">全部方向</Select.Option>
              <Select.Option value="send">send</Select.Option>
              <Select.Option value="receive">receive</Select.Option>
            </Select>
            <Text type="secondary">最小大小</Text>
            <InputNumber
              min={0}
              value={minSize}
              onChange={(v) => {
                setMsgPage(1)
                setMinSize(Number(v || 0))
              }}
              size="small"
              style={{ width: 120 }}
            />
            <Text type="secondary">B</Text>
          </Space>
        )}
        <Table
          rowKey="id"
          columns={messageColumns}
          dataSource={filteredMessages}
          loading={messagesLoading}
          size="small"
          pagination={{
            current: msgPage,
            pageSize: msgPageSize,
            total: msgTotal,
            showSizeChanger: true,
            pageSizeOptions: [50, 100, 200, 500],
            onChange: (p, ps) => {
              setMsgPage(p)
              setMsgPageSize(ps)
            },
          }}
          scroll={{ y: 520 }}
          virtual
        />
      </Drawer>

      <Modal
        title="握手请求详情"
        open={linkedRequestVisible}
        onCancel={() => setLinkedRequestVisible(false)}
        footer={[
          <Button key="close" onClick={() => setLinkedRequestVisible(false)}>
            关闭
          </Button>,
        ]}
        width={900}
      >
        <pre style={{ maxHeight: 520, overflow: 'auto', fontSize: 12 }}>{linkedRequest ? JSON.stringify(linkedRequest, null, 2) : '-'}</pre>
      </Modal>
    </>
  )
}

export default ProxyWebSocket
