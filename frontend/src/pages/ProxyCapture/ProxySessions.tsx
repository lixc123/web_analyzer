import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, Table, Space, Button, Tag, Typography, Drawer, Tabs, message, Modal, Input, Tooltip } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, EyeOutlined, DeleteOutlined, DownloadOutlined, EditOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Text } = Typography

type ProxySession = {
  session_id: string
  status?: string
  host?: string
  port?: number
  started_at?: string
  ended_at?: string | null
  request_count?: number
  ws_message_count?: number
  artifact_count?: number
  notes?: string
}

type ProxyRequest = any
type WsConnection = any
type WsMessage = any

const fmt = (s?: string | null) => {
  if (!s) return '-'
  try {
    const d = new Date(s)
    if (Number.isNaN(d.getTime())) return s
    return d.toLocaleString('zh-CN')
  } catch {
    return String(s)
  }
}

const ProxySessions: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [sessions, setSessions] = useState<ProxySession[]>([])
  const [selected, setSelected] = useState<ProxySession | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [notesModalOpen, setNotesModalOpen] = useState(false)
  const [notesDraft, setNotesDraft] = useState('')

  const [requests, setRequests] = useState<ProxyRequest[]>([])
  const [wsConnections, setWsConnections] = useState<WsConnection[]>([])
  const [wsMessages, setWsMessages] = useState<WsMessage[]>([])
  const [wsSelectedConn, setWsSelectedConn] = useState<string>('')
  const [detailModalOpen, setDetailModalOpen] = useState(false)
  const [detailData, setDetailData] = useState<any>(null)

  const loadSessions = useCallback(async () => {
    setLoading(true)
    try {
      const res = await axios.get('/api/v1/proxy/sessions', { params: { limit: 500, offset: 0 } })
      setSessions(res.data.sessions || [])
    } catch (e) {
      console.error('加载会话失败:', e)
      message.error('加载会话失败')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadSessionData = useCallback(async (sessionId: string) => {
    try {
      const [reqRes, wsRes] = await Promise.all([
        axios.get(`/api/v1/proxy/sessions/${encodeURIComponent(sessionId)}/requests`, { params: { limit: 500, offset: 0 } }),
        axios.get(`/api/v1/proxy/sessions/${encodeURIComponent(sessionId)}/websockets`, { params: { limit: 300, offset: 0 } }),
      ])
      setRequests(reqRes.data.requests || [])
      setWsConnections(wsRes.data.connections || [])
      setWsMessages([])
      setWsSelectedConn('')
    } catch (e) {
      console.error('加载会话数据失败:', e)
      message.error('加载会话数据失败')
    }
  }, [])

  useEffect(() => {
    loadSessions()
  }, [loadSessions])

  const exportRequests = async (format: 'har' | 'csv' | 'json') => {
    if (!selected?.session_id) return
    try {
      const params = new URLSearchParams({ format, limit: '5000', session_id: selected.session_id })
      const res = await axios.get(`/api/v1/proxy/requests/export?${params.toString()}`, { responseType: 'blob' })
      const blob = new Blob([res.data])
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '-')
      link.download = `proxy_requests_${selected.session_id}_${ts}.${format}`
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

  const exportWebsockets = async (format: 'json' | 'csv') => {
    if (!selected?.session_id) return
    try {
      const res = await axios.get('/api/v1/proxy/websockets/export', {
        params: { format, session_id: selected.session_id, limit: 10000 },
        responseType: 'blob',
      })
      const blob = new Blob([res.data])
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '-')
      link.download = `proxy_websockets_${selected.session_id}_${ts}.${format}`
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

  const deleteSession = async (sessionId: string) => {
    Modal.confirm({
      title: '确认删除会话？',
      content: `会话：${sessionId}（会同时删除该会话引用的 artifacts）`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      async onOk() {
        try {
          await axios.delete(`/api/v1/proxy/sessions/${encodeURIComponent(sessionId)}`)
          message.success('删除成功')
          if (selected?.session_id === sessionId) {
            setDrawerOpen(false)
            setSelected(null)
          }
          loadSessions()
        } catch (e) {
          console.error('删除失败:', e)
          message.error('删除失败')
        }
      },
    })
  }

  const openNotes = () => {
    setNotesDraft(selected?.notes || '')
    setNotesModalOpen(true)
  }

  const saveNotes = async () => {
    if (!selected?.session_id) return
    try {
      await axios.patch(`/api/v1/proxy/sessions/${encodeURIComponent(selected.session_id)}`, { notes: notesDraft })
      message.success('已保存备注')
      setNotesModalOpen(false)
      loadSessions()
    } catch (e) {
      console.error('保存备注失败:', e)
      message.error('保存备注失败')
    }
  }

  const openWsMessages = async (connId: string) => {
    if (!selected?.session_id) return
    setWsSelectedConn(connId)
    try {
      const res = await axios.get(`/api/v1/proxy/sessions/${encodeURIComponent(selected.session_id)}/websockets/${encodeURIComponent(connId)}/messages`, {
        params: { limit: 2000, offset: 0 },
      })
      setWsMessages(res.data.messages || [])
    } catch (e) {
      console.error('加载 WS 消息失败:', e)
      message.error('加载 WS 消息失败')
    }
  }

  const sessionColumns: ColumnsType<ProxySession> = [
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (s?: string) => (s === 'active' ? <Tag color="green">active</Tag> : <Tag>{s || 'stopped'}</Tag>),
    },
    { title: '会话ID', dataIndex: 'session_id', key: 'session_id', width: 220, render: (v: string) => <Text code>{v}</Text> },
    { title: '开始', dataIndex: 'started_at', key: 'started_at', width: 180, render: (v?: string) => <Text type="secondary">{fmt(v)}</Text> },
    { title: '结束', dataIndex: 'ended_at', key: 'ended_at', width: 180, render: (v?: string) => <Text type="secondary">{fmt(v)}</Text> },
    { title: '请求', dataIndex: 'request_count', key: 'request_count', width: 80, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    { title: 'WS消息', dataIndex: 'ws_message_count', key: 'ws_message_count', width: 90, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    { title: 'Artifacts', dataIndex: 'artifact_count', key: 'artifact_count', width: 90, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    {
      title: '备注',
      dataIndex: 'notes',
      key: 'notes',
      ellipsis: true,
      render: (v?: string) => <Text type="secondary">{v || '-'}</Text>,
    },
    {
      title: '操作',
      key: 'action',
      width: 140,
      render: (_, r) => (
        <Space>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() => {
              setSelected(r)
              setDrawerOpen(true)
              loadSessionData(r.session_id)
            }}
          >
            查看
          </Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => deleteSession(r.session_id)} />
        </Space>
      ),
    },
  ]

  const requestColumns: ColumnsType<any> = [
    { title: '方法', dataIndex: 'method', key: 'method', width: 80, render: (m: string) => <Tag>{m}</Tag> },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (u: string) => (
        <Tooltip title={u}>
          <Text style={{ fontSize: 12 }}>{u}</Text>
        </Tooltip>
      ),
    },
    { title: '状态', dataIndex: 'status_code', key: 'status_code', width: 90, render: (s?: number) => <Text type="secondary">{s ?? '-'}</Text> },
    { title: '进程', dataIndex: 'client_process', key: 'client_process', width: 140, render: (p?: any) => <Text type="secondary">{p?.name || '-'}</Text> },
    { title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 180, render: (t?: number) => <Text type="secondary">{t ? new Date(t * 1000).toLocaleString('zh-CN') : '-'}</Text> },
    {
      title: '操作',
      key: 'act',
      width: 90,
      render: (_, r) => (
        <Button
          size="small"
          onClick={() => {
            setDetailData(r)
            setDetailModalOpen(true)
          }}
        >
          详情
        </Button>
      ),
    },
  ]

  const wsConnColumns: ColumnsType<any> = [
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (s?: string) => (s === 'closed' ? <Tag>closed</Tag> : <Tag color="green">open</Tag>) },
    { title: 'URL', dataIndex: 'url', key: 'url', ellipsis: true, render: (u: string) => <Text style={{ fontSize: 12 }}>{u}</Text> },
    { title: '消息数', dataIndex: 'message_count', key: 'message_count', width: 100, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    {
      title: '操作',
      key: 'act',
      width: 120,
      render: (_, r) => (
        <Space>
          <Button size="small" onClick={() => openWsMessages(r.id)}>
            消息
          </Button>
        </Space>
      ),
    },
  ]

  const wsMsgColumns: ColumnsType<any> = [
    { title: '方向', dataIndex: 'direction', key: 'direction', width: 90, render: (d?: string) => (d === 'send' ? <Tag color="blue">send</Tag> : <Tag color="purple">recv</Tag>) },
    { title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 180, render: (v?: any) => <Text type="secondary">{fmt(v)}</Text> },
    { title: '大小', dataIndex: 'size', key: 'size', width: 100, render: (v?: number) => <Text type="secondary">{v ?? 0} B</Text> },
    { title: '预览', dataIndex: 'data', key: 'data', ellipsis: true, render: (v?: string) => <Text style={{ fontSize: 12 }}>{v || '-'}</Text> },
  ]

  const drawerTitle = useMemo(() => {
    if (!selected) return '会话详情'
    return `会话：${selected.session_id}`
  }, [selected])

  return (
    <>
      <Card
        title="Proxy Capture 会话"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} size="small" onClick={loadSessions} loading={loading}>
              刷新
            </Button>
          </Space>
        }
      >
        <Table rowKey="session_id" columns={sessionColumns} dataSource={sessions} loading={loading} size="small" pagination={{ pageSize: 20, showSizeChanger: true }} />
      </Card>

      <Drawer title={drawerTitle} open={drawerOpen} onClose={() => setDrawerOpen(false)} width={1100} extra={
        <Space>
          <Button icon={<EditOutlined />} size="small" onClick={openNotes} disabled={!selected}>
            备注
          </Button>
          <Button icon={<DownloadOutlined />} size="small" onClick={() => exportRequests('json')} disabled={!selected}>
            导出请求(JSON)
          </Button>
          <Button size="small" onClick={() => exportRequests('har')} disabled={!selected}>
            HAR
          </Button>
          <Button size="small" onClick={() => exportRequests('csv')} disabled={!selected}>
            CSV
          </Button>
          <Button size="small" onClick={() => exportWebsockets('json')} disabled={!selected}>
            导出WS(JSON)
          </Button>
          <Button size="small" onClick={() => exportWebsockets('csv')} disabled={!selected}>
            导出WS(CSV)
          </Button>
        </Space>
      }>
        <Tabs
          defaultActiveKey="requests"
          items={[
            {
              key: 'requests',
              label: '请求',
              children: <Table rowKey="id" columns={requestColumns} dataSource={requests} size="small" pagination={{ pageSize: 20, showSizeChanger: true }} />,
            },
            {
              key: 'websockets',
              label: 'WebSocket',
              children: (
                <Space direction="vertical" style={{ width: '100%' }} size={12}>
                  <Table rowKey="id" columns={wsConnColumns} dataSource={wsConnections} size="small" pagination={{ pageSize: 20, showSizeChanger: true }} />
                  {wsSelectedConn ? (
                    <Card size="small" title={`消息：${wsSelectedConn}`}>
                      <Table rowKey="id" columns={wsMsgColumns} dataSource={wsMessages} size="small" pagination={{ pageSize: 30, showSizeChanger: true }} />
                    </Card>
                  ) : null}
                </Space>
              ),
            },
          ]}
        />
      </Drawer>

      <Modal title="会话备注" open={notesModalOpen} onCancel={() => setNotesModalOpen(false)} onOk={saveNotes} okText="保存" cancelText="取消">
        <Input.TextArea rows={4} value={notesDraft} onChange={(e) => setNotesDraft(e.target.value)} placeholder="写点备注，方便回溯…" />
      </Modal>

      <Modal title="请求详情" open={detailModalOpen} onCancel={() => setDetailModalOpen(false)} footer={[<Button key="close" onClick={() => setDetailModalOpen(false)}>关闭</Button>]} width={900}>
        <pre style={{ maxHeight: 520, overflow: 'auto', fontSize: 12 }}>{detailData ? JSON.stringify(detailData, null, 2) : '-'}</pre>
      </Modal>
    </>
  )
}

export default ProxySessions

