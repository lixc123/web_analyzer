import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, Table, Space, Button, Input, InputNumber, Switch, Typography, message, Alert, Select, Tooltip, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, PlayCircleOutlined, PauseCircleOutlined, EyeOutlined, DownloadOutlined } from '@ant-design/icons'
import axios from 'axios'
import { useProxyWebSocket, ProxyJsEvent } from '@hooks/useProxyWebSocket'

const { Text } = Typography

interface JsInjectionSession {
  session_id: string
  status: string
  created_at_ms?: number
  endpoint?: string
  target_url_contains?: string
  sample_rate?: number
  capture_stack?: boolean
  max_stack_lines?: number
  max_body_length?: number
  enable_ws_messages?: boolean
  proxy_session_id?: string
  attached_targets?: any[]
  event_count?: number
  errors?: string[]
}

const formatTs = (ts?: number | string) => {
  if (!ts) return '-'
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  return d.toLocaleString('zh-CN')
}

const downloadJson = (filename: string, data: any) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

const ProxyJsInjection: React.FC = () => {
  const { proxyStatus, jsEvents } = useProxyWebSocket()
  const [sessions, setSessions] = useState<JsInjectionSession[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(false)
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [endpoint, setEndpoint] = useState('http://127.0.0.1:9222')
  const [targetUrlContains, setTargetUrlContains] = useState<string>('')
  const [sampleRate, setSampleRate] = useState<number>(0.2)
  const [captureStack, setCaptureStack] = useState<boolean>(true)
  const [maxStackLines, setMaxStackLines] = useState<number>(25)
  const [maxBodyLength, setMaxBodyLength] = useState<number>(1200)
  const [enableWsMessages, setEnableWsMessages] = useState<boolean>(false)

  const [proxySessionId, setProxySessionId] = useState<string>('')
  const [diskEvents, setDiskEvents] = useState<ProxyJsEvent[]>([])
  const [diskLoading, setDiskLoading] = useState(false)
  const [diskTotal, setDiskTotal] = useState(0)
  const [diskPage, setDiskPage] = useState(1)
  const [diskPageSize, setDiskPageSize] = useState(200)
  const [filterCorrelatedRequestId, setFilterCorrelatedRequestId] = useState<string>('')

  useEffect(() => {
    if (!proxySessionId && proxyStatus?.proxy_session_id) setProxySessionId(proxyStatus.proxy_session_id)
  }, [proxyStatus?.proxy_session_id, proxySessionId])

  // 来自“请求详情联动”的自动过滤
  useEffect(() => {
    const fromStore = sessionStorage.getItem('proxy_js_filter_request_id')
    if (fromStore) {
      setFilterCorrelatedRequestId(fromStore)
      sessionStorage.removeItem('proxy_js_filter_request_id')
    }
    const handler = (e: any) => {
      const rid = e?.detail?.requestId
      if (!rid) return
      setFilterCorrelatedRequestId(String(rid))
    }
    window.addEventListener('proxy-js-injection:set-filter', handler as any)
    return () => window.removeEventListener('proxy-js-injection:set-filter', handler as any)
  }, [])

  const loadSessions = useCallback(async () => {
    setSessionsLoading(true)
    try {
      const res = await axios.get('/api/v1/js-injection/sessions')
      setSessions(res.data.sessions || [])
    } catch (e) {
      console.error('加载 JS 注入会话失败:', e)
      message.error('加载 JS 注入会话失败')
    } finally {
      setSessionsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadSessions()
  }, [loadSessions])

  const startInjection = async () => {
    if (!endpoint) {
      message.warning('请输入远程调试端口地址，例如 http://127.0.0.1:9222')
      return
    }
    setStarting(true)
    try {
      await axios.post('/api/v1/js-injection/start', {
        endpoint,
        target_url_contains: targetUrlContains || undefined,
        sample_rate: sampleRate,
        capture_stack: captureStack,
        max_stack_lines: maxStackLines,
        max_body_length: maxBodyLength,
        enable_ws_messages: enableWsMessages,
        proxy_session_id: proxyStatus?.proxy_session_id || undefined,
      })
      message.success('JS 注入已启动（请确保目标进程已开启 remote debugging）')
      await loadSessions()
    } catch (e: any) {
      console.error('启动 JS 注入失败:', e)
      message.error(e?.response?.data?.detail || '启动 JS 注入失败')
    } finally {
      setStarting(false)
    }
  }

  const stopSession = async (sid: string) => {
    if (!sid) return
    setStopping(true)
    try {
      await axios.post(`/api/v1/js-injection/stop/${encodeURIComponent(sid)}`)
      message.success('已停止')
      await loadSessions()
    } catch (e) {
      console.error('停止失败:', e)
      message.error('停止失败')
    } finally {
      setStopping(false)
    }
  }

  const liveEvents = useMemo(() => {
    let list = jsEvents || []
    if (filterCorrelatedRequestId) {
      list = list.filter((e) => String(e.correlated_request_id || '') === String(filterCorrelatedRequestId))
    }
    return list
  }, [jsEvents, filterCorrelatedRequestId])

  const loadDiskEvents = useCallback(async () => {
    if (!proxySessionId) return
    setDiskLoading(true)
    try {
      const res = await axios.get(`/api/v1/proxy/sessions/${encodeURIComponent(proxySessionId)}/js-events`, {
        params: {
          limit: diskPageSize,
          offset: (diskPage - 1) * diskPageSize,
          correlated_request_id: filterCorrelatedRequestId || undefined,
        },
      })
      setDiskEvents(res.data.events || [])
      setDiskTotal(Number(res.data.total || 0))
    } catch (e) {
      console.error('加载会话 JS 事件失败:', e)
      message.error('加载会话 JS 事件失败（可能该会话没有注入数据）')
    } finally {
      setDiskLoading(false)
    }
  }, [proxySessionId, diskPage, diskPageSize, filterCorrelatedRequestId])

  const exportDiskAll = async () => {
    if (!proxySessionId) return
    try {
      const limit = 5000
      const res = await axios.get(`/api/v1/proxy/sessions/${encodeURIComponent(proxySessionId)}/js-events`, {
        params: {
          limit,
          offset: 0,
          correlated_request_id: filterCorrelatedRequestId || undefined,
        },
      })
      const events = res.data.events || []
      const totalAll = Number(res.data.total || events.length)
      downloadJson(
        `js_events_${proxySessionId}_${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
        { session_id: proxySessionId, total: totalAll, events }
      )
      if (totalAll > limit) message.info(`仅导出前 ${limit} 条（总计 ${totalAll} 条）`)
    } catch (e) {
      console.error('导出失败:', e)
      message.error('导出失败')
    }
  }

  useEffect(() => {
    if (proxySessionId) loadDiskEvents()
  }, [proxySessionId, diskPage, diskPageSize, filterCorrelatedRequestId, loadDiskEvents])

  const openRequestDetail = (requestId?: string) => {
    if (!requestId) return
    sessionStorage.setItem('proxy_capture_request_id', requestId)
    window.dispatchEvent(new CustomEvent('proxy-capture:switch-tab', { detail: { key: 'requests' } }))
    window.dispatchEvent(new CustomEvent('proxy-capture:open-request-detail', { detail: { requestId } }))
  }

  const columns: ColumnsType<ProxyJsEvent> = useMemo(
    () => [
      {
        title: '时间',
        dataIndex: 'timestamp',
        key: 'timestamp',
        width: 180,
        render: (ts: any, r) => <Text type="secondary">{formatTs(ts ?? (r.timestamp_ms ? Number(r.timestamp_ms) / 1000 : undefined))}</Text>,
      },
      {
        title: '类型',
        dataIndex: 'event_type',
        key: 'event_type',
        width: 130,
        render: (v?: string) => <Tag color={v?.includes('ERROR') ? 'red' : v?.includes('WS_') ? 'purple' : 'blue'}>{v || '-'}</Tag>,
      },
      { title: '方法', dataIndex: 'method', key: 'method', width: 90, render: (v?: string) => <Text type="secondary">{v || '-'}</Text> },
      {
        title: 'URL',
        dataIndex: 'url',
        key: 'url',
        ellipsis: true,
        render: (v?: string) => (
          <Tooltip title={v}>
            <Text style={{ fontSize: 12 }}>{v || '-'}</Text>
          </Tooltip>
        ),
      },
      {
        title: '关联请求',
        dataIndex: 'correlated_request_id',
        key: 'correlated_request_id',
        width: 200,
        render: (v?: string) =>
          v ? (
            <Space size={6}>
              <Text code>{v}</Text>
              <Button size="small" icon={<EyeOutlined />} onClick={() => openRequestDetail(v)} />
            </Space>
          ) : (
            <Text type="secondary">-</Text>
          ),
      },
    ],
    []
  )

  const expandedRowRender = (r: ProxyJsEvent) => (
    <div style={{ padding: 8 }}>
      {r.target ? (
        <div style={{ marginBottom: 8 }}>
          <Text type="secondary">Target:</Text> <Text code>{r.target?.title || r.target?.id}</Text>{' '}
          <Text type="secondary">{r.target?.url || ''}</Text>
        </div>
      ) : null}
      {r.stack ? (
        <>
          <Text strong>Stack</Text>
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 240, overflow: 'auto', marginTop: 8 }}>{String(r.stack)}</pre>
        </>
      ) : (
        <Text type="secondary">无调用栈（可在启动时开启 capture_stack）</Text>
      )}
      {r.data ? (
        <>
          <Text strong>Data</Text>
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 240, overflow: 'auto', marginTop: 8 }}>
            {JSON.stringify(r.data, null, 2)}
          </pre>
        </>
      ) : null}
    </div>
  )

  const sessionOptions = useMemo(() => {
    const opts = (sessions || []).map((s) => s.proxy_session_id).filter((v): v is string => !!v)
    return Array.from(new Set(opts)).sort().reverse()
  }, [sessions])

  return (
    <div style={{ padding: 0 }}>
      <Card
        title="JS 注入采集（可选：WebView2/Electron/CEF）"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={loadSessions} loading={sessionsLoading}>
              刷新会话
            </Button>
            <Button type="primary" icon={<PlayCircleOutlined />} onClick={startInjection} loading={starting}>
              启动注入
            </Button>
          </Space>
        }
        style={{ marginBottom: 16 }}
      >
        <Alert
          type="info"
          showIcon
          message="需要目标进程开启 Remote Debugging（CDP）"
          description={
            <div>
              <div>示例：Electron/CEF/Chrome 启动参数：<Text code>--remote-debugging-port=9222</Text></div>
              <div>默认关联到当前 Proxy 会话：<Text code>{proxyStatus?.proxy_session_id || '-'}</Text></div>
            </div>
          }
          style={{ marginBottom: 12 }}
        />

        <Space wrap>
          <div>
            <Text type="secondary">CDP 端口</Text>
            <Input style={{ width: 260 }} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="http://127.0.0.1:9222" />
          </div>
          <div>
            <Text type="secondary">Target URL 包含</Text>
            <Input style={{ width: 220 }} value={targetUrlContains} onChange={(e) => setTargetUrlContains(e.target.value)} placeholder="可选过滤" />
          </div>
          <div>
            <Text type="secondary">采样率</Text>
            <InputNumber min={0} max={1} step={0.05} value={sampleRate} onChange={(v) => setSampleRate(Number(v ?? 0.2))} />
          </div>
          <div>
            <Text type="secondary">调用栈</Text>
            <Switch checked={captureStack} onChange={setCaptureStack} />
          </div>
          <div>
            <Text type="secondary">栈深</Text>
            <InputNumber min={1} max={120} value={maxStackLines} onChange={(v) => setMaxStackLines(Number(v ?? 25))} />
          </div>
          <div>
            <Text type="secondary">Body 预览</Text>
            <InputNumber min={0} max={20000} value={maxBodyLength} onChange={(v) => setMaxBodyLength(Number(v ?? 1200))} />
          </div>
          <div>
            <Text type="secondary">WS 消息大小</Text>
            <Switch checked={enableWsMessages} onChange={setEnableWsMessages} />
          </div>
        </Space>
      </Card>

      <Card
        title="注入会话"
        style={{ marginBottom: 16 }}
        extra={<Text type="secondary">共 {sessions.length} 个</Text>}
      >
        <Table
          size="small"
          rowKey="session_id"
          loading={sessionsLoading}
          dataSource={sessions}
          pagination={{ pageSize: 5 }}
          columns={[
            { title: 'ID', dataIndex: 'session_id', key: 'session_id', width: 220, render: (v: string) => <Text code>{v}</Text> },
            { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (v: string) => (v === 'running' ? <Tag color="green">running</Tag> : <Tag>{v}</Tag>) },
            { title: '端口', dataIndex: 'endpoint', key: 'endpoint', width: 220, render: (v?: string) => <Text type="secondary">{v || '-'}</Text> },
            { title: 'Targets', dataIndex: 'attached_targets', key: 'attached_targets', width: 100, render: (v?: any[]) => <Text type="secondary">{v?.length ?? 0}</Text> },
            { title: '事件数', dataIndex: 'event_count', key: 'event_count', width: 100, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
            {
              title: '操作',
              key: 'actions',
              width: 120,
              render: (_, r: JsInjectionSession) => (
                <Space>
                  <Button size="small" danger icon={<PauseCircleOutlined />} loading={stopping} disabled={r.status !== 'running'} onClick={() => stopSession(r.session_id)}>
                    停止
                  </Button>
                </Space>
              ),
            },
          ]}
          expandable={{
            expandedRowRender: (r: JsInjectionSession) => (
              <div style={{ padding: 8 }}>
                <div style={{ marginBottom: 8 }}>
                  <Text type="secondary">Proxy 会话：</Text> <Text code>{r.proxy_session_id || '-'}</Text>
                </div>
                {r.errors?.length ? (
                  <Alert type="warning" showIcon message="最近错误" description={<pre style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>{r.errors.join('\n')}</pre>} />
                ) : (
                  <Text type="secondary">无错误</Text>
                )}
              </div>
            ),
          }}
        />
      </Card>

      <Card
        title="实时事件（WS）"
        extra={
          <Space wrap>
            <Text type="secondary">最近 {liveEvents.length} 条</Text>
            <Input
              placeholder="按关联 request_id 过滤"
              style={{ width: 240 }}
              value={filterCorrelatedRequestId}
              onChange={(e) => setFilterCorrelatedRequestId(e.target.value)}
              allowClear
            />
            <Button icon={<DownloadOutlined />} onClick={() => downloadJson(`js_events_live_${new Date().toISOString().replace(/[:.]/g, '-')}.json`, liveEvents)}>
              导出 JSON
            </Button>
          </Space>
        }
        style={{ marginBottom: 16 }}
      >
        <Table
          size="small"
          rowKey="id"
          dataSource={liveEvents}
          columns={columns}
          pagination={{ pageSize: 20 }}
          expandable={{ expandedRowRender }}
        />
      </Card>

      <Card
        title="落盘回放（Proxy 会话）"
        extra={
          <Space wrap>
            <Text type="secondary">会话</Text>
            {sessionOptions.length ? (
              <Select
                style={{ width: 320 }}
                value={proxySessionId || undefined}
                onChange={(v) => {
                  setDiskPage(1)
                  setProxySessionId(String(v))
                }}
                showSearch
                placeholder="选择 proxy_session_id"
                options={sessionOptions.map((s) => ({ value: s, label: s }))}
              />
            ) : (
              <Input
                style={{ width: 320 }}
                value={proxySessionId}
                onChange={(e) => {
                  setDiskPage(1)
                  setProxySessionId(e.target.value)
                }}
                placeholder="输入 proxy_session_id"
              />
            )}
            <Button icon={<ReloadOutlined />} onClick={() => loadDiskEvents()} loading={diskLoading}>
              刷新
            </Button>
            <Button
              icon={<DownloadOutlined />}
              onClick={exportDiskAll}
            >
              导出 JSON
            </Button>
          </Space>
        }
      >
        {!proxySessionId ? (
          <Text type="secondary">暂无 proxy_session_id</Text>
        ) : (
          <Table
            size="small"
            rowKey="id"
            loading={diskLoading}
            dataSource={diskEvents}
            columns={columns}
            pagination={{
              current: diskPage,
              pageSize: diskPageSize,
              total: diskTotal,
              showSizeChanger: true,
              pageSizeOptions: [50, 100, 200, 500],
              onChange: (p, ps) => {
                setDiskPage(p)
                setDiskPageSize(ps)
              },
            }}
            expandable={{ expandedRowRender }}
          />
        )}
      </Card>
    </div>
  )
}

export default ProxyJsInjection
