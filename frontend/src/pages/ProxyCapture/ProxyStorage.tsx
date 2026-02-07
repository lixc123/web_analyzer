import React, { useCallback, useEffect, useState } from 'react'
import { Card, Space, Button, Typography, Table, InputNumber, Switch, message, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Text } = Typography

const formatBytes = (bytes?: number) => {
  const b = Number(bytes || 0)
  if (!b) return '0 B'
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(2)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} MB`
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

const ProxyStorage: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState<any>(null)

  const [artifactsMaxTotalMb, setArtifactsMaxTotalMb] = useState<number>(0)
  const [artifactsMaxAgeDays, setArtifactsMaxAgeDays] = useState<number>(0)
  const [sessionsMaxAgeDays, setSessionsMaxAgeDays] = useState<number>(0)
  const [dryRun, setDryRun] = useState(true)
  const [cleanupResult, setCleanupResult] = useState<any>(null)

  const loadStatus = useCallback(async () => {
    setLoading(true)
    try {
      const res = await axios.get('/api/v1/proxy/storage/status')
      setStatus(res.data)
    } catch (e) {
      console.error('加载存储状态失败:', e)
      message.error('加载存储状态失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadStatus()
  }, [loadStatus])

  const runCleanup = async (execute: boolean) => {
    try {
      const res = await axios.post('/api/v1/proxy/storage/cleanup', {
        artifacts_max_total_mb: artifactsMaxTotalMb,
        artifacts_max_age_days: artifactsMaxAgeDays,
        sessions_max_age_days: sessionsMaxAgeDays,
        dry_run: execute ? false : dryRun,
      })
      setCleanupResult(res.data)
      message.success(execute ? '清理完成' : '已生成清理预览')
      loadStatus()
    } catch (e) {
      console.error('清理失败:', e)
      message.error('清理失败')
    }
  }

  const deleteSession = async (sessionId: string) => {
    try {
      await axios.delete(`/api/v1/proxy/sessions/${encodeURIComponent(sessionId)}`)
      message.success('已删除会话')
      loadStatus()
    } catch (e) {
      console.error('删除失败:', e)
      message.error('删除失败')
    }
  }

  const sessions: any[] = status?.sessions?.items || []

  const columns: ColumnsType<any> = [
    { title: '会话ID', dataIndex: 'session_id', key: 'session_id', width: 240, render: (v: string) => <Text code>{v}</Text> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (s?: string) => (s === 'active' ? <Tag color="green">active</Tag> : <Tag>{s || 'stopped'}</Tag>) },
    { title: '请求', dataIndex: 'request_count', key: 'request_count', width: 80, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    { title: 'WS', dataIndex: 'ws_message_count', key: 'ws_message_count', width: 80, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    { title: 'Artifacts', dataIndex: 'artifact_count', key: 'artifact_count', width: 90, render: (v?: number) => <Text type="secondary">{v ?? 0}</Text> },
    {
      title: '占用',
      dataIndex: 'usage',
      key: 'usage',
      width: 120,
      render: (u?: any) => <Text type="secondary">{formatBytes(u?.total_bytes)}</Text>,
    },
    { title: '备注', dataIndex: 'notes', key: 'notes', ellipsis: true, render: (v?: string) => <Text type="secondary">{v || '-'}</Text> },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_, r) => (
        <Button size="small" danger icon={<DeleteOutlined />} onClick={() => deleteSession(r.session_id)} />
      ),
    },
  ]

  return (
    <Space direction="vertical" style={{ width: '100%' }} size={12}>
      <Card
        title="存储占用"
        extra={
          <Button icon={<ReloadOutlined />} size="small" onClick={loadStatus} loading={loading}>
            刷新
          </Button>
        }
      >
        <Space direction="vertical" style={{ width: '100%' }} size={6}>
          <Text>
            Artifacts：<Text code>{status?.artifacts?.path || '-'}</Text> | {formatBytes(status?.artifacts?.total_bytes)} | {status?.artifacts?.file_count ?? 0} files
          </Text>
          <Text>
            Sessions：<Text code>{status?.sessions?.path || '-'}</Text> | {formatBytes(status?.sessions?.total_bytes)} | {status?.sessions?.count ?? 0} sessions
          </Text>
        </Space>
      </Card>

      <Card title="清理策略（支持预览/执行）">
        <Space wrap>
          <Space>
            <Text type="secondary">Artifacts 最大总量</Text>
            <InputNumber min={0} value={artifactsMaxTotalMb} onChange={(v) => setArtifactsMaxTotalMb(Number(v || 0))} />
            <Text type="secondary">MB</Text>
          </Space>
          <Space>
            <Text type="secondary">Artifacts 最大年龄</Text>
            <InputNumber min={0} value={artifactsMaxAgeDays} onChange={(v) => setArtifactsMaxAgeDays(Number(v || 0))} />
            <Text type="secondary">天</Text>
          </Space>
          <Space>
            <Text type="secondary">Sessions 最大年龄</Text>
            <InputNumber min={0} value={sessionsMaxAgeDays} onChange={(v) => setSessionsMaxAgeDays(Number(v || 0))} />
            <Text type="secondary">天</Text>
          </Space>
          <Space>
            <Switch checked={dryRun} onChange={setDryRun} />
            <Text>dry-run</Text>
          </Space>
          <Button onClick={() => runCleanup(false)}>生成预览</Button>
          <Button type="primary" danger onClick={() => runCleanup(true)}>
            执行清理
          </Button>
        </Space>
        {cleanupResult ? (
          <pre style={{ marginTop: 12, maxHeight: 260, overflow: 'auto', fontSize: 12 }}>{JSON.stringify(cleanupResult, null, 2)}</pre>
        ) : null}
      </Card>

      <Card title="Proxy 会话占用">
        <Table rowKey="session_id" columns={columns} dataSource={sessions} size="small" pagination={{ pageSize: 20, showSizeChanger: true }} />
      </Card>
    </Space>
  )
}

export default ProxyStorage
