import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, Space, Button, Typography, Alert, Tag, Divider, List, Tooltip, message, Descriptions } from 'antd'
import { ReloadOutlined, CopyOutlined, SafetyCertificateOutlined, SettingOutlined, ThunderboltOutlined } from '@ant-design/icons'
import axios from 'axios'
import { useProxyWebSocket } from '@hooks/useProxyWebSocket'
import { useNavigate } from 'react-router-dom'

const { Text, Paragraph } = Typography

type Issue = {
  code: string
  level: 'info' | 'warning' | 'error'
  message: string
  action?: string
  command?: string
}

const levelColor: Record<Issue['level'], string> = {
  info: 'blue',
  warning: 'orange',
  error: 'red',
}

const WindowsCaptureWizard: React.FC = () => {
  const navigate = useNavigate()
  const { proxyStatus } = useProxyWebSocket()
  const [loading, setLoading] = useState(false)
  const [diagnostics, setDiagnostics] = useState<any>(null)

  const loadDiagnostics = useCallback(async () => {
    setLoading(true)
    try {
      const res = await axios.get('/api/v1/proxy/diagnostics')
      setDiagnostics(res.data)
    } catch (e) {
      console.error('加载诊断失败:', e)
      message.error('加载诊断失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadDiagnostics()
  }, [loadDiagnostics])

  const currentPort = useMemo(() => {
    const p = proxyStatus?.port || diagnostics?.proxy_service?.port
    return typeof p === 'number' ? p : 8888
  }, [proxyStatus?.port, diagnostics?.proxy_service?.port])

  const doInstallCert = async () => {
    try {
      await axios.post('/api/v1/proxy/cert/install-windows')
      message.success('证书安装完成（若失败请以管理员权限重试）')
      loadDiagnostics()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '证书安装失败')
    }
  }

  const doRegenerateCert = async () => {
    try {
      await axios.post('/api/v1/proxy/cert/regenerate')
      message.success('证书已重新生成，请重新安装证书并重启代理')
      loadDiagnostics()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '重新生成失败')
    }
  }

  const doEnableWininet = async () => {
    try {
      await axios.post('/api/v1/proxy/system-proxy/enable', { host: '127.0.0.1', port: currentPort })
      message.success('WinINet 系统代理已启用')
      loadDiagnostics()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '启用失败')
    }
  }

  const doDisableWininet = async () => {
    try {
      await axios.post('/api/v1/proxy/system-proxy/disable')
      message.success('WinINet 系统代理已恢复')
      loadDiagnostics()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '恢复失败')
    }
  }

  const doEnableWinhttp = async (importFromIe = false) => {
    try {
      await axios.post('/api/v1/proxy/winhttp-proxy/enable', { host: '127.0.0.1', port: currentPort, import_from_ie: importFromIe })
      message.success('WinHTTP 代理已启用')
      loadDiagnostics()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '启用失败')
    }
  }

  const doDisableWinhttp = async () => {
    try {
      await axios.post('/api/v1/proxy/winhttp-proxy/disable')
      message.success('WinHTTP 代理已恢复')
      loadDiagnostics()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '恢复失败')
    }
  }

  const doOneClickCleanup = async () => {
    try {
      await Promise.allSettled([axios.post('/api/v1/proxy/system-proxy/disable'), axios.post('/api/v1/proxy/winhttp-proxy/disable'), axios.delete('/api/v1/proxy/websockets')])
      message.success('已尝试恢复代理并清空 WebSocket 缓存')
      loadDiagnostics()
    } catch {
      message.warning('清理过程中部分操作失败')
    }
  }

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      message.success('已复制')
    } catch {
      message.warning('复制失败，请手动复制')
    }
  }

  const issues: Issue[] = diagnostics?.issues || []

  const quickActions = (
    <Space wrap>
      <Button icon={<SafetyCertificateOutlined />} onClick={doInstallCert}>
        安装 CA 证书
      </Button>
      <Button icon={<SettingOutlined />} onClick={doEnableWininet}>
        启用 WinINet 代理
      </Button>
      <Button onClick={doDisableWininet}>恢复 WinINet</Button>
      <Button icon={<SettingOutlined />} onClick={() => doEnableWinhttp(false)}>
        启用 WinHTTP 代理
      </Button>
      <Button icon={<SettingOutlined />} onClick={() => doEnableWinhttp(true)}>
        WinHTTP 从IE导入
      </Button>
      <Button onClick={doDisableWinhttp}>恢复 WinHTTP</Button>
      <Button danger onClick={doOneClickCleanup}>
        一键清理/回滚
      </Button>
      <Button icon={<ThunderboltOutlined />} type="primary" onClick={() => navigate('/native-hook')}>
        打开 Native Hook
      </Button>
    </Space>
  )

  return (
    <Card
      title="Windows 桌面应用抓包向导"
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadDiagnostics} loading={loading} size="small">
            刷新诊断
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        message="推荐顺序（命中率最高）"
        description={
          <ol style={{ margin: 0, paddingLeft: 20 }}>
            <li>启动代理服务（Proxy Capture → 代理控制）</li>
            <li>安装 mitmproxy CA 证书（HTTPS 解密必需）</li>
            <li>开启 WinINet 系统代理（覆盖大多数应用）</li>
            <li>抓不到再开启 WinHTTP 代理（很多桌面应用用它）</li>
            <li>仍无效：考虑 QUIC/HTTP3 或证书固定 → 用 Native Hook（SSL Unpin）</li>
          </ol>
        }
        style={{ marginBottom: 16 }}
      />

      <Divider />

      <Paragraph>
        <Text strong>当前端口：</Text>
        <Text code>{currentPort}</Text>
        <Text type="secondary">（以运行状态为准，端口占用时可能自动+1）</Text>
      </Paragraph>

      {quickActions}

      <Divider />

      <Card size="small" title="当前代理快照" style={{ marginBottom: 12 }}>
        <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label="WinINet(系统代理)">
            <pre style={{ margin: 0, fontSize: 12, maxHeight: 140, overflow: 'auto' }}>{JSON.stringify(diagnostics?.proxy?.wininet || {}, null, 2)}</pre>
          </Descriptions.Item>
          <Descriptions.Item label="WinHTTP">
            <pre style={{ margin: 0, fontSize: 12, maxHeight: 140, overflow: 'auto' }}>{JSON.stringify(diagnostics?.proxy?.winhttp || {}, null, 2)}</pre>
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Alert
        type={issues.some((i) => i.level === 'error') ? 'error' : issues.some((i) => i.level === 'warning') ? 'warning' : 'success'}
        showIcon
        message="诊断结果"
        description={
          issues.length ? (
            <List
              size="small"
              dataSource={issues}
              renderItem={(item) => (
                <List.Item
                  actions={[
                    item.command ? (
                      <Tooltip title="复制命令">
                        <Button size="small" icon={<CopyOutlined />} onClick={() => copyText(item.command!)} />
                      </Tooltip>
                    ) : null,
                    item.code === 'CERT_EXPIRED' || item.code === 'CERT_EXPIRING_SOON' ? (
                      <Button size="small" onClick={doRegenerateCert}>
                        重新生成证书
                      </Button>
                    ) : null,
                    item.code === 'CERT_NOT_INSTALLED' ? (
                      <Button size="small" onClick={doInstallCert}>
                        安装证书
                      </Button>
                    ) : null,
                    item.code === 'WININET_PROXY_DISABLED' ? (
                      <Button size="small" onClick={doEnableWininet}>
                        启用 WinINet
                      </Button>
                    ) : null,
                    item.code === 'WINHTTP_PROXY_NOT_SET' ? (
                      <Button size="small" onClick={() => doEnableWinhttp(false)}>
                        启用 WinHTTP
                      </Button>
                    ) : null,
                    item.code === 'NO_TRAFFIC' ? (
                      <Button size="small" type="primary" onClick={() => navigate('/native-hook')}>
                        去 Hook
                      </Button>
                    ) : item.code === 'TLS_HANDSHAKE_FAIL' || item.code === 'CERT_PINNING' || item.code === 'APP_LAYER_ENCRYPTION' ? (
                      <Button size="small" type="primary" onClick={() => navigate('/native-hook')}>
                        去 Hook
                      </Button>
                    ) : item.code === 'BYPASS_PROXY' ? (
                      <Button
                        size="small"
                        onClick={() => {
                          doEnableWininet()
                          doEnableWinhttp(false)
                        }}
                      >
                        开启双代理
                      </Button>
                    ) : null,
                  ].filter(Boolean)}
                >
                  <Space direction="vertical" size={2}>
                    <Space>
                      <Tag color={levelColor[item.level]}>{item.level.toUpperCase()}</Tag>
                      <Text code>{item.code}</Text>
                      <Text>{item.message}</Text>
                    </Space>
                    {item.action && <Text type="secondary">{item.action}</Text>}
                    {item.command && (
                      <Text type="secondary">
                        命令：<Text code>{item.command}</Text>
                      </Text>
                    )}
                  </Space>
                </List.Item>
              )}
            />
          ) : (
            <Text type="secondary">暂无问题（仍抓不到时，多半是证书固定/HTTP3/自研协议）</Text>
          )
        }
      />
    </Card>
  )
}

export default WindowsCaptureWizard
