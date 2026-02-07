import React, { useCallback, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import { Alert, Button, Card, Collapse, Descriptions, Divider, List, Space, Tag, Typography } from 'antd'
import { ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons'

const { Title, Text, Paragraph } = Typography

type Device = {
  platform?: string
  device?: string
  os_version?: string
  ip?: string
  first_seen?: string
  last_seen?: string
  request_count?: number
  user_agent?: string
  device_id?: string
}

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

const MobileSetup: React.FC = () => {
  const [platform, setPlatform] = useState<'ios' | 'android'>('ios')
  const [loading, setLoading] = useState(false)
  const [qrCode, setQrCode] = useState('')
  const [instructions, setInstructions] = useState<any>(null)
  const [serverIP, setServerIP] = useState('')
  const [serverPort, setServerPort] = useState<number>(8888)
  const [devices, setDevices] = useState<Device[]>([])
  const [diagnostics, setDiagnostics] = useState<any>(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const [qrRes, instRes, ipRes, statusRes, devicesRes, diagRes] = await Promise.all([
        axios.get('/api/v1/proxy/cert/qrcode'),
        axios.get('/api/v1/proxy/cert/instructions'),
        axios.get('/api/v1/proxy/local-ip'),
        axios.get('/api/v1/proxy/status'),
        axios.get('/api/v1/proxy/devices'),
        axios.get('/api/v1/proxy/diagnostics'),
      ])

      setQrCode(qrRes.data?.qrcode || '')
      setInstructions(instRes.data || null)
      setServerIP(ipRes.data?.ip || '')
      setServerPort(Number(statusRes.data?.port || 8888))
      setDevices((devicesRes.data?.devices || []) as Device[])
      setDiagnostics(diagRes.data || null)
    } catch (error) {
      console.error('获取移动端配置数据失败:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const timer = setInterval(fetchData, 5000)
    return () => clearInterval(timer)
  }, [fetchData])

  const platformDevices = useMemo(() => {
    const want = platform === 'ios' ? 'ios' : 'android'
    return (devices || []).filter((d) => (d.platform || '').toString().toLowerCase() === want)
  }, [devices, platform])

  const isConnected = platformDevices.length > 0
  const currentInstructions: string[] = useMemo(() => {
    const key = platform === 'ios' ? 'ios' : 'android'
    const list = instructions?.[key]
    return Array.isArray(list) ? list : []
  }, [instructions, platform])

  const issues: Issue[] = diagnostics?.issues || []

  return (
    <Card
      title="移动端配置向导"
      extra={
        <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading} size="small">
          刷新
        </Button>
      }
    >
      <Alert
        type="info"
        showIcon
        message="推荐顺序"
        description={
          <ol style={{ margin: 0, paddingLeft: 20 }}>
            <li>手机与本机在同一 Wi‑Fi/局域网</li>
            <li>手机 Wi‑Fi 代理设置为：{serverIP}:{serverPort}</li>
            <li>安装并信任 CA 证书（HTTPS 解密必需）</li>
            <li>打开目标 App 触发请求 → 在「请求列表」确认是否有流量</li>
          </ol>
        }
        style={{ marginBottom: 16 }}
      />

      <Space style={{ marginBottom: 12 }}>
        <Button type={platform === 'ios' ? 'primary' : 'default'} onClick={() => setPlatform('ios')}>
          iOS
        </Button>
        <Button type={platform === 'android' ? 'primary' : 'default'} onClick={() => setPlatform('android')}>
          Android
        </Button>
        {isConnected ? <Tag color="green">已检测到设备请求</Tag> : <Tag color="orange">未检测到设备请求</Tag>}
      </Space>

      <Descriptions bordered size="small" column={1} style={{ marginBottom: 12 }}>
        <Descriptions.Item label="代理服务器">
          <Text code>{serverIP || '-'}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="代理端口">
          <Text code>{serverPort}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="设备请求数（当前平台）">
          <Text>{platformDevices.reduce((sum, d) => sum + Number(d.request_count || 0), 0)}</Text>
        </Descriptions.Item>
      </Descriptions>

      {qrCode ? (
        <Card size="small" title="证书下载" style={{ marginBottom: 12 }}>
          <Space align="start" wrap>
            <img src={`data:image/png;base64,${qrCode}`} alt="CA证书二维码" style={{ width: 160, height: 160 }} />
            <div>
              <Paragraph style={{ marginBottom: 8 }}>
                <Space>
                  <SafetyCertificateOutlined />
                  <Text>扫描二维码下载证书，或直接下载：</Text>
                </Space>
              </Paragraph>
              <Space direction="vertical" size={4}>
                <a href="/api/v1/proxy/cert/download" download>
                  下载证书文件
                </a>
                <Text type="secondary">
                  也可在手机浏览器访问 <Text code>http://mitm.it</Text> 下载证书（需手机已设置代理）
                </Text>
              </Space>
            </div>
          </Space>
        </Card>
      ) : null}

      <Card size="small" title={`${platform === 'ios' ? 'iOS' : 'Android'} 配置步骤`} style={{ marginBottom: 12 }}>
        {currentInstructions.length ? (
          <ol style={{ margin: 0, paddingLeft: 20 }}>
            {currentInstructions.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        ) : (
          <Text type="secondary">暂无平台步骤（后端未返回 instructions）</Text>
        )}
      </Card>

      <Card size="small" title="设备列表（当前平台）" style={{ marginBottom: 12 }}>
        {platformDevices.length ? (
          <List
            size="small"
            dataSource={platformDevices}
            renderItem={(d) => (
              <List.Item>
                <Space direction="vertical" size={2}>
                  <Space>
                    <Tag color="blue">{d.platform}</Tag>
                    <Text strong>{d.device || 'Unknown'}</Text>
                    <Text type="secondary">{d.os_version || ''}</Text>
                    {d.ip ? <Text code>{d.ip}</Text> : null}
                  </Space>
                  <Text type="secondary">请求数：{Number(d.request_count || 0)}；首次：{d.first_seen ? new Date(d.first_seen).toLocaleString('zh-CN') : '-'}</Text>
                  {d.user_agent ? <Text type="secondary" ellipsis={{ tooltip: d.user_agent }}>UA：{d.user_agent}</Text> : null}
                </Space>
              </List.Item>
            )}
          />
        ) : (
          <Text type="secondary">暂无设备请求。请确认手机代理设置与证书安装后，打开 App 产生网络请求。</Text>
        )}
      </Card>

      <Divider />

      <Alert
        type={issues.some((i) => i.level === 'error') ? 'error' : issues.some((i) => i.level === 'warning') ? 'warning' : 'success'}
        showIcon
        message="抓包诊断（来自后端）"
        description={
          issues.length ? (
            <List
              size="small"
              dataSource={issues}
              renderItem={(item) => (
                <List.Item>
                  <Space direction="vertical" size={2}>
                    <Space>
                      <Tag color={levelColor[item.level]}>{item.level.toUpperCase()}</Tag>
                      <Text code>{item.code}</Text>
                      <Text>{item.message}</Text>
                    </Space>
                    {item.action ? <Text type="secondary">{item.action}</Text> : null}
                    {item.command ? (
                      <Text type="secondary">
                        命令：<Text code>{item.command}</Text>
                      </Text>
                    ) : null}
                  </Space>
                </List.Item>
              )}
            />
          ) : (
            <Text type="secondary">暂无问题提示（仍抓不到时多半是绕过代理/HTTP3/证书固定/自研协议）</Text>
          )
        }
      />

      <Collapse
        style={{ marginTop: 12 }}
        items={[
          {
            key: 'triage',
            label: '抓不到怎么办（分诊）',
            children: (
              <Space direction="vertical" size={8}>
                <Alert
                  type="warning"
                  showIcon
                  message="1) 完全没流量（请求列表为空）"
                  description={
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      <li>确认手机 Wi‑Fi 代理为 {serverIP}:{serverPort}，且手机与本机同网段</li>
                      <li>确认目标 App 没走 VPN/专线/自建隧道（会绕过系统代理）</li>
                      <li>部分 App/浏览器可能走 HTTP/3(QUIC)：会造成代理抓不到或抓不全</li>
                    </ul>
                  }
                />
                <Alert
                  type="warning"
                  showIcon
                  message="2) 有流量但 HTTPS 全是失败/不可解密"
                  description={
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      <li>确认已安装并信任 CA 证书（iOS 需在“关于本机→证书信任设置”启用完全信任）</li>
                      <li>若证书已信任仍失败，常见原因：证书固定(pinning)/自研 TLS/应用层加密</li>
                    </ul>
                  }
                />
                <Alert
                  type="info"
                  showIcon
                  message="3) 证书固定/自研协议的处理路径"
                  description={
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      <li>本项目内置 Windows Native Hook（桌面应用）。移动端需额外方案（如 Frida/LSPosed/越狱等）</li>
                      <li>建议先用代理抓到“域名/路径/时序”，再用 Hook 定位“加密/签名/压缩点”</li>
                    </ul>
                  }
                />
              </Space>
            ),
          },
        ]}
      />
    </Card>
  )
}

export default MobileSetup
