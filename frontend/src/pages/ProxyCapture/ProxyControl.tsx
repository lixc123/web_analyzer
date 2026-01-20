import React, { useState, useEffect } from 'react'
import {
  Card,
  Form,
  InputNumber,
  Switch,
  Button,
  Space,
  Badge,
  Statistic,
  Row,
  Col,
  message,
  Alert,
  Divider
} from 'antd'
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  ReloadOutlined,
  WifiOutlined
} from '@ant-design/icons'
import axios from 'axios'
import { useProxyWebSocket } from '@hooks/useProxyWebSocket'

interface ProxyConfig {
  host: string
  port: number
  enable_system_proxy: boolean
}

const ProxyControl: React.FC = () => {
  const [form] = Form.useForm()
  const [config, setConfig] = useState<ProxyConfig>({
    host: '0.0.0.0',
    port: 8888,
    enable_system_proxy: false
  })
  const [isRunning, setIsRunning] = useState(false)
  const [localIP, setLocalIP] = useState('')
  const [loading, setLoading] = useState(false)
  const [statusLoading, setStatusLoading] = useState(false)
  const [clientsCount, setClientsCount] = useState(0)
  const [totalRequests, setTotalRequests] = useState(0)

  // 使用WebSocket实时更新
  const { proxyStatus } = useProxyWebSocket()

  // 初始化
  useEffect(() => {
    checkStatus()
    fetchLocalIP()
    // 每30秒轮询一次状态（作为WebSocket的备份）
    const interval = setInterval(checkStatus, 30000)
    return () => clearInterval(interval)
  }, [])

  // 监听WebSocket状态更新
  useEffect(() => {
    if (proxyStatus) {
      setIsRunning(proxyStatus.running)
      setClientsCount(proxyStatus.clients_count || 0)
      setTotalRequests(proxyStatus.total_requests || 0)
    }
  }, [proxyStatus])

  const checkStatus = async () => {
    setStatusLoading(true)
    try {
      const res = await axios.get('/api/v1/proxy/status')
      setIsRunning(res.data.running)
      setClientsCount(res.data.clients_count || 0)
      setTotalRequests(res.data.total_requests || 0)
    } catch (error) {
      console.error('获取状态失败:', error)
    } finally {
      setStatusLoading(false)
    }
  }

  const fetchLocalIP = async () => {
    try {
      const res = await axios.get('/api/v1/proxy/local-ip')
      setLocalIP(res.data.ip)
    } catch (error) {
      console.error('获取本机IP失败:', error)
      message.error('获取本机IP失败')
    }
  }

  const handleStart = async () => {
    setLoading(true)
    try {
      const response = await axios.post('/api/v1/proxy/start', config)
      if (response.status === 200) {
        setIsRunning(true)
        message.success('代理服务启动成功')
        // 立即检查状态
        setTimeout(checkStatus, 1000)
      }
    } catch (error: any) {
      const errorMsg = error.response?.data?.detail || '启动失败'
      message.error(errorMsg)

      // 处理常见错误
      if (errorMsg.includes('端口') || errorMsg.includes('port')) {
        message.warning('端口可能被占用，请尝试其他端口')
      } else if (errorMsg.includes('权限') || errorMsg.includes('permission')) {
        message.warning('需要管理员权限，请以管理员身份运行')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleStop = async () => {
    setLoading(true)
    try {
      const response = await axios.post('/api/v1/proxy/stop')
      if (response.status === 200) {
        setIsRunning(false)
        message.success('代理服务已停止')
        setClientsCount(0)
        setTotalRequests(0)
      }
    } catch (error: any) {
      message.error(error.response?.data?.detail || '停止失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card
      title="代理服务控制"
      extra={
        <Space>
          <Badge
            status={isRunning ? 'processing' : 'default'}
            text={isRunning ? '运行中' : '已停止'}
          />
          <Button
            icon={<ReloadOutlined />}
            onClick={checkStatus}
            loading={statusLoading}
            size="small"
          >
            刷新状态
          </Button>
        </Space>
      }
    >
      {/* 状态统计 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={24} md={8} lg={8} xl={8}>
          <Card>
            <Statistic
              title="代理端口"
              value={config.port}
              prefix={<WifiOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={24} md={8} lg={8} xl={8}>
          <Card>
            <Statistic
              title="连接客户端"
              value={clientsCount}
              suffix="个"
            />
          </Card>
        </Col>
        <Col xs={24} sm={24} md={8} lg={8} xl={8}>
          <Card>
            <Statistic
              title="总请求数"
              value={totalRequests}
              suffix="次"
            />
          </Card>
        </Col>
      </Row>

      {/* 本机IP显示 */}
      {localIP && (
        <Alert
          message={`本机IP地址: ${localIP}`}
          description={`移动设备请配置代理为: ${localIP}:${config.port}`}
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      <Divider />

      {/* 配置表单 */}
      <Form
        form={form}
        layout="vertical"
        initialValues={config}
        onValuesChange={(_, allValues) => setConfig(allValues)}
      >
        <Row gutter={16}>
          <Col xs={24} sm={24} md={12} lg={12} xl={12}>
            <Form.Item
              label="代理端口"
              name="port"
              rules={[
                { required: true, message: '请输入端口号' },
                { type: 'number', min: 1, max: 65535, message: '端口范围: 1-65535' }
              ]}
            >
              <InputNumber
                style={{ width: '100%' }}
                min={1}
                max={65535}
                disabled={isRunning}
                placeholder="请输入端口号"
              />
            </Form.Item>
          </Col>
          <Col xs={24} sm={24} md={12} lg={12} xl={12}>
            <Form.Item
              label="系统代理"
              name="enable_system_proxy"
              valuePropName="checked"
              tooltip="启用后将自动设置系统代理（需要管理员权限）"
            >
              <Switch
                disabled={isRunning}
                checkedChildren="启用"
                unCheckedChildren="禁用"
              />
            </Form.Item>
          </Col>
        </Row>

        {/* HTTPS捕获说明 */}
        <Alert
          message="HTTPS 捕获说明"
          description={
            <div>
              <p>本系统默认支持HTTPS流量捕获，需要安装CA证书：</p>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li><strong>Windows:</strong> 在"证书管理"标签页点击"Windows 安装证书"</li>
                <li><strong>移动端:</strong> 在"移动端配置向导"标签页扫码下载并安装证书</li>
                <li><strong>macOS:</strong> 下载证书后添加到钥匙串并设置为"始终信任"</li>
              </ul>
              <p style={{ marginTop: 8, marginBottom: 0 }}>
                <strong>注意:</strong> 证书安装后即可自动捕获HTTPS流量，无需额外配置。
              </p>
            </div>
          }
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />
      </Form>

      {/* 操作按钮 */}
      <Space style={{ width: '100%', justifyContent: 'center' }}>
        {!isRunning ? (
          <Button
            type="primary"
            size="large"
            icon={<PlayCircleOutlined />}
            onClick={handleStart}
            loading={loading}
          >
            启动代理服务
          </Button>
        ) : (
          <Button
            danger
            size="large"
            icon={<PauseCircleOutlined />}
            onClick={handleStop}
            loading={loading}
          >
            停止代理服务
          </Button>
        )}
      </Space>

      {/* 提示信息 */}
      {!isRunning && (
        <Alert
          message="使用提示"
          description={
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              <li>启动代理后，可以抓取浏览器、桌面应用和移动设备的网络流量</li>
              <li>移动设备需要手动配置代理并安装证书</li>
              <li>Windows应用可能需要启用系统代理</li>
            </ul>
          }
          type="warning"
          showIcon
          style={{ marginTop: 16 }}
        />
      )}
    </Card>
  )
}

export default ProxyControl
