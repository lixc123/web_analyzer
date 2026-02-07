import React, { useEffect, useState } from 'react'
import { Tabs, Row, Col } from 'antd'
import {
  ControlOutlined,
  MobileOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  UnorderedListOutlined,
  MessageOutlined,
  WindowsOutlined,
  HistoryOutlined,
  DatabaseOutlined,
  CodeOutlined
} from '@ant-design/icons'
import ProxyControl from './ProxyControl'
import MobileSetup from './MobileSetup'
import CertManager from './CertManager'
import DeviceList from '@components/proxy/DeviceList'
import ProxyRequestList from './ProxyRequestList'
import ProxyWebSocket from './ProxyWebSocket'
import WindowsCaptureWizard from './WindowsCaptureWizard'
import ProxySessions from './ProxySessions'
import ProxyStorage from './ProxyStorage'
import ProxyJsInjection from './ProxyJsInjection'

const ProxyCapture: React.FC = () => {
  const [activeKey, setActiveKey] = useState('control')

  useEffect(() => {
    const handler = (e: any) => {
      const key = e?.detail?.key
      if (typeof key === 'string' && key) setActiveKey(key)
    }
    window.addEventListener('proxy-capture:switch-tab', handler as any)
    return () => window.removeEventListener('proxy-capture:switch-tab', handler as any)
  }, [])

  const items = [
    {
      key: 'control',
      label: (
        <span>
          <ControlOutlined />
          <span style={{ marginLeft: 8 }}>代理控制</span>
        </span>
      ),
      children: (
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={24} md={24} lg={24} xl={24}>
            <ProxyControl />
          </Col>
          <Col xs={24} sm={24} md={24} lg={24} xl={24}>
            <DeviceList />
          </Col>
        </Row>
      )
    },
    {
      key: 'requests',
      label: (
        <span>
          <UnorderedListOutlined />
          <span style={{ marginLeft: 8 }}>请求列表</span>
        </span>
      ),
      children: <ProxyRequestList />
    },
    {
      key: 'sessions',
      label: (
        <span>
          <HistoryOutlined />
          <span style={{ marginLeft: 8 }}>会话</span>
        </span>
      ),
      children: <ProxySessions />
    },
    {
      key: 'websocket',
      label: (
        <span>
          <MessageOutlined />
          <span style={{ marginLeft: 8 }}>WebSocket</span>
        </span>
      ),
      children: <ProxyWebSocket />
    },
    {
      key: 'js_injection',
      label: (
        <span>
          <CodeOutlined />
          <span style={{ marginLeft: 8 }}>JS 注入</span>
        </span>
      ),
      children: <ProxyJsInjection />
    },
    {
      key: 'storage',
      label: (
        <span>
          <DatabaseOutlined />
          <span style={{ marginLeft: 8 }}>存储/清理</span>
        </span>
      ),
      children: <ProxyStorage />
    },
    {
      key: 'windows',
      label: (
        <span>
          <WindowsOutlined />
          <span style={{ marginLeft: 8 }}>Windows 向导</span>
        </span>
      ),
      children: <WindowsCaptureWizard />
    },
    {
      key: 'mobile',
      label: (
        <span>
          <MobileOutlined />
          <span style={{ marginLeft: 8 }}>移动端配置</span>
        </span>
      ),
      children: <MobileSetup />
    },
    {
      key: 'cert',
      label: (
        <span>
          <SafetyCertificateOutlined />
          <span style={{ marginLeft: 8 }}>证书管理</span>
        </span>
      ),
      children: <CertManager />
    },
    {
      key: 'devices',
      label: (
        <span>
          <TeamOutlined />
          <span style={{ marginLeft: 8 }}>设备列表</span>
        </span>
      ),
      children: <DeviceList />
    }
  ]

  return (
    <div style={{ padding: '0', width: '100%', maxWidth: '100%', overflow: 'hidden' }}>
      <Tabs
        activeKey={activeKey}
        onChange={setActiveKey}
        items={items}
        size="large"
        tabBarStyle={{ marginBottom: 16 }}
        style={{ width: '100%' }}
        tabBarGutter={16}
      />
    </div>
  )
}

export default ProxyCapture
