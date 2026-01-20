import React from 'react'
import { Tabs, Row, Col } from 'antd'
import {
  ControlOutlined,
  MobileOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  UnorderedListOutlined
} from '@ant-design/icons'
import ProxyControl from './ProxyControl'
import MobileSetup from './MobileSetup'
import CertManager from './CertManager'
import DeviceList from './DeviceList'
import ProxyRequestList from './ProxyRequestList'

const ProxyCapture: React.FC = () => {
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
        defaultActiveKey="control"
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
