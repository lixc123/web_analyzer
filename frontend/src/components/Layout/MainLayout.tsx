import React, { useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Layout,
  Menu,
  Button,
  Avatar,
  Dropdown,
  Badge,
  Space,
  Typography,
  theme
} from 'antd'
import {
  MenuUnfoldOutlined,
  MenuFoldOutlined,
  HomeOutlined,
  BugOutlined,
  BarChartOutlined,
  RobotOutlined,
  CodeOutlined,
  SettingOutlined,
  UserOutlined,
  LogoutOutlined,
  BellOutlined,
  FullscreenOutlined,
  FullscreenExitOutlined
} from '@ant-design/icons'
import { useGlobalStore, useWebSocketStatus, useSystemStatus } from '@store/GlobalStore'
import LoginModal from '@components/Auth/LoginModal'
import { useAuth } from '@components/Auth/AuthProvider'

const { Header, Sider, Content } = Layout
const { Title, Text } = Typography

const MainLayout: React.FC = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [fullscreen, setFullscreen] = useState(false)
  const [showLoginModal, setShowLoginModal] = useState(false)

  const { isAuthenticated, user, logout } = useAuth()
  
  const {
    sidebarCollapsed,
    setSidebarCollapsed,
    theme: currentTheme,
    setTheme
  } = useGlobalStore()
  
  const wsConnected = useWebSocketStatus()
  const systemStatus = useSystemStatus()
  
  const { token } = theme.useToken()

  // 菜单项配置
  const menuItems = [
    {
      key: '/',
      icon: <HomeOutlined />,
      label: '首页',
      title: '系统概览'
    },
    {
      key: '/crawler',
      icon: <BugOutlined />,
      label: '网络爬虫',
      title: '网络流量录制'
    },
    {
      key: '/analysis',
      icon: <BarChartOutlined />,
      label: '数据分析',
      title: '流量数据分析'
    },
    {
      key: '/terminal',
      icon: <CodeOutlined />,
      label: 'Qwen终端',
      title: 'Qwen代码助手终端'
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: '系统设置',
      title: '系统配置'
    }
  ]

  // 用户菜单
  const userMenuItems = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: '个人资料',
    },
    {
      key: 'auth',
      icon: <UserOutlined />,
      label: isAuthenticated ? '认证/切换登录' : '登录',
      onClick: () => setShowLoginModal(true)
    },
    {
      key: 'theme',
      icon: <SettingOutlined />,
      label: `切换到${currentTheme === 'light' ? '暗色' : '亮色'}主题`,
      onClick: () => setTheme(currentTheme === 'light' ? 'dark' : 'light')
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: '退出登录',
      danger: true,
      onClick: async () => {
        if (!isAuthenticated) {
          return
        }
        await logout()
      }
    }
  ]

  const handleMenuClick = ({ key }: { key: string }) => {
    navigate(key)
  }

  const toggleFullscreen = () => {
    if (!fullscreen) {
      document.documentElement.requestFullscreen?.()
      setFullscreen(true)
    } else {
      document.exitFullscreen?.()
      setFullscreen(false)
    }
  }

  // 系统状态指示器
  const renderSystemStatus = () => {
    const getStatusColor = (status: string) => {
      switch (status) {
        case 'healthy': return '#52c41a'
        case 'unhealthy': return '#f5222d'
        default: return '#faad14'
      }
    }

    return (
      <Space size="small">
        <Badge 
          color={getStatusColor(systemStatus.backend)} 
          text="Backend"
          title={`后端状态: ${systemStatus.backend}`}
        />
      </Space>
    )
  }

  return (
    <Layout style={{ height: '100vh', overflow: 'hidden' }}>
      {/* 侧边栏 */}
      <Sider 
        trigger={null} 
        collapsible 
        collapsed={sidebarCollapsed}
        style={{
          height: '100vh',
          position: 'sticky',
          top: 0,
          overflow: 'auto',
          background: token.colorBgContainer,
          borderRight: `1px solid ${token.colorBorder}`
        }}
      >
        {/* Logo区域 */}
        <div 
          style={{ 
            height: 64, 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            borderBottom: `1px solid ${token.colorBorder}`,
            background: token.colorBgContainer
          }}
        >
          {!sidebarCollapsed ? (
            <Title level={4} style={{ margin: 0, color: token.colorPrimary }}>
              Web Analyzer
            </Title>
          ) : (
            <Avatar 
              size="large" 
              style={{ backgroundColor: token.colorPrimary }}
            >
              WA
            </Avatar>
          )}
        </div>

        {/* 菜单 */}
        <Menu
          theme={currentTheme === 'dark' ? 'dark' : 'light'}
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={handleMenuClick}
          style={{ 
            borderRight: 'none',
            background: 'transparent'
          }}
        />
      </Sider>

      {/* 主内容区域 */}
      <Layout style={{ height: '100vh', overflow: 'hidden' }}>
        {/* 顶部导航栏 */}
        <Header 
          style={{ 
            padding: '0 24px', 
            background: token.colorBgContainer,
            borderBottom: `1px solid ${token.colorBorder}`,
            height: 64,
            lineHeight: 'normal',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            position: 'sticky',
            top: 0,
            zIndex: 10,
          }}
        >
          {/* 左侧：折叠按钮和页面标题 */}
          <Space>
            <Button
              type="text"
              icon={sidebarCollapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              style={{
                fontSize: '16px',
                width: 40,
                height: 40,
              }}
            />
            
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                minHeight: 40,
              }}
            >
              <Title 
                level={4} 
                style={{
                  margin: 0,
                  color: token.colorText,
                  lineHeight: 1.15,
                  whiteSpace: 'nowrap',
                }}
              >
                {menuItems.find(item => item.key === location.pathname)?.title || '首页'}
              </Title>
              <Text
                type="secondary"
                style={{
                  fontSize: '12px',
                  lineHeight: 1.15,
                  marginTop: 2,
                  whiteSpace: 'nowrap',
                }}
              >
                现代化网络流量分析平台
              </Text>
            </div>
          </Space>

          {/* 右侧：状态指示器和用户菜单 */}
          <Space>
            {/* WebSocket连接状态 */}
            <Badge 
              status={wsConnected ? "success" : "error"}
              text={wsConnected ? "已连接" : "已断开"}
              title="WebSocket连接状态"
            />

            {/* 系统状态 */}
            {renderSystemStatus()}

            {/* 通知按钮 */}
            <Button
              type="text"
              icon={<BellOutlined />}
              size="large"
            />

            {/* 全屏切换 */}
            <Button
              type="text"
              icon={fullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
              onClick={toggleFullscreen}
              size="large"
            />

            {/* 用户菜单 */}
            <Dropdown 
              menu={{ items: userMenuItems as any }}
              placement="bottomRight"
            >
              <Button type="text" style={{ height: 'auto', padding: '4px 8px' }}>
                <Space>
                  <Avatar 
                    size="small" 
                    icon={<UserOutlined />}
                    style={{ backgroundColor: token.colorPrimary }}
                  />
                  <Text>{user?.name || (isAuthenticated ? '已登录' : '未登录')}</Text>
                </Space>
              </Button>
            </Dropdown>
          </Space>
        </Header>

        {/* 主内容区 */}
        <Content
          style={{
            margin: '16px',
            padding: 0,
            background: 'transparent',
            overflow: 'auto',
            flex: 1,
            minHeight: 0,
          }}
        >
          <Outlet />
        </Content>
      </Layout>

      <LoginModal
        visible={showLoginModal}
        onClose={() => setShowLoginModal(false)}
      />
    </Layout>
  )
}

export default MainLayout
