import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider, theme as antTheme, App as AntApp, notification } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'

import App from './App'
import { GlobalProvider, useGlobalStore } from './store/GlobalStore'
import { AuthProvider } from './components/Auth/AuthProvider'
import './styles/global.css'

// 设置dayjs中文
dayjs.locale('zh-cn')

// 创建Query客户端
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5分钟
      gcTime: 10 * 60 * 1000, // 10分钟 (React Query v5更名为gcTime)
    },
    mutations: {
      retry: 1,
    },
  },
})

// 动态主题配置组件
const ThemedApp: React.FC = () => {
  const { theme: currentTheme } = useGlobalStore()

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', currentTheme)
  }, [currentTheme])

  // 动态主题配置
  const themeConfig = {
    algorithm: currentTheme === 'dark' ? antTheme.darkAlgorithm : antTheme.defaultAlgorithm,
    token: {
      colorPrimary: '#1890ff',
      colorSuccess: '#52c41a',
      colorWarning: '#faad14',
      colorError: '#f5222d',
      borderRadius: 6,
      fontSize: 14,
      // 暗色模式下的全局token配置
      ...(currentTheme === 'dark' && {
        colorBgContainer: '#141414',
        colorBgElevated: '#1f1f1f',
        colorBgLayout: '#000000',
        colorBorder: '#303030',
        colorBorderSecondary: '#303030',
        colorFill: '#1f1f1f',
        colorFillSecondary: '#262626',
        colorFillTertiary: '#262626',
        colorFillQuaternary: '#262626',
        colorBgMask: 'rgba(0, 0, 0, 0.45)',
        colorTextBase: '#fff',
        colorText: 'rgba(255, 255, 255, 0.88)',
        colorTextSecondary: 'rgba(255, 255, 255, 0.65)',
        colorTextTertiary: 'rgba(255, 255, 255, 0.45)',
        colorTextQuaternary: 'rgba(255, 255, 255, 0.25)',
      }),
    },
    components: {
      Layout: {
        headerBg: currentTheme === 'dark' ? '#001529' : '#ffffff',
        siderBg: currentTheme === 'dark' ? '#001529' : '#ffffff',
        bodyBg: currentTheme === 'dark' ? '#141414' : '#f0f2f5',
      },
      Menu: {
        darkItemBg: '#001529',
        darkSubMenuItemBg: '#000c17',
      },
      Card: {
        ...(currentTheme === 'dark' && {
          colorBgContainer: '#141414',
          colorBorderSecondary: '#303030',
        }),
      },
      Table: {
        ...(currentTheme === 'dark' && {
          colorBgContainer: '#141414',
          headerBg: '#1f1f1f',
          headerColor: 'rgba(255, 255, 255, 0.88)',
          rowHoverBg: '#262626',
        }),
      },
      Input: {
        ...(currentTheme === 'dark' && {
          colorBgContainer: '#141414',
          colorBorder: '#303030',
          activeBorderColor: '#1890ff',
          hoverBorderColor: '#40a9ff',
        }),
      },
      Form: {
        ...(currentTheme === 'dark' && {
          labelColor: 'rgba(255, 255, 255, 0.88)',
        }),
      },
      Drawer: {
        ...(currentTheme === 'dark' && {
          colorBgElevated: '#141414',
          colorBgMask: 'rgba(0, 0, 0, 0.45)',
        }),
      },
      Modal: {
        ...(currentTheme === 'dark' && {
          contentBg: '#141414',
          headerBg: '#141414',
          footerBg: '#141414',
        }),
      },
    },
  }

  return (
    <ConfigProvider locale={zhCN} theme={themeConfig}>
      <AntApp>
        <App />
      </AntApp>
    </ConfigProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter 
        future={{
          v7_startTransition: true,
          v7_relativeSplatPath: true
        }}
      >
        <GlobalProvider>
          <AuthProvider>
            <ThemedApp />
          </AuthProvider>
        </GlobalProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
)
