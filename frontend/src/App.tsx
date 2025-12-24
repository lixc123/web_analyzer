import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from 'antd'
import { useGlobalStore } from '@store/GlobalStore'
import MainLayout from '@components/Layout/MainLayout'
import HomePage from '@pages/Home'
import CrawlerPage from '@pages/Crawler'
import AnalysisPage from '@pages/Analysis'
import AnalysisWorkbench from '@pages/AnalysisWorkbench'
import TerminalPage from '@pages/Terminal'
import SettingsPage from '@pages/Settings'
import { useWebSocket } from '@hooks/useWebSocket'

const App: React.FC = () => {
  const { theme } = useGlobalStore()

  // 初始化WebSocket连接
  useWebSocket()

  return (
    <Layout style={{ height: '100vh', overflow: 'hidden' }}>
      <Routes>
        {/* 主应用路由 */}
        <Route path="/" element={<MainLayout />}>
          <Route index element={<HomePage />} />
          <Route path="crawler" element={<CrawlerPage />} />
          <Route path="analysis" element={<AnalysisPage />} />
          <Route path="workbench" element={<AnalysisWorkbench />} />
          <Route path="terminal" element={<TerminalPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Layout>
  )
}

export default App
