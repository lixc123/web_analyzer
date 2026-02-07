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
import ProxyCapturePage from '@pages/ProxyCapture'
import NativeHookPage from '@pages/NativeHook'
import CodeGeneratorPage from '@pages/CodeGenerator'
import RequestRecorderPage from '@pages/RequestRecorder'
import { useWebSocket } from '@hooks/useWebSocket'
import ErrorBoundary from '@components/ErrorBoundary'

const App: React.FC = () => {
  const { theme } = useGlobalStore()

  // 初始化WebSocket连接
  useWebSocket()

  return (
    <ErrorBoundary componentName="App">
      <Layout style={{ height: '100vh', overflow: 'hidden' }}>
        <Routes>
          {/* 主应用路由 */}
          <Route path="/" element={<MainLayout />}>
            <Route index element={
              <ErrorBoundary componentName="HomePage">
                <HomePage />
              </ErrorBoundary>
            } />
            <Route path="crawler" element={
              <ErrorBoundary componentName="CrawlerPage">
                <CrawlerPage />
              </ErrorBoundary>
            } />
            <Route path="proxy-capture" element={
              <ErrorBoundary componentName="ProxyCapturePage">
                <ProxyCapturePage />
              </ErrorBoundary>
            } />
            <Route path="native-hook" element={
              <ErrorBoundary componentName="NativeHookPage">
                <NativeHookPage />
              </ErrorBoundary>
            } />
            <Route path="analysis" element={
              <ErrorBoundary componentName="AnalysisPage">
                <AnalysisPage />
              </ErrorBoundary>
            } />
            <Route path="workbench" element={
              <ErrorBoundary componentName="AnalysisWorkbench">
                <AnalysisWorkbench />
              </ErrorBoundary>
            } />
            <Route path="code-generator" element={
              <ErrorBoundary componentName="CodeGeneratorPage">
                <CodeGeneratorPage />
              </ErrorBoundary>
            } />
            <Route path="request-recorder" element={
              <ErrorBoundary componentName="RequestRecorderPage">
                <RequestRecorderPage />
              </ErrorBoundary>
            } />
            <Route path="terminal" element={
              <ErrorBoundary componentName="TerminalPage">
                <TerminalPage />
              </ErrorBoundary>
            } />
            {/* Backward-compatible alias */}
            <Route path="ai" element={<Navigate to="/terminal" replace />} />
            <Route path="settings" element={
              <ErrorBoundary componentName="SettingsPage">
                <SettingsPage />
              </ErrorBoundary>
            } />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </Layout>
    </ErrorBoundary>
  )
}

export default App
