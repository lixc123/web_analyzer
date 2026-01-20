/**
 * React错误边界组件
 * 捕获组件树中的JavaScript错误，记录错误并显示降级UI
 */

import React, { Component, ErrorInfo, ReactNode } from 'react'
import { Result, Button, Typography, Collapse, Space } from 'antd'
import { BugOutlined, ReloadOutlined, HomeOutlined } from '@ant-design/icons'
import { createErrorBoundaryHandler, getErrorLogs, exportErrorLogs } from '@/utils/errorHandler'

const { Paragraph, Text } = Typography
const { Panel } = Collapse

interface Props {
  children: ReactNode
  fallback?: ReactNode
  onError?: (error: Error, errorInfo: ErrorInfo) => void
  showDetails?: boolean
  componentName?: string
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
  errorCount: number
}

/**
 * 错误边界组件
 * 用法:
 * <ErrorBoundary>
 *   <YourComponent />
 * </ErrorBoundary>
 */
class ErrorBoundary extends Component<Props, State> {
  private errorHandler: ReturnType<typeof createErrorBoundaryHandler>

  constructor(props: Props) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorCount: 0
    }

    this.errorHandler = createErrorBoundaryHandler(props.componentName || 'Unknown')
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error
    }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // 记录错误
    this.errorHandler(error, errorInfo)

    // 更新状态
    this.setState(prevState => ({
      errorInfo,
      errorCount: prevState.errorCount + 1
    }))

    // 调用自定义错误处理
    if (this.props.onError) {
      this.props.onError(error, errorInfo)
    }

    // 如果错误频繁发生，可能需要采取更激进的措施
    if (this.state.errorCount > 5) {
      console.error('Too many errors occurred. Consider reloading the page.')
    }
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    })
  }

  handleReload = () => {
    window.location.reload()
  }

  handleGoHome = () => {
    window.location.href = '/'
  }

  handleDownloadLogs = () => {
    const logs = exportErrorLogs()
    const blob = new Blob([logs], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `error-logs-${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  render() {
    if (this.state.hasError) {
      // 如果提供了自定义fallback，使用它
      if (this.props.fallback) {
        return this.props.fallback
      }

      const { error, errorInfo } = this.state
      const showDetails = this.props.showDetails !== false

      return (
        <div style={{ padding: '50px 20px', maxWidth: '800px', margin: '0 auto' }}>
          <Result
            status="error"
            icon={<BugOutlined />}
            title="页面出现错误"
            subTitle="抱歉，页面遇到了一些问题。您可以尝试刷新页面或返回首页。"
            extra={[
              <Space key="actions" size="middle">
                <Button type="primary" icon={<ReloadOutlined />} onClick={this.handleReload}>
                  刷新页面
                </Button>
                <Button icon={<HomeOutlined />} onClick={this.handleGoHome}>
                  返回首页
                </Button>
                <Button onClick={this.handleReset}>
                  重试
                </Button>
              </Space>
            ]}
          >
            {showDetails && error && (
              <div style={{ textAlign: 'left', marginTop: 24 }}>
                <Collapse ghost>
                  <Panel header="错误详情" key="1">
                    <Paragraph>
                      <Text strong>错误信息:</Text>
                      <br />
                      <Text code>{error.toString()}</Text>
                    </Paragraph>

                    {error.stack && (
                      <Paragraph>
                        <Text strong>错误堆栈:</Text>
                        <pre style={{
                          background: '#f5f5f5',
                          padding: '12px',
                          borderRadius: '4px',
                          overflow: 'auto',
                          maxHeight: '200px',
                          fontSize: '12px'
                        }}>
                          {error.stack}
                        </pre>
                      </Paragraph>
                    )}

                    {errorInfo?.componentStack && (
                      <Paragraph>
                        <Text strong>组件堆栈:</Text>
                        <pre style={{
                          background: '#f5f5f5',
                          padding: '12px',
                          borderRadius: '4px',
                          overflow: 'auto',
                          maxHeight: '200px',
                          fontSize: '12px'
                        }}>
                          {errorInfo.componentStack}
                        </pre>
                      </Paragraph>
                    )}

                    <Button
                      size="small"
                      onClick={this.handleDownloadLogs}
                      style={{ marginTop: 12 }}
                    >
                      下载错误日志
                    </Button>
                  </Panel>
                </Collapse>
              </div>
            )}
          </Result>
        </div>
      )
    }

    return this.props.children
  }
}

/**
 * 高阶组件：为组件添加错误边界
 */
export function withErrorBoundary<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  errorBoundaryProps?: Omit<Props, 'children'>
) {
  const displayName = WrappedComponent.displayName || WrappedComponent.name || 'Component'

  const ComponentWithErrorBoundary = (props: P) => (
    <ErrorBoundary {...errorBoundaryProps} componentName={displayName}>
      <WrappedComponent {...props} />
    </ErrorBoundary>
  )

  ComponentWithErrorBoundary.displayName = `withErrorBoundary(${displayName})`

  return ComponentWithErrorBoundary
}

/**
 * Hook：在函数组件中使用错误处理
 */
export function useErrorHandler() {
  const [error, setError] = React.useState<Error | null>(null)

  React.useEffect(() => {
    if (error) {
      throw error
    }
  }, [error])

  return setError
}

export default ErrorBoundary
