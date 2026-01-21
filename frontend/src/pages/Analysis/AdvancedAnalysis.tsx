import React, { useState } from 'react'
import {
  Card,
  Button,
  Space,
  Input,
  message,
  Tabs,
  Modal,
  Form,
  Select,
  Spin,
  Alert
} from 'antd'
import {
  CodeOutlined,
  ApartmentOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
  DownloadOutlined
} from '@ant-design/icons'
import axios from 'axios'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'

const { TextArea } = Input
const { Option } = Select
const { TabPane } = Tabs

interface AdvancedAnalysisProps {
  sessionId?: string
}

const AdvancedAnalysis: React.FC<AdvancedAnalysisProps> = ({ sessionId }) => {
  const [loading, setLoading] = useState(false)
  const [beautifiedCode, setBeautifiedCode] = useState('')
  const [dependencyGraph, setDependencyGraph] = useState<any>(null)
  const [signatureAnalysis, setSignatureAnalysis] = useState<any>(null)
  const [replayResult, setReplayResult] = useState<any>(null)
  const [jsCode, setJsCode] = useState('')
  const [requestId, setRequestId] = useState('')
  const [form] = Form.useForm()

  // JS美化
  const handleBeautifyJS = async () => {
    if (!jsCode.trim()) {
      message.warning('请输入JavaScript代码')
      return
    }

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/analysis/beautify-js', {
        code: jsCode
      })
      setBeautifiedCode(response.data.beautified_code || response.data.code)
      message.success('代码美化成功')
    } catch (error: any) {
      message.error(error.response?.data?.detail || '代码美化失败')
    } finally {
      setLoading(false)
    }
  }

  // 依赖分析
  const handleDependencyAnalysis = async () => {
    if (!sessionId) {
      message.warning('请先选择一个会话')
      return
    }

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/analysis/dependency-graph', {
        session_id: sessionId
      })
      setDependencyGraph(response.data)
      message.success('依赖分析完成')
    } catch (error: any) {
      message.error(error.response?.data?.detail || '依赖分析失败')
    } finally {
      setLoading(false)
    }
  }

  // 签名分析
  const handleSignatureAnalysis = async () => {
    if (!sessionId) {
      message.warning('请先选择一个会话')
      return
    }

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/analysis/signature-analysis', {
        session_id: sessionId
      })
      setSignatureAnalysis(response.data)
      message.success('签名分析完成')
    } catch (error: any) {
      message.error(error.response?.data?.detail || '签名分析失败')
    } finally {
      setLoading(false)
    }
  }

  // 重放验证
  const handleReplayValidate = async () => {
    if (!requestId.trim()) {
      message.warning('请输入请求ID')
      return
    }

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/analysis/replay-validate', {
        request_id: requestId
      })
      setReplayResult(response.data)
      message.success('重放验证完成')
    } catch (error: any) {
      message.error(error.response?.data?.detail || '重放验证失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Tabs defaultActiveKey="beautify">
      <TabPane
        tab={
          <span>
            <CodeOutlined />
            JS美化
          </span>
        }
        key="beautify"
      >
        <Card>
          <Space direction="vertical" style={{ width: '100%' }}>
            <Alert
              message="JavaScript代码美化"
              description="将压缩或混淆的JavaScript代码格式化为易读的形式"
              type="info"
              showIcon
            />
            <TextArea
              rows={10}
              placeholder="粘贴JavaScript代码..."
              value={jsCode}
              onChange={e => setJsCode(e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: '12px' }}
            />
            <Button
              type="primary"
              icon={<CodeOutlined />}
              onClick={handleBeautifyJS}
              loading={loading}
            >
              美化代码
            </Button>
            {beautifiedCode && (
              <div>
                <div style={{ marginBottom: 8, fontWeight: 'bold' }}>美化后的代码：</div>
                <SyntaxHighlighter
                  language="javascript"
                  style={vscDarkPlus}
                  showLineNumbers
                  customStyle={{ fontSize: '12px', maxHeight: '500px' }}
                >
                  {beautifiedCode}
                </SyntaxHighlighter>
              </div>
            )}
          </Space>
        </Card>
      </TabPane>

      <TabPane
        tab={
          <span>
            <ApartmentOutlined />
            依赖分析
          </span>
        }
        key="dependency"
      >
        <Card>
          <Space direction="vertical" style={{ width: '100%' }}>
            <Alert
              message="请求依赖关系分析"
              description="分析会话中请求之间的依赖关系，构建依赖图"
              type="info"
              showIcon
            />
            <Button
              type="primary"
              icon={<ApartmentOutlined />}
              onClick={handleDependencyAnalysis}
              loading={loading}
              disabled={!sessionId}
            >
              开始分析
            </Button>
            {dependencyGraph && (
              <div>
                <pre style={{ background: '#f5f5f5', padding: '16px', borderRadius: '4px' }}>
                  {JSON.stringify(dependencyGraph, null, 2)}
                </pre>
              </div>
            )}
          </Space>
        </Card>
      </TabPane>

      <TabPane
        tab={
          <span>
            <SafetyOutlined />
            签名分析
          </span>
        }
        key="signature"
      >
        <Card>
          <Space direction="vertical" style={{ width: '100%' }}>
            <Alert
              message="请求签名分析"
              description="分析请求中的签名算法和参数生成逻辑"
              type="info"
              showIcon
            />
            <Button
              type="primary"
              icon={<SafetyOutlined />}
              onClick={handleSignatureAnalysis}
              loading={loading}
              disabled={!sessionId}
            >
              开始分析
            </Button>
            {signatureAnalysis && (
              <div>
                <pre style={{ background: '#f5f5f5', padding: '16px', borderRadius: '4px' }}>
                  {JSON.stringify(signatureAnalysis, null, 2)}
                </pre>
              </div>
            )}
          </Space>
        </Card>
      </TabPane>

      <TabPane
        tab={
          <span>
            <ThunderboltOutlined />
            重放验证
          </span>
        }
        key="replay"
      >
        <Card>
          <Space direction="vertical" style={{ width: '100%' }}>
            <Alert
              message="请求重放验证"
              description="重放指定请求，验证签名和参数的有效性"
              type="info"
              showIcon
            />
            <Input
              placeholder="输入请求ID"
              value={requestId}
              onChange={e => setRequestId(e.target.value)}
            />
            <Button
              type="primary"
              icon={<ThunderboltOutlined />}
              onClick={handleReplayValidate}
              loading={loading}
            >
              开始重放
            </Button>
            {replayResult && (
              <div>
                <Alert
                  message={replayResult.success ? '重放成功' : '重放失败'}
                  description={replayResult.message || ''}
                  type={replayResult.success ? 'success' : 'error'}
                  showIcon
                  style={{ marginBottom: 16 }}
                />
                <pre style={{ background: '#f5f5f5', padding: '16px', borderRadius: '4px' }}>
                  {JSON.stringify(replayResult, null, 2)}
                </pre>
              </div>
            )}
          </Space>
        </Card>
      </TabPane>
    </Tabs>
  )
}

export default AdvancedAnalysis
