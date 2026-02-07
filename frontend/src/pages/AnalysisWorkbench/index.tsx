import React, { useCallback, useState, useEffect, useRef } from 'react';
import { Layout, Divider, message, Button, Space, Badge, Popconfirm, Alert, Tooltip, Select } from 'antd';
import { PlayCircleOutlined, PauseCircleOutlined, ReloadOutlined, RobotOutlined, FullscreenOutlined } from '@ant-design/icons';
import SessionSelector from './components/SessionSelector';
import RequestList from './components/RequestList';
import './index.css';

const { Content, Sider } = Layout;
const { Option } = Select;

export interface CrawlerSession {
  session_id: string;
  session_name: string;
  url: string;
  status: string;
  created_at: string;
  updated_at: string;
  total_requests: number;
  completed_requests: number;
  current_url?: string;
}

export interface RequestRecord {
  id: string;
  url: string;
  method: string;
  status: number;
  timestamp: number;
  response_size?: number;
  content_type?: string;
  session_id: string;
  resource_type?: string;
}

const AnalysisWorkbench: React.FC = () => {
  const [selectedSession, setSelectedSession] = useState<CrawlerSession | null>(null);
  const [sessions, setSessions] = useState<CrawlerSession[]>([]);
  const [requests, setRequests] = useState<RequestRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [recording, setRecording] = useState(false);
  const [recordingLoading, setRecordingLoading] = useState(false);
  const [terminalReady, setTerminalReady] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedAIModel, setSelectedAIModel] = useState<string>('qwen');
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // 支持的AI模型
  const aiModels = [
    { key: 'qwen', name: 'Qwen', command: 'qwen' },
    { key: 'codex', name: 'Codex', command: 'codex' },
    { key: 'claude', name: 'Claude', command: 'claude' },
    { key: 'gemini', name: 'Gemini', command: 'gemini' }
  ];

  // 加载所有爬虫会话
  const loadSessions = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/crawler/sessions');
      if (response.ok) {
        const data = await response.json();
        setSessions(data.sessions || []);
        
        // 自动选择第一个会话
        if (data.sessions?.length > 0) {
          setSelectedSession((prev) => prev ?? data.sessions[0]);
        }
      }
    } catch (error) {
      console.error('加载会话失败:', error);
      message.error('加载会话失败');
    } finally {
      setLoading(false);
    }
  }, []);

  // 加载指定会话的请求记录
  const loadSessionRequests = useCallback(async (sessionId: string) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/crawler/session/${sessionId}/requests?limit=1000`);
      if (response.ok) {
        const data = await response.json();
        setRequests(data.requests || []);
      }
    } catch (error) {
      console.error('加载请求记录失败:', error);
      message.error('加载请求记录失败');
    } finally {
      setLoading(false);
    }
  }, []);

  // 会话切换处理
  const handleSessionChange = (session: CrawlerSession) => {
    setSelectedSession(session);
    loadSessionRequests(session.session_id);
    // 检查会话状态，更新录制状态
    setRecording(session.status === 'running');
  };

  // 在终端中切换到当前会话
  const switchTerminalToSession = () => {
    if (!selectedSession || !terminalReady) {
      message.warning('请先选择会话并等待终端加载完成');
      return;
    }

    const currentModel = aiModels.find(m => m.key === selectedAIModel);
    const sessionPath = `data/sessions/${selectedSession.session_id}`;
    
    // 通过postMessage发送会话切换命令到iframe
    if (iframeRef.current?.contentWindow) {
      try {
        iframeRef.current.contentWindow.postMessage({
          type: 'switch-session',
          path: sessionPath,
          aiModel: selectedAIModel,
          aiCommand: currentModel?.command || 'qwen'
        }, '*');
        message.success(`已切换到会话: ${selectedSession.session_name}，使用模型: ${currentModel?.name}`);
      } catch (error) {
        console.error('切换会话失败:', error);
        message.error('切换会话失败');
      }
    }
  };

  // 切换全屏
  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  // 开始录制
  const handleStartRecording = async () => {
    if (!selectedSession) {
      message.warning('请先选择一个会话');
      return;
    }

    setRecordingLoading(true);
    try {
      const response = await fetch(`/api/v1/crawler/start-recording/${selectedSession.session_id}`, {
        method: 'POST'
      });

      if (response.ok) {
        const data = await response.json();
        message.success(data.message || '录制已开始');
        setRecording(true);
        // 刷新会话列表
        loadSessions();
      } else {
        const error = await response.json();
        message.error(error.detail || '开始录制失败');
      }
    } catch (error) {
      console.error('开始录制失败:', error);
      message.error('开始录制失败');
    } finally {
      setRecordingLoading(false);
    }
  };

  // 停止录制
  const handleStopRecording = async () => {
    if (!selectedSession) {
      message.warning('请先选择一个会话');
      return;
    }

    setRecordingLoading(true);
    try {
      const response = await fetch(`/api/v1/crawler/stop-recording/${selectedSession.session_id}`, {
        method: 'POST'
      });

      if (response.ok) {
        const data = await response.json();
        message.success(data.message || '录制已停止');
        setRecording(false);
        // 刷新会话列表和请求记录
        loadSessions();
        loadSessionRequests(selectedSession.session_id);
      } else {
        const error = await response.json();
        message.error(error.detail || '停止录制失败');
      }
    } catch (error) {
      console.error('停止录制失败:', error);
      message.error('停止录制失败');
    } finally {
      setRecordingLoading(false);
    }
  };

  // 刷新请求列表
  const handleRefreshRequests = () => {
    if (selectedSession) {
      loadSessionRequests(selectedSession.session_id);
    }
  };

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    if (selectedSession) {
      loadSessionRequests(selectedSession.session_id);
    }
  }, [selectedSession, loadSessionRequests]);

  return (
    <div className="analysis-workbench">
      <Layout style={{ height: '100vh' }}>
        <Sider width={400} className="workbench-sider">
          <div className="sider-content">
            <div className="session-section">
              <h3>爬虫会话</h3>
              <SessionSelector
                sessions={sessions}
                selectedSession={selectedSession}
                onSessionChange={handleSessionChange}
                loading={loading}
              />
            </div>
            
            <Divider />

            <div className="requests-section">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ margin: 0 }}>
                  请求记录
                  <Badge
                    count={requests.length}
                    style={{ marginLeft: 8, backgroundColor: '#52c41a' }}
                  />
                </h3>
                <Space>
                  <Button
                    icon={<ReloadOutlined />}
                    onClick={handleRefreshRequests}
                    loading={loading}
                    size="small"
                    disabled={!selectedSession}
                  >
                    刷新
                  </Button>
                  {recording ? (
                    <Popconfirm
                      title="确定要停止录制吗？"
                      description="停止后将无法继续录制当前会话"
                      onConfirm={handleStopRecording}
                      okText="确定"
                      cancelText="取消"
                    >
                      <Button
                        type="primary"
                        danger
                        icon={<PauseCircleOutlined />}
                        loading={recordingLoading}
                        disabled={!selectedSession}
                        size="small"
                      >
                        停止录制
                      </Button>
                    </Popconfirm>
                  ) : (
                    <Button
                      type="primary"
                      icon={<PlayCircleOutlined />}
                      onClick={handleStartRecording}
                      loading={recordingLoading}
                      disabled={!selectedSession}
                      size="small"
                    >
                      开始录制
                    </Button>
                  )}
                </Space>
              </div>
              <RequestList
                requests={requests}
                selectedSession={selectedSession}
                loading={loading}
              />
            </div>
          </div>
        </Sider>
        
        <Layout>
          <Content className="workbench-content">
            <div className="terminal-section" style={{ 
              height: isFullscreen ? '100vh' : '100%',
              position: isFullscreen ? 'fixed' : 'relative',
              top: isFullscreen ? 0 : 'auto',
              left: isFullscreen ? 0 : 'auto',
              right: isFullscreen ? 0 : 'auto',
              bottom: isFullscreen ? 0 : 'auto',
              zIndex: isFullscreen ? 1000 : 'auto',
              backgroundColor: '#fff'
            }}>
              <div style={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center',
                padding: '12px 16px',
                borderBottom: '1px solid #d9d9d9',
                backgroundColor: '#fafafa'
              }}>
                <Space>
                  <RobotOutlined style={{ fontSize: 18, color: '#1890ff' }} />
                  <h3 style={{ margin: 0 }}>AI 终端</h3>
                  {terminalReady && (
                    <Badge status="success" text="已连接" />
                  )}
                </Space>
                <Space>
                  <Select
                    value={selectedAIModel}
                    onChange={setSelectedAIModel}
                    style={{ width: 120 }}
                    size="small"
                  >
                    {aiModels.map(model => (
                      <Option key={model.key} value={model.key}>
                        <RobotOutlined /> {model.name}
                      </Option>
                    ))}
                  </Select>
                  <Tooltip title={`在当前会话中启动${aiModels.find(m => m.key === selectedAIModel)?.name}`}>
                    <Button
                      type="primary"
                      icon={<PlayCircleOutlined />}
                      onClick={switchTerminalToSession}
                      disabled={!selectedSession || !terminalReady}
                      size="small"
                    >
                      启动 {aiModels.find(m => m.key === selectedAIModel)?.name}
                    </Button>
                  </Tooltip>
                  <Tooltip title={isFullscreen ? "退出全屏" : "全屏"}>
                    <Button
                      icon={<FullscreenOutlined />}
                      onClick={toggleFullscreen}
                      size="small"
                    />
                  </Tooltip>
                </Space>
              </div>

              {!terminalReady && (
                <Alert
                  message="正在连接终端服务..."
                  description="请确保终端服务运行在 localhost:3001"
                  type="info"
                  showIcon
                  style={{ margin: 16 }}
                />
              )}

              <iframe
                ref={iframeRef}
                src="http://localhost:3001"
                style={{
                  width: '100%',
                  height: isFullscreen ? 'calc(100vh - 60px)' : 'calc(100% - 60px)',
                  border: 'none',
                  display: 'block'
                }}
                onLoad={() => {
                  setTerminalReady(true);
                  message.success('终端已连接');
                }}
                onError={() => {
                  setTerminalReady(false);
                  message.error('终端连接失败，请检查终端服务是否运行');
                }}
              />

              {selectedSession && terminalReady && (
                <div style={{
                  padding: '8px 16px',
                  borderTop: '1px solid #d9d9d9',
                  backgroundColor: '#fafafa',
                  fontSize: 12,
                  color: '#666'
                }}>
                  <Space split="|">
                    <span>当前会话: <strong>{selectedSession.session_name}</strong></span>
                    <span>会话路径: <code>data/sessions/{selectedSession.session_id}</code></span>
                    <span>提示: 点击"启动Qwen"按钮自动切换到当前会话</span>
                  </Space>
                </div>
              )}
            </div>
          </Content>
        </Layout>
      </Layout>
    </div>
  );
};

export default AnalysisWorkbench;
