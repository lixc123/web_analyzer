import React, { useState, useEffect, useRef } from 'react';
import { Card, Select, Button, message, Spin, Alert, Space, Typography } from 'antd';
import { PlayCircleOutlined, ReloadOutlined, RobotOutlined } from '@ant-design/icons';

const { Option } = Select;
const { Text } = Typography;

interface Session {
  name: string;
  description: string;
  path: string;
  type: string;
}

interface AIModel {
  key: string;
  name: string;
  description: string;
  command: string;
  icon?: string;
}

const Terminal: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSession, setSelectedSession] = useState<string>('');
  const [selectedModel, setSelectedModel] = useState<string>('qwen');
  const [loading, setLoading] = useState(true);
  const [terminalReady, setTerminalReady] = useState(false);
  const [status, setStatus] = useState('正在连接...');
  const [error, setError] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // 支持的AI模型配置
  const aiModels: AIModel[] = [
    {
      key: 'qwen',
      name: 'Qwen',
      description: '通义千问 - 阿里云大语言模型',
      command: 'qwen'
    },
    {
      key: 'codex',
      name: 'Codex',
      description: 'OpenAI Codex - 专业代码生成模型',
      command: 'codex'
    },
    {
      key: 'claude',
      name: 'Claude',
      description: 'Anthropic Claude - 安全可靠的AI助手',
      command: 'claude'
    },
    {
      key: 'gemini',
      name: 'Gemini',
      description: 'Google Gemini - 多模态AI模型',
      command: 'gemini'
    }
  ];

  // 加载会话列表
  const loadSessions = async () => {
    try {
      const response = await fetch('/api/v1/terminal/sessions');
      if (!response.ok) throw new Error('Failed to load sessions');
      
      const sessionData = await response.json();
      setSessions(sessionData);
      
      if (sessionData.length > 0) {
        setSelectedSession(sessionData[0].path);
      }
    } catch (err) {
      console.error('加载会话失败:', err);
      message.error('加载会话列表失败');
      setError('无法加载会话列表');
    }
  };

  // 检查终端服务是否可用
  const checkTerminalService = async () => {
    try {
      const response = await fetch('http://localhost:3001/health');
      return response.ok;
    } catch {
      return false;
    }
  };

  // 加载终端iframe
  const loadTerminal = () => {
    setLoading(true);
    setError(null);
    setStatus('正在连接终端服务...');

    const iframe = iframeRef.current;
    if (!iframe) return;

    const handleLoad = () => {
      setLoading(false);
      setTerminalReady(true);
      setStatus('终端已连接');
    };

    const handleError = () => {
      setLoading(false);
      setTerminalReady(false);
      setStatus('连接失败');
      setError('无法连接到终端服务，请确保Node.js终端服务在端口3000运行');
    };

    // 设置超时检查
    const timeout = setTimeout(() => {
      if (!terminalReady) {
        handleError();
      }
    }, 5000);

    iframe.onload = () => {
      clearTimeout(timeout);
      handleLoad();
    };

    iframe.onerror = () => {
      clearTimeout(timeout);
      handleError();
    };

    // 刷新iframe
    iframe.src = 'http://localhost:3001';
  };

  // 切换会话和AI模型
  const switchToSession = () => {
    if (!selectedSession || !terminalReady) return;

    const currentModel = aiModels.find(m => m.key === selectedModel);
    setStatus(`正在切换会话并启动${currentModel?.name}...`);
    message.info(`正在切换到会话: ${selectedSession}, 使用模型: ${currentModel?.name}`);

    // 通过postMessage发送会话切换命令到iframe
    if (iframeRef.current?.contentWindow) {
      try {
        iframeRef.current.contentWindow.postMessage({
          type: 'switch-session',
          path: selectedSession,
          aiModel: selectedModel,
          aiCommand: currentModel?.command || 'qwen'
        }, '*');
        
        setTimeout(() => {
          setStatus(`已切换到: ${sessions.find(s => s.path === selectedSession)?.name || selectedSession} (${currentModel?.name})`);
        }, 2000);
      } catch (err) {
        console.error('发送切换命令失败:', err);
        message.error('切换会话失败');
      }
    }
  };

  // 重试连接
  const retryConnection = async () => {
    setStatus('正在检查服务...');
    const serviceAvailable = await checkTerminalService();
    
    if (serviceAvailable) {
      loadTerminal();
    } else {
      setError('终端服务不可用，请启动Node.js终端服务');
      setStatus('服务不可用');
    }
  };

  useEffect(() => {
    loadSessions();
    
    // 延迟加载终端，确保DOM准备好
    const timer = setTimeout(() => {
      loadTerminal();
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  // 定期检查服务状态
  useEffect(() => {
    const interval = setInterval(async () => {
      if (!terminalReady) {
        const serviceAvailable = await checkTerminalService();
        if (serviceAvailable) {
          loadTerminal();
        }
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [terminalReady]);

  return (
    <div className="terminal-page" style={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      {/* 控制面板 */}
      <Card 
        style={{ 
          margin: 0, 
          borderRadius: 0, 
          borderBottom: '1px solid #d9d9d9',
          backgroundColor: '#fafafa'
        }}
        bodyStyle={{ padding: '12px 16px' }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '16px', flexWrap: 'wrap' }}>
          <Space size="middle" align="start">
            <div>
              <Text strong style={{ display: 'block', marginBottom: '4px' }}>AI模型:</Text>
              <Select
                value={selectedModel}
                onChange={setSelectedModel}
                style={{ minWidth: '200px' }}
                placeholder="选择AI模型"
                size="middle"
              >
                {aiModels.map((model) => (
                  <Option key={model.key} value={model.key}>
                    <div style={{ fontWeight: 600, color: '#1890ff' }}>
                      <RobotOutlined /> {model.name}
                    </div>
                  </Option>
                ))}
              </Select>
            </div>
            
            <div>
              <Text strong style={{ display: 'block', marginBottom: '4px' }}>选择会话:</Text>
          
              <Select
                value={selectedSession}
                onChange={setSelectedSession}
                style={{ minWidth: '400px' }}
                placeholder="搜索或选择爬虫会话..."
                loading={sessions.length === 0}
                showSearch
                size="middle"
                filterOption={(input, option) => {
                  const session = sessions.find(s => s.path === option?.value);
                  if (!session) return false;
                  return (
                    session.name.toLowerCase().includes(input.toLowerCase()) ||
                    session.description.toLowerCase().includes(input.toLowerCase()) ||
                    session.path.toLowerCase().includes(input.toLowerCase())
                  );
                }}
                optionLabelProp="label"
              >
                {sessions.map((session) => (
                  <Option 
                    key={session.path} 
                    value={session.path}
                    label={session.name}
                  >
                    <div style={{ fontWeight: 600, color: session.type === 'crawler_session' ? '#52c41a' : '#666' }}>
                      {session.name}
                    </div>
                  </Option>
                ))}
              </Select>
            </div>
          </Space>
          
          <Button
            type="primary"
            icon={<PlayCircleOutlined />}
            onClick={switchToSession}
            disabled={!terminalReady || !selectedSession}
            size="middle"
          >
            启动 {aiModels.find(m => m.key === selectedModel)?.name || 'AI'}
          </Button>
          
          <Button
            icon={<ReloadOutlined />}
            onClick={retryConnection}
            disabled={loading}
            size="middle"
          >
            重新连接
          </Button>
          
          <div style={{ marginLeft: 'auto', alignSelf: 'center', color: '#666', fontSize: '12px' }}>
            <div>状态: {status}</div>
          </div>
        </div>
      </Card>

      {/* 终端容器 */}
      <div style={{ flex: 1, position: 'relative', backgroundColor: '#000' }}>
        {loading && (
          <div
            style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              zIndex: 1000,
              textAlign: 'center',
              color: '#4a9eff'
            }}
          >
            <Spin size="large" />
            <div style={{ marginTop: 16, fontSize: 16 }}>正在连接终端服务...</div>
            <div style={{ marginTop: 8, fontSize: 12, opacity: 0.7 }}>
              Node.js 终端服务: localhost:3000
            </div>
          </div>
        )}

        {error && !loading && (
          <div
            style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              zIndex: 1000,
              textAlign: 'center'
            }}
          >
            <Alert
              message="终端连接失败"
              description={error}
              type="error"
              showIcon
              action={
                <Button size="small" danger onClick={retryConnection}>
                  重试连接
                </Button>
              }
            />
          </div>
        )}

        <iframe
          ref={iframeRef}
          style={{
            width: '100%',
            height: '100%',
            border: 'none',
            backgroundColor: '#1a1a1a',
            display: loading || error ? 'none' : 'block'
          }}
          title="Terminal"
        />
      </div>
    </div>
  );
};

export default Terminal;
