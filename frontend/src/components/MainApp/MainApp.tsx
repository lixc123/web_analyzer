import React, { useState, useEffect } from 'react';
import { Layout, Space, Typography, Button, Badge, Card, message } from 'antd';
import { 
  LoginOutlined, 
  LogoutOutlined, 
  UserOutlined, 
  SettingOutlined,
  DashboardOutlined,
  MessageOutlined 
} from '@ant-design/icons';
import { useAuth, AuthType } from '../Auth/AuthProvider';
import LoginModal from '../Auth/LoginModal';
import ModelSwitcher from '../ModelSwitcher/ModelSwitcher';
import CommandInput from '../CommandSystem/CommandInput';

const { Header, Content, Sider } = Layout;
const { Title, Text } = Typography;

interface ChatMessage {
  id: string;
  content: string;
  type: 'user' | 'assistant' | 'system' | 'command';
  timestamp: Date;
  model?: string;
  tokens?: number;
}

export const MainApp: React.FC = () => {
  const { 
    isAuthenticated, 
    authType, 
    user, 
    quota, 
    logout 
  } = useAuth();

  const [showLoginModal, setShowLoginModal] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [currentModel, setCurrentModel] = useState('coder-model');
  const [sessionStats, setSessionStats] = useState({
    messages: 0,
    tokens: 0,
    requests: 0
  });

  // 初始化检查认证状态
  useEffect(() => {
    if (!isAuthenticated) {
      setShowLoginModal(true);
    }
  }, [isAuthenticated]);

  // 处理命令执行
  const handleCommand = async (command: string, args: string[]) => {
    const commandMessage: ChatMessage = {
      id: Date.now().toString(),
      content: `/${command} ${args.join(' ')}`,
      type: 'command',
      timestamp: new Date()
    };

    setChatMessages(prev => [...prev, commandMessage]);

    try {
      let result;
      
      switch (command) {
        case 'clear':
          setChatMessages([]);
          result = { message: '[OK] 会话历史已清除' };
          break;
          
        case 'stats':
          result = {
            message: '[STAT] 会话统计信息',
            data: {
              ...sessionStats,
              authType: authType,
              currentModel: currentModel,
              quota: quota
            }
          };
          break;
          
        case 'model':
          if (args[0]) {
            setCurrentModel(args[0]);
            result = { message: `[OK] 已切换到模型: ${args[0]}` };
          } else {
            result = { message: `当前模型: ${currentModel}` };
          }
          break;
          
        case 'auth':
          setShowLoginModal(true);
          result = { message: '打开认证设置' };
          break;
          
        case 'help':
          result = {
            message: 'Web Analyzer 帮助',
            data: {
              commands: [
                '/clear - 清除会话历史',
                '/stats - 显示会话统计',
                '/model <name> - 切换模型',
                '/auth - 认证设置',
                '/help - 显示此帮助'
              ]
            }
          };
          break;
          
        default:
          // 调用后端API处理其他命令
          {
            const response = await fetch('/api/v1/commands/execute', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                command,
                args,
                session_id: 'current'
              })
            });
            result = await response.json();
          }
          break;
      }

      const responseMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        content: result.message || '命令执行完成',
        type: 'system',
        timestamp: new Date()
      };

      setChatMessages(prev => [...prev, responseMessage]);
      
    } catch (error) {
      message.error(`命令执行失败: ${error}`);
      
      const errorMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        content: `[FAIL] 命令执行失败: ${error}`,
        type: 'system',
        timestamp: new Date()
      };

      setChatMessages(prev => [...prev, errorMessage]);
    }
  };

  // 处理普通消息
  const handleMessage = async (messageContent: string) => {
    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      content: messageContent,
      type: 'user',
      timestamp: new Date(),
      model: currentModel
    };

    setChatMessages(prev => [...prev, userMessage]);

    try {
      // AI功能已移除，显示占位符消息
      const assistantMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        content: 'AI功能已被移除。此应用现在专注于网络流量录制和分析。',
        type: 'assistant',
        timestamp: new Date(),
        model: currentModel,
        tokens: 0
      };

      setChatMessages(prev => [...prev, assistantMessage]);

      // 更新统计信息
      setSessionStats(prev => ({
        messages: prev.messages + 1,
        tokens: prev.tokens + 0, // AI功能已移除，tokens为0
        requests: prev.requests + 1
      }));

    } catch (error) {
      message.error(`发送消息失败: ${error}`);
      
      const errorMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        content: `[FAIL] 发送失败: ${error}`,
        type: 'system',
        timestamp: new Date()
      };

      setChatMessages(prev => [...prev, errorMessage]);
    }
  };

  // 处理登录
  const handleLogin = () => {
    setShowLoginModal(false);
    message.success('登录成功！');
  };

  // 处理登出
  const handleLogout = async () => {
    await logout();
    setChatMessages([]);
    setSessionStats({ messages: 0, tokens: 0, requests: 0 });
    message.info('已退出登录');
  };

  // 渲染用户信息
  const renderUserInfo = () => {
    if (!isAuthenticated) {
      return (
        <Button 
          type="primary" 
          icon={<LoginOutlined />}
          onClick={() => setShowLoginModal(true)}
        >
          登录
        </Button>
      );
    }

    return (
      <Space>
        <Badge count={quota?.used || 0} overflowCount={9999} color="blue">
          <UserOutlined style={{ fontSize: 16 }} />
        </Badge>
        <Text>{user?.name || '用户'}</Text>
        <Button 
          size="small" 
          icon={<LogoutOutlined />}
          onClick={handleLogout}
        >
          退出
        </Button>
      </Space>
    );
  };

  // 渲染消息
  const renderMessage = (msg: ChatMessage) => {
    const colors = {
      user: '#1890ff',
      assistant: '#52c41a', 
      system: '#fa8c16',
      command: '#722ed1'
    };

    return (
      <div key={msg.id} style={{ marginBottom: 16 }}>
        <Card 
          size="small"
          bodyStyle={{ 
            padding: 12,
            borderLeft: `4px solid ${colors[msg.type]}`,
            backgroundColor: msg.type === 'user' ? '#f0f9ff' : '#f6ffed'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ flex: 1 }}>
              <Text strong style={{ color: colors[msg.type] }}>
                {msg.type === 'user' ? '我' : 
                 msg.type === 'assistant' ? '助手' :
                 msg.type === 'command' ? '命令' : '系统'}
              </Text>
              {msg.model && <Text type="secondary"> • {msg.model}</Text>}
              <div style={{ marginTop: 8, whiteSpace: 'pre-wrap' }}>
                {msg.content}
              </div>
            </div>
            <div style={{ textAlign: 'right', marginLeft: 16 }}>
              <Text type="secondary" style={{ fontSize: '12px' }}>
                {msg.timestamp.toLocaleTimeString()}
              </Text>
              {msg.tokens && (
                <div style={{ fontSize: '11px', color: '#999' }}>
                  {msg.tokens} tokens
                </div>
              )}
            </div>
          </div>
        </Card>
      </div>
    );
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {/* 侧边栏 */}
      <Sider width={280} theme="light" style={{ borderRight: '1px solid #f0f0f0' }}>
        <div style={{ padding: 16 }}>
          <Title level={4} style={{ marginBottom: 16 }}>
            <DashboardOutlined /> Web Analyzer
          </Title>
          
          {/* 用户信息 */}
          <Card size="small" title="用户状态" style={{ marginBottom: 16 }}>
            {renderUserInfo()}
            
            {isAuthenticated && (
              <div style={{ marginTop: 12 }}>
                <Text type="secondary">认证方式:</Text>
                <div style={{ marginTop: 4 }}>
                  <Badge 
                    status={authType === AuthType.GUEST ? "success" : "processing"}
                    text="访客模式"
                  />
                </div>
                
                {quota && (
                  <div style={{ marginTop: 8 }}>
                    <Text type="secondary">配额:</Text>
                    <div style={{ marginTop: 4 }}>
                      <Text>{quota.used} / {quota.limit || '∞'}</Text>
                    </div>
                  </div>
                )}
              </div>
            )}
          </Card>

          {/* 模型切换 */}
          {isAuthenticated && (
            <Card size="small" title="模型管理" style={{ marginBottom: 16 }}>
              <ModelSwitcher 
                currentModel={currentModel}
                onModelChange={(modelId) => setCurrentModel(modelId)}
              />
            </Card>
          )}

          {/* 会话统计 */}
          {isAuthenticated && (
            <Card size="small" title="会话统计">
              <Space orientation="vertical" style={{ width: '100%' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary">消息:</Text>
                  <Text>{sessionStats.messages}</Text>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary">Tokens:</Text>
                  <Text>{sessionStats.tokens}</Text>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary">请求:</Text>
                  <Text>{sessionStats.requests}</Text>
                </div>
              </Space>
            </Card>
          )}
        </div>
      </Sider>

      <Layout>
        {/* 头部 */}
        <Header style={{ background: '#fff', padding: '0 24px', borderBottom: '1px solid #f0f0f0' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Space>
              <MessageOutlined />
              <Title level={4} style={{ margin: 0 }}>
                智能对话分析
              </Title>
            </Space>
            
            <Space>
              <Button icon={<SettingOutlined />}>设置</Button>
            </Space>
          </div>
        </Header>

        {/* 主内容区域 */}
        <Content style={{ margin: 24, display: 'flex', flexDirection: 'column' }}>
          {/* 消息显示区域 */}
          <div style={{ 
            flex: 1, 
            overflowY: 'auto', 
            padding: '0 16px',
            backgroundColor: '#fafafa',
            borderRadius: 8,
            marginBottom: 16
          }}>
            {chatMessages.length === 0 ? (
              <div style={{ 
                textAlign: 'center', 
                padding: '60px 20px',
                color: '#999'
              }}>
                <MessageOutlined style={{ fontSize: 48, marginBottom: 16 }} />
                <div>
                  {isAuthenticated 
                    ? '开始对话或使用 / 执行命令...' 
                    : '请先登录以开始使用'
                  }
                </div>
                {isAuthenticated && (
                  <div style={{ marginTop: 16, fontSize: '14px' }}>
                    <Text type="secondary">
                      提示: 试试这些命令: /help, /stats, /model qwen-coder
                    </Text>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ padding: 16 }}>
                {chatMessages.map(renderMessage)}
              </div>
            )}
          </div>

          {/* 输入区域 */}
          <div style={{ 
            backgroundColor: '#fff', 
            padding: 16, 
            borderRadius: 8,
            boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
          }}>
            <CommandInput
              onCommand={handleCommand}
              onMessage={handleMessage}
              disabled={!isAuthenticated}
              placeholder={isAuthenticated 
                ? "输入消息或使用 / 开始命令..." 
                : "请先登录..."}
            />
          </div>
        </Content>
      </Layout>

      {/* 登录模态框 */}
      <LoginModal
        visible={showLoginModal}
        onClose={() => {
          setShowLoginModal(false);
          if (isAuthenticated) {
            handleLogin();
          }
        }}
      />
    </Layout>
  );
};

export default MainApp;
