import React, { useState, useEffect } from 'react';
import { Layout, Divider, message } from 'antd';
import SessionSelector from './components/SessionSelector';
import RequestList from './components/RequestList';
import QwenTerminal from './components/QwenTerminal';
import './index.css';

const { Content, Sider } = Layout;

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

  // 加载所有爬虫会话
  const loadSessions = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/crawler/sessions');
      if (response.ok) {
        const data = await response.json();
        setSessions(data.sessions || []);
        
        // 自动选择第一个会话
        if (data.sessions?.length > 0 && !selectedSession) {
          setSelectedSession(data.sessions[0]);
        }
      }
    } catch (error) {
      console.error('加载会话失败:', error);
      message.error('加载会话失败');
    } finally {
      setLoading(false);
    }
  };

  // 加载指定会话的请求记录
  const loadSessionRequests = async (sessionId: string) => {
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
  };

  // 会话切换处理
  const handleSessionChange = (session: CrawlerSession) => {
    setSelectedSession(session);
    loadSessionRequests(session.session_id);
  };

  useEffect(() => {
    loadSessions();
  }, []);

  useEffect(() => {
    if (selectedSession) {
      loadSessionRequests(selectedSession.session_id);
    }
  }, [selectedSession]);

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
              <h3>请求记录 ({requests.length})</h3>
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
            <div className="terminal-section">
              <h3>Qwen Code CLI</h3>
              <QwenTerminal />
            </div>
          </Content>
        </Layout>
      </Layout>
    </div>
  );
};

export default AnalysisWorkbench;
