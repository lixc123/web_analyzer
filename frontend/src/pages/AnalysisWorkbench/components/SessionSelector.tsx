import React from 'react';
import { Select, Badge, Tooltip, Spin } from 'antd';
import { ReloadOutlined, GlobalOutlined } from '@ant-design/icons';
import type { CrawlerSession } from '../index';

const { Option } = Select;

interface SessionSelectorProps {
  sessions: CrawlerSession[];
  selectedSession: CrawlerSession | null;
  onSessionChange: (session: CrawlerSession) => void;
  loading: boolean;
}

const SessionSelector: React.FC<SessionSelectorProps> = ({
  sessions,
  selectedSession,
  onSessionChange,
  loading
}) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'processing';
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'starting': return 'warning';
      default: return 'default';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'running': return '运行中';
      case 'completed': return '已完成';
      case 'failed': return '失败';
      case 'starting': return '启动中';
      default: return status;
    }
  };

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleString('zh-CN');
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="session-selector">
      <Select
        style={{ width: '100%' }}
        placeholder="选择爬虫会话"
        value={selectedSession?.session_id}
        showSearch
        optionFilterProp="label"
        onChange={(sessionId) => {
          const session = sessions.find(s => s.session_id === sessionId);
          if (session) {
            onSessionChange(session);
          }
        }}
        loading={loading}
        suffixIcon={loading ? <Spin size="small" /> : <ReloadOutlined />}
      >
        {sessions.map(session => (
          <Option
            key={session.session_id}
            value={session.session_id}
            label={`${session.session_name} ${session.url || ''}`}
          >
            <div className="session-option">
              <div className="session-header">
                <span className="session-name">{session.session_name}</span>
                <Badge 
                  status={getStatusColor(session.status)} 
                  text={getStatusText(session.status)}
                />
              </div>
              <div className="session-details">
                <Tooltip title={session.url}>
                  <span className="session-url">
                    <GlobalOutlined /> {session.url?.length > 30 ? 
                      session.url.substring(0, 30) + '...' : session.url}
                  </span>
                </Tooltip>
              </div>
              <div className="session-stats">
                <span>请求: {session.total_requests}</span>
                <span>创建: {formatDate(session.created_at)}</span>
              </div>
            </div>
          </Option>
        ))}
      </Select>
    </div>
  );
};

export default SessionSelector;
