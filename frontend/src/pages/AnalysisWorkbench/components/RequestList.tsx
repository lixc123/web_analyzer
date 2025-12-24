import React, { useEffect, useMemo, useState } from 'react';
import { Input, List, Tag, Tooltip, Badge, Empty } from 'antd';
import { GlobalOutlined, ClockCircleOutlined, FileTextOutlined } from '@ant-design/icons';
import type { RequestRecord, CrawlerSession } from '../index';

const { Search } = Input;

interface RequestListProps {
  requests: RequestRecord[];
  selectedSession: CrawlerSession | null;
  loading: boolean;
}

const RequestList: React.FC<RequestListProps> = ({
  requests,
  selectedSession,
  loading
}) => {
  const [searchText, setSearchText] = useState('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);

  // 过滤和搜索请求
  const filteredRequests = useMemo(() => {
    return requests.filter(request => {
      // 搜索文本过滤
      if (searchText) {
        const keyword = searchText.toLowerCase();
        const haystack = [
          request.url,
          request.method,
          String(request.status ?? ''),
          request.content_type || '',
          request.resource_type || ''
        ]
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(keyword)) {
          return false;
        }
      }
      
      return true;
    });
  }, [requests, searchText]);

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'warning';
    if (status >= 400 && status < 500) return 'error';
    if (status >= 500) return 'error';
    return 'default';
  };

  const getMethodColor = (method: string) => {
    switch (method?.toUpperCase()) {
      case 'GET': return 'blue';
      case 'POST': return 'green';
      case 'PUT': return 'orange';
      case 'DELETE': return 'red';
      case 'PATCH': return 'purple';
      default: return 'default';
    }
  };

  const formatSize = (bytes?: number) => {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString('zh-CN');
  };

  const clearFilters = () => {
    setSearchText('');
  };

  useEffect(() => {
    setCurrentPage(1);
  }, [searchText, requests]);

  if (!selectedSession) {
    return (
      <div className="request-list-empty">
        <Empty description="请选择一个爬虫会话" />
      </div>
    );
  }

  return (
    <div className="request-list">
      {/* 搜索和过滤器 */}
      <div className="request-filters">
        <Search
          placeholder="搜索内容/URL..."
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          style={{ marginBottom: 8 }}
          allowClear
        />

        <div className="filter-summary">
          显示 {filteredRequests.length} / {requests.length} 请求
          {searchText && (
            <a onClick={clearFilters} style={{ marginLeft: 8 }}>清除筛选</a>
          )}
        </div>
      </div>

      {/* 请求列表 */}
      <div className="request-list-container">
        <List
          size="small"
          loading={loading}
          dataSource={filteredRequests}
          locale={{ emptyText: '暂无请求记录' }}
          pagination={{
            current: currentPage,
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            pageSizeOptions: ['10', '20', '50', '100'],
            onChange: (page, size) => {
              setCurrentPage(page);
              if (typeof size === 'number') {
                setPageSize(size);
              }
            },
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`
          }}
          renderItem={(request) => (
            <List.Item className="request-item">
              <div className="request-content">
                <div className="request-header">
                  <Tag color={getMethodColor(request.method)}>{request.method}</Tag>
                  <Badge 
                    status={getStatusColor(request.status)} 
                    text={request.status.toString()}
                  />
                  <span className="request-time">
                    <ClockCircleOutlined /> {formatTime(request.timestamp)}
                  </span>
                </div>
                
                <div className="request-url">
                  <Tooltip title={request.url}>
                    <span>
                      <GlobalOutlined /> 
                      {request.url.length > 50 ? 
                        request.url.substring(0, 50) + '...' : 
                        request.url}
                    </span>
                  </Tooltip>
                </div>
                
                <div className="request-meta">
                  {request.content_type && (
                    <Tag icon={<FileTextOutlined />} color="blue">
                      {request.content_type.split(';')[0]}
                    </Tag>
                  )}
                  {request.response_size && (
                    <Tag color="green">{formatSize(request.response_size)}</Tag>
                  )}
                  {request.resource_type && (
                    <Tag color="purple">{request.resource_type}</Tag>
                  )}
                </div>
              </div>
            </List.Item>
          )}
        />
      </div>
    </div>
  );
};

export default RequestList;
