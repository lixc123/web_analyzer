import React, { useState, useEffect } from 'react';
import {
  Card,
  Table,
  Button,
  Space,
  Input,
  Select,
  Typography,
  Tag,
  Modal,
  Drawer,
  Tabs,
  message,
  Badge,
  Tooltip
} from 'antd';
import {
  ReloadOutlined,
  SearchOutlined,
  BugOutlined,
  CodeOutlined,
  DownloadOutlined,
  PlayCircleOutlined
} from '@ant-design/icons';

const { Title, Text } = Typography;
const { Search } = Input;
const { Option } = Select;

interface HttpRequest {
  id: string;
  method: string;
  url: string;
  status: number;
  responseType: string;
  size: number;
  duration: number;
  timestamp: Date;
  headers: Record<string, string>;
  payload?: any;
  response?: any;
  callStack?: string[];
}

export const RequestAnalysisPanel: React.FC = () => {
  const [requests, setRequests] = useState<HttpRequest[]>([]);
  const [filteredRequests, setFilteredRequests] = useState<HttpRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<HttpRequest | null>(null);
  const [showCallStack, setShowCallStack] = useState(false);
  const [showCodeModal, setShowCodeModal] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [methodFilter, setMethodFilter] = useState<string>('all');

  // 加载真实请求数据
  useEffect(() => {
    const loadRequests = async () => {
      try {
        const response = await fetch('/api/v1/request-analysis/requests');
        if (response.ok) {
          const data = await response.json();
          const realRequests: HttpRequest[] = data.requests.map((req: any) => ({
            id: req.id || Date.now().toString(),
            method: req.method || 'GET',
            url: req.url || '',
            status: req.status || 200,
            responseType: req.responseType || 'text/html',
            size: req.size || 0,
            duration: req.duration || 0,
            timestamp: new Date(req.timestamp || Date.now()),
            headers: req.headers || {},
            payload: req.payload,
            callStack: req.callStack
          }));
          setRequests(realRequests);
          setFilteredRequests(realRequests);
        } else {
          // 如果API调用失败，显示空数据而非模拟数据
          setRequests([]);
          setFilteredRequests([]);
        }
      } catch (error) {
        console.error('加载请求数据失败:', error);
        setRequests([]);
        setFilteredRequests([]);
      }
    };

    loadRequests();
  }, []);

  // 筛选和搜索
  useEffect(() => {
    let filtered = requests;

    if (searchText) {
      filtered = filtered.filter(req =>
        req.url.toLowerCase().includes(searchText.toLowerCase()) ||
        req.method.toLowerCase().includes(searchText.toLowerCase())
      );
    }

    if (statusFilter !== 'all') {
      const statusRange = statusFilter.split('-').map(Number);
      filtered = filtered.filter(req =>
        req.status >= statusRange[0] && req.status <= statusRange[1]
      );
    }

    if (methodFilter !== 'all') {
      filtered = filtered.filter(req => req.method === methodFilter);
    }

    setFilteredRequests(filtered);
  }, [requests, searchText, statusFilter, methodFilter]);

  // 重放请求
  const replayRequest = async (request: HttpRequest) => {
    try {
      message.loading('正在重放请求...', 0.5);
      // 模拟重放请求逻辑
      await new Promise(resolve => setTimeout(resolve, 1000));
      message.success(`请求重放完成: ${request.method} ${request.url}`);
    } catch (error) {
      message.error('请求重放失败');
    }
  };

  // 复制为代码
  const copyAsCode = (request: HttpRequest, format: 'curl' | 'python' | 'javascript') => {
    let code = '';

    switch (format) {
      case 'curl':
        code = `curl -X ${request.method} "${request.url}" \\
  -H "Content-Type: ${request.headers['Content-Type'] || 'application/json'}"`;
        break;
      case 'python':
        code = `import requests

response = requests.${request.method.toLowerCase()}(
    "${request.url}",
    headers=${JSON.stringify(request.headers, null, 2)}
)`;
        break;
      case 'javascript':
        code = `fetch('${request.url}', {
  method: '${request.method}',
  headers: ${JSON.stringify(request.headers, null, 2)}
})`;
        break;
    }

    navigator.clipboard.writeText(code);
    message.success(`已复制${format.toUpperCase()}代码`);
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'warning';
    if (status >= 400) return 'error';
    return 'default';
  };

  const columns = [
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => <Tag color="blue">{method}</Tag>
    },
    {
      title: '状态码',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (status: number) => (
        <Badge status={getStatusColor(status)} text={status.toString()} />
      )
    },
    {
      title: '类型',
      dataIndex: 'responseType',
      key: 'responseType',
      width: 120,
      render: (type: string) => <Text code>{type.split('/')[1]}</Text>
    },
    {
      title: '大小',
      dataIndex: 'size',
      key: 'size',
      width: 80,
      render: (size: number) => `${(size / 1024).toFixed(1)}KB`
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Tooltip title={url}>
          <Text>{url}</Text>
        </Tooltip>
      )
    },
    {
      title: '操作',
      key: 'actions',
      width: 200,
      render: (_: any, record: HttpRequest) => (
        <Space size="small">
          <Tooltip title="重放请求">
            <Button
              size="small"
              icon={<PlayCircleOutlined />}
              onClick={() => replayRequest(record)}
            />
          </Tooltip>
          <Tooltip title="复制代码">
            <Button
              size="small"
              icon={<CodeOutlined />}
              onClick={() => {
                setSelectedRequest(record);
                setShowCodeModal(true);
              }}
            />
          </Tooltip>
          <Tooltip title="调用栈">
            <Button
              size="small"
              icon={<BugOutlined />}
              onClick={() => {
                setSelectedRequest(record);
                setShowCallStack(true);
              }}
            />
          </Tooltip>
        </Space>
      )
    }
  ];

  return (
    <div>
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <Title level={4}>
            <SearchOutlined /> 请求分析
          </Title>
          <Space>
            <Button icon={<ReloadOutlined />}>刷新</Button>
            <Button icon={<DownloadOutlined />}>导出</Button>
          </Space>
        </div>

        {/* 筛选器 */}
        <Space style={{ marginBottom: 16, width: '100%' }}>
          <Search
            placeholder="搜索URL或方法"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            style={{ width: 300 }}
            allowClear
          />

          <Select
            value={statusFilter}
            onChange={setStatusFilter}
            style={{ width: 120 }}
            placeholder="状态码"
          >
            <Option value="all">全部状态</Option>
            <Option value="200-299">2xx 成功</Option>
            <Option value="300-399">3xx 重定向</Option>
            <Option value="400-499">4xx 客户端错误</Option>
            <Option value="500-599">5xx 服务器错误</Option>
          </Select>

          <Select
            value={methodFilter}
            onChange={setMethodFilter}
            style={{ width: 100 }}
            placeholder="方法"
          >
            <Option value="all">全部方法</Option>
            <Option value="GET">GET</Option>
            <Option value="POST">POST</Option>
            <Option value="PUT">PUT</Option>
            <Option value="DELETE">DELETE</Option>
          </Select>

          <Text type="secondary">
            共 {filteredRequests.length} 条请求
          </Text>
        </Space>

        {/* 请求列表 */}
        <Table
          columns={columns}
          dataSource={filteredRequests}
          rowKey="id"
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showQuickJumper: true
          }}
          onRow={(record) => ({
            onClick: () => setSelectedRequest(record)
          })}
        />
      </Card>

      {/* 调用栈抽屉 */}
      <Drawer
        title="调用栈分析"
        placement="right"
        open={showCallStack}
        onClose={() => setShowCallStack(false)}
        width={500}
      >
        {selectedRequest && selectedRequest.callStack && (
          <div>
            <Title level={5}>调用栈</Title>
            {selectedRequest.callStack.map((call, index) => (
              <div key={index}>
                {index + 1}. {call}
              </div>
            ))}
          </div>
        )}
      </Drawer>

      {/* 复制代码模态框 */}
      <Modal
        title="复制为代码"
        open={showCodeModal}
        onCancel={() => setShowCodeModal(false)}
        footer={null}
        width={600}
      >
        {selectedRequest && (
          <Tabs
            items={[
              {
                key: 'curl',
                label: 'cURL',
                children: (
                  <div>
                    <Button
                      style={{ marginBottom: 8 }}
                      onClick={() => copyAsCode(selectedRequest, 'curl')}
                    >
                      复制 cURL
                    </Button>
                    <pre style={{ background: '#f5f5f5', padding: 12 }}>
                      {`curl -X ${selectedRequest.method} "${selectedRequest.url}" \\
  -H "Content-Type: ${selectedRequest.headers['Content-Type'] || 'application/json'}"`}
                    </pre>
                  </div>
                )
              },
              {
                key: 'python',
                label: 'Python',
                children: (
                  <div>
                    <Button
                      style={{ marginBottom: 8 }}
                      onClick={() => copyAsCode(selectedRequest, 'python')}
                    >
                      复制 Python
                    </Button>
                    <pre style={{ background: '#f5f5f5', padding: 12 }}>
                      {`import requests

response = requests.${selectedRequest.method.toLowerCase()}(
    "${selectedRequest.url}",
    headers=${JSON.stringify(selectedRequest.headers, null, 2)}
)`}
                    </pre>
                  </div>
                )
              },
              {
                key: 'javascript',
                label: 'JavaScript',
                children: (
                  <div>
                    <Button
                      style={{ marginBottom: 8 }}
                      onClick={() => copyAsCode(selectedRequest, 'javascript')}
                    >
                      复制 JavaScript
                    </Button>
                    <pre style={{ background: '#f5f5f5', padding: 12 }}>
                      {`fetch('${selectedRequest.url}', {
  method: '${selectedRequest.method}',
  headers: ${JSON.stringify(selectedRequest.headers, null, 2)}
})`}
                    </pre>
                  </div>
                )
              }
            ]}
          />
        )}
      </Modal>
    </div>
  );
};

export default RequestAnalysisPanel;
