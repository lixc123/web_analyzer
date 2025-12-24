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
  Tooltip,
  Row,
  Col,
  Statistic
} from 'antd';
import {
  ReloadOutlined,
  SearchOutlined,
  BugOutlined,
  CodeOutlined,
  DownloadOutlined,
  PlayCircleOutlined,
  FilterOutlined,
  ExportOutlined,
  EyeOutlined,
  FileTextOutlined,
  RocketOutlined
} from '@ant-design/icons';
import CallStackAnalyzer from './CallStackAnalyzer';

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

interface CallStackFrame {
  id: string;
  function: string;
  file: string;
  line: number;
  column: number;
  source?: string;
  variables?: Record<string, any>;
  isUserCode: boolean;
  executionTime?: number;
}

export const EnhancedRequestAnalysisPanel: React.FC = () => {
  const [requests, setRequests] = useState<HttpRequest[]>([]);
  const [filteredRequests, setFilteredRequests] = useState<HttpRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<HttpRequest | null>(null);
  const [showCallStack, setShowCallStack] = useState(false);
  const [showCodeModal, setShowCodeModal] = useState(false);
  const [showDetailsDrawer, setShowDetailsDrawer] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [methodFilter, setMethodFilter] = useState<string>('all');
  const [isRecording, setIsRecording] = useState(false);
  const [showGeneratedCode, setShowGeneratedCode] = useState(false);
  const [generatedCode, setGeneratedCode] = useState('');
  const [codeGenerating, setCodeGenerating] = useState(false);

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
      const response = await fetch('/api/v1/replay-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: request.method,
          url: request.url,
          headers: request.headers,
          payload: request.payload
        })
      });

      if (response.ok) {
        message.success(`请求重放完成: ${request.method} ${request.url}`);
        
        // 添加重放的请求到列表
        const replayedRequest: HttpRequest = {
          ...request,
          id: Date.now().toString(),
          timestamp: new Date(),
          status: 200 // 假设重放成功
        };
        
        setRequests(prev => [replayedRequest, ...prev]);
      } else {
        throw new Error('重放失败');
      }
    } catch (error) {
      message.error(`请求重放失败: ${error}`);
    }
  };

  // 生成会话Python代码
  const generateSessionCode = async () => {
    try {
      setCodeGenerating(true);
      message.loading('正在生成Python代码...', 0.5);
      
      // 模拟会话路径 - 实际项目中应该从会话管理获取
      const sessionPath = 'C:\\Users\\Administrator\\Desktop\\WEB_p\\new\\web_analyzer_v2\\data\\sessions\\session_20241224_174600';
      
      const response = await fetch('/api/v1/code/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_path: sessionPath,
          include_js_analysis: true,
          output_format: 'python'
        })
      });

      if (response.ok) {
        const data = await response.json();
        setGeneratedCode(data.code_preview || '// 代码生成成功，但预览为空');
        setShowGeneratedCode(true);
        message.success(`代码生成成功！包含 ${data.stats?.api_requests || 0} 个API请求`);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || '代码生成失败');
      }
    } catch (error) {
      message.error(`代码生成失败: ${error}`);
    } finally {
      setCodeGenerating(false);
    }
  };

  // 下载会话代码
  const downloadSessionCode = async () => {
    try {
      message.loading('正在下载代码文件...', 0.5);
      
      // 模拟会话名称 - 实际项目中应该从会话管理获取
      const sessionName = 'session_20241224_174600';
      
      const response = await fetch(`/api/v1/code/download/${sessionName}`);
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `session_${sessionName}_generated.py`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        message.success('代码文件下载成功！');
      } else {
        throw new Error('下载失败');
      }
    } catch (error) {
      message.error(`下载失败: ${error}`);
    }
  };

  // 复制为代码
  const copyAsCode = (request: HttpRequest, format: 'curl' | 'python' | 'javascript') => {
    let code = '';
    
    switch (format) {
      case 'curl':
        code = `curl -X ${request.method} "${request.url}"`;
        Object.entries(request.headers).forEach(([key, value]) => {
          code += ` \\\n  -H "${key}: ${value}"`;
        });
        if (request.payload && request.method !== 'GET') {
          code += ` \\\n  -d '${JSON.stringify(request.payload)}'`;
        }
        break;
        
      case 'python':
        code = `import requests
import json

url = "${request.url}"
headers = ${JSON.stringify(request.headers, null, 2)}`;
        
        if (request.payload && request.method !== 'GET') {
          code += `\ndata = ${JSON.stringify(request.payload, null, 2)}`;
          code += `\n\nresponse = requests.${request.method.toLowerCase()}(url, headers=headers, json=data)`;
        } else {
          code += `\n\nresponse = requests.${request.method.toLowerCase()}(url, headers=headers)`;
        }
        code += `\nprint(response.status_code)\nprint(response.text)`;
        break;
        
      case 'javascript':
        code = `const response = await fetch('${request.url}', {
  method: '${request.method}',
  headers: ${JSON.stringify(request.headers, null, 2)}`;
        
        if (request.payload && request.method !== 'GET') {
          code += `,\n  body: JSON.stringify(${JSON.stringify(request.payload, null, 2)})`;
        }
        code += `\n});

const data = await response.json();
console.log(data);`;
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

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const getRequestStats = () => {
    const total = filteredRequests.length;
    const success = filteredRequests.filter(req => req.status >= 200 && req.status < 300).length;
    const errors = filteredRequests.filter(req => req.status >= 400).length;
    const totalSize = filteredRequests.reduce((sum, req) => sum + req.size, 0);
    const avgDuration = total > 0 ? filteredRequests.reduce((sum, req) => sum + req.duration, 0) / total : 0;

    return { total, success, errors, totalSize, avgDuration };
  };

  const columns = [
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => {
        const colors = {
          GET: 'blue',
          POST: 'green', 
          PUT: 'orange',
          DELETE: 'red',
          PATCH: 'purple'
        };
        return <Tag color={colors[method as keyof typeof colors] || 'default'}>{method}</Tag>;
      }
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
      render: (type: string) => {
        const shortType = type.includes('/') ? type.split('/')[1] : type;
        return <Text code>{shortType}</Text>;
      }
    },
    {
      title: '大小',
      dataIndex: 'size',
      key: 'size', 
      width: 80,
      render: (size: number) => formatFileSize(size)
    },
    {
      title: '时间',
      dataIndex: 'duration',
      key: 'duration',
      width: 80,
      render: (duration: number) => `${duration}ms`
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
          <Tooltip title="查看详情">
            <Button 
              size="small" 
              icon={<EyeOutlined />}
              onClick={() => {
                setSelectedRequest(record);
                setShowDetailsDrawer(true);
              }}
            />
          </Tooltip>
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

  const stats = getRequestStats();

  return (
    <div>
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <Title level={4}>
            <SearchOutlined /> HTTP 请求分析
          </Title>
          <Space>
            <Button 
              type={isRecording ? 'primary' : 'default'}
              danger={isRecording}
              onClick={() => setIsRecording(!isRecording)}
            >
              {isRecording ? '停止录制' : '开始录制'}
            </Button>
            <Button icon={<ReloadOutlined />}>刷新</Button>
            <Button icon={<ExportOutlined />}>导出HAR</Button>
            <Button icon={<DownloadOutlined />}>导出报告</Button>
            <Button 
              type="primary"
              icon={<RocketOutlined />}
              loading={codeGenerating}
              onClick={generateSessionCode}
            >
              生成Python代码
            </Button>
            <Button 
              icon={<FileTextOutlined />}
              onClick={downloadSessionCode}
              disabled={codeGenerating}
            >
              下载代码
            </Button>
          </Space>
        </div>

        {/* 统计信息 */}
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={4}>
            <Card size="small">
              <Statistic title="总请求数" value={stats.total} />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic
                title="成功请求" 
                value={stats.success}
                valueStyle={{ color: '#3f8600' }}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic
                title="错误请求"
                value={stats.errors} 
                valueStyle={{ color: '#cf1322' }}
              />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic title="总数据量" value={formatFileSize(stats.totalSize)} />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic title="平均响应时间" value={`${Math.round(stats.avgDuration)}ms`} />
            </Card>
          </Col>
          <Col span={4}>
            <Card size="small">
              <Statistic
                title="录制状态"
                value={isRecording ? '进行中' : '已停止'}
                valueStyle={{ color: isRecording ? '#1890ff' : '#999' }}
              />
            </Card>
          </Col>
        </Row>

        {/* 筛选器 */}
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={8}>
            <Search
              placeholder="搜索URL、方法或状态码"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              allowClear
            />
          </Col>
          
          <Col span={4}>
            <Select
              value={statusFilter}
              onChange={setStatusFilter}
              style={{ width: '100%' }}
              placeholder="状态码筛选"
            >
              <Option value="all">全部状态</Option>
              <Option value="200-299">2xx 成功</Option>
              <Option value="300-399">3xx 重定向</Option>
              <Option value="400-499">4xx 客户端错误</Option>
              <Option value="500-599">5xx 服务器错误</Option>
            </Select>
          </Col>

          <Col span={4}>
            <Select
              value={methodFilter}
              onChange={setMethodFilter}
              style={{ width: '100%' }}
              placeholder="方法筛选"
            >
              <Option value="all">全部方法</Option>
              <Option value="GET">GET</Option>
              <Option value="POST">POST</Option>
              <Option value="PUT">PUT</Option>
              <Option value="DELETE">DELETE</Option>
              <Option value="PATCH">PATCH</Option>
            </Select>
          </Col>

          <Col span={8}>
            <Space>
              <Button icon={<FilterOutlined />}>高级筛选</Button>
              <Text type="secondary">
                共 {filteredRequests.length} 条请求
              </Text>
            </Space>
          </Col>
        </Row>

        {/* 请求列表 */}
        <Table
          columns={columns}
          dataSource={filteredRequests}
          rowKey="id"
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`
          }}
          onRow={(record) => ({
            onClick: () => setSelectedRequest(record),
            style: { cursor: 'pointer' }
          })}
          scroll={{ x: 1200 }}
        />
      </Card>

      {/* 请求详情抽屉 */}
      <Drawer
        title={`请求详情 - ${selectedRequest?.method} ${selectedRequest?.url}`}
        placement="right"
        open={showDetailsDrawer}
        onClose={() => setShowDetailsDrawer(false)}
        width={600}
      >
        {selectedRequest && (
          <Tabs
            items={[
              {
                key: 'general',
                label: '概览',
                children: (
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Card size="small" title="请求信息">
                      <p><strong>URL:</strong> {selectedRequest.url}</p>
                      <p><strong>方法:</strong> {selectedRequest.method}</p>
                      <p><strong>状态码:</strong> <Badge status={getStatusColor(selectedRequest.status)} text={selectedRequest.status.toString()} /></p>
                      <p><strong>响应时间:</strong> {selectedRequest.duration}ms</p>
                      <p><strong>数据大小:</strong> {formatFileSize(selectedRequest.size)}</p>
                      <p><strong>时间:</strong> {selectedRequest.timestamp.toLocaleString()}</p>
                    </Card>
                  </Space>
                )
              },
              {
                key: 'headers',
                label: '请求头',
                children: (
                  <Card size="small">
                    {Object.entries(selectedRequest.headers).map(([key, value]) => (
                      <div key={key} style={{ marginBottom: 8 }}>
                        <Text strong>{key}:</Text>
                        <Text style={{ marginLeft: 8 }}>{value}</Text>
                      </div>
                    ))}
                  </Card>
                )
              },
              {
                key: 'payload',
                label: '请求体',
                children: (
                  <Card size="small">
                    {selectedRequest.payload ? (
                      <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4 }}>
                        {JSON.stringify(selectedRequest.payload, null, 2)}
                      </pre>
                    ) : (
                      <Text type="secondary">无请求体数据</Text>
                    )}
                  </Card>
                )
              },
              {
                key: 'response',
                label: '响应',
                children: (
                  <Card size="small">
                    <Text type="secondary">响应数据将在实际录制时显示</Text>
                  </Card>
                )
              }
            ]}
          />
        )}
      </Drawer>

      {/* 调用栈分析器 */}
      <CallStackAnalyzer
        requestId={selectedRequest?.id || ''}
        callStack={[]} // 将传入实际的调用栈数据
        visible={showCallStack}
        onClose={() => setShowCallStack(false)}
      />

      {/* 复制代码模态框 */}
      <Modal
        title="复制为代码"
        open={showCodeModal}
        onCancel={() => setShowCodeModal(false)}
        footer={null}
        width={800}
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
                      复制 cURL 命令
                    </Button>
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, overflow: 'auto' }}>
                      {`curl -X ${selectedRequest.method} "${selectedRequest.url}"${Object.entries(selectedRequest.headers).map(([key, value]) => `\n  -H "${key}: ${value}"`).join('')}${selectedRequest.payload && selectedRequest.method !== 'GET' ? `\n  -d '${JSON.stringify(selectedRequest.payload)}'` : ''}`}
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
                      复制 Python 代码
                    </Button>
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, overflow: 'auto' }}>
                      {`import requests\nimport json\n\nurl = "${selectedRequest.url}"\nheaders = ${JSON.stringify(selectedRequest.headers, null, 2)}${selectedRequest.payload && selectedRequest.method !== 'GET' ? `\ndata = ${JSON.stringify(selectedRequest.payload, null, 2)}\n\nresponse = requests.${selectedRequest.method.toLowerCase()}(url, headers=headers, json=data)` : `\n\nresponse = requests.${selectedRequest.method.toLowerCase()}(url, headers=headers)`}\nprint(response.status_code)\nprint(response.text)`}
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
                      复制 JavaScript 代码
                    </Button>
                    <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 4, overflow: 'auto' }}>
                      {`const response = await fetch('${selectedRequest.url}', {\n  method: '${selectedRequest.method}',\n  headers: ${JSON.stringify(selectedRequest.headers, null, 2)}${selectedRequest.payload && selectedRequest.method !== 'GET' ? `,\n  body: JSON.stringify(${JSON.stringify(selectedRequest.payload, null, 2)})` : ''}\n});\n\nconst data = await response.json();\nconsole.log(data);`}
                    </pre>
                  </div>
                )
              }
            ]}
          />
        )}
      </Modal>

      {/* 生成的代码展示模态框 */}
      <Modal
        title="生成的Python会话代码"
        open={showGeneratedCode}
        onCancel={() => setShowGeneratedCode(false)}
        width={1000}
        footer={[
          <Button key="copy" onClick={() => {
            navigator.clipboard.writeText(generatedCode);
            message.success('代码已复制到剪贴板');
          }}>
            复制全部代码
          </Button>,
          <Button key="download" type="primary" onClick={downloadSessionCode}>
            下载完整代码文件
          </Button>
        ]}
      >
        <div>
          <div style={{ marginBottom: 16 }}>
            <Text type="secondary">
              这是根据录制的HTTP请求生成的Python代码，可以直接运行来验证请求逻辑。
              包含JavaScript分析功能，帮助AI理解签名算法等复杂逻辑。
            </Text>
          </div>
          <pre style={{ 
            background: '#f5f5f5', 
            padding: 16, 
            borderRadius: 4, 
            overflow: 'auto',
            maxHeight: '500px',
            fontSize: '13px',
            lineHeight: '1.4'
          }}>
            {generatedCode || '// 正在生成代码...'}
          </pre>
          <div style={{ marginTop: 16 }}>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              提示：生成的代码包含完整的会话类、所有API请求方法、JavaScript调用栈分析等功能。
              可以直接在Python环境中运行，便于AI分析和调试。
            </Text>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default EnhancedRequestAnalysisPanel;
