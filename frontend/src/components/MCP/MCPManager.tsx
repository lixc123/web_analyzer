import React, { useState, useEffect } from 'react';
import {
  Card, 
  Table, 
  Button, 
  Space, 
  Badge, 
  Modal, 
  Form, 
  Input, 
  Typography, 
  message,
  Tabs,
  Tag,
  Switch,
  Divider
} from 'antd';
import {
  ApiOutlined,
  SettingOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  PlusOutlined,
  ToolOutlined,
  LinkOutlined,
  DisconnectOutlined,
  InfoCircleOutlined
} from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;

// MCP服务器配置接口
interface MCPServer {
  id: string;
  name: string;
  description?: string;
  url: string;
  status: 'connected' | 'disconnected' | 'connecting' | 'error';
  tools: MCPTool[];
  lastConnected?: Date;
  error?: string;
  config: {
    autoConnect: boolean;
    timeout: number;
    retries: number;
  };
}

// MCP工具接口
interface MCPTool {
  id: string;
  name: string;
  description: string;
  category: 'file' | 'database' | 'api' | 'analysis' | 'automation' | 'other';
  parameters: MCPToolParameter[];
  serverId: string;
  enabled: boolean;
}

interface MCPToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description?: string;
  required: boolean;
  default?: any;
}

// 预设MCP服务器配置
const PRESET_MCP_SERVERS = [
  {
    id: 'filesystem',
    name: '文件系统工具',
    description: '提供文件读写、目录操作等文件系统功能',
    url: 'mcp://filesystem',
    category: 'file',
    tools: ['read_file', 'write_file', 'list_directory', 'create_folder']
  },
  {
    id: 'web-recorder',
    name: '网页录制器',
    description: '集成现有的网页录制和分析工具',
    url: 'mcp://localhost:8080/recorder',
    category: 'automation', 
    tools: ['start_recording', 'stop_recording', 'analyze_requests', 'export_har']
  },
  {
    id: 'database',
    name: '数据库连接器',
    description: '提供数据库查询和操作功能',
    url: 'mcp://database',
    category: 'database',
    tools: ['execute_query', 'list_tables', 'describe_table', 'export_data']
  },
  {
    id: 'python-executor',
    name: 'Python执行器',
    description: '安全执行Python代码和脚本',
    url: 'mcp://python',
    category: 'analysis',
    tools: ['execute_code', 'install_package', 'run_script', 'analyze_data']
  }
];

export const MCPManager: React.FC = () => {
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [availableTools, setAvailableTools] = useState<MCPTool[]>([]);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showToolModal, setShowToolModal] = useState(false);
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [form] = Form.useForm();

  // 初始化加载MCP配置
  useEffect(() => {
    loadMCPConfig();
  }, []);

  // 从localStorage加载MCP配置
  const loadMCPConfig = () => {
    try {
      const globalConfig = JSON.parse(localStorage.getItem('globalConfig') || '{}');
      const mcpConfig = globalConfig.mcp || { servers: [], tools: [] };
      
      setServers(mcpConfig.servers || []);
      setAvailableTools(mcpConfig.tools || []);
    } catch (error) {
      console.error('加载MCP配置失败:', error);
    }
  };

  // 保存MCP配置到localStorage
  const saveMCPConfig = (newServers: MCPServer[], newTools: MCPTool[]) => {
    try {
      const globalConfig = JSON.parse(localStorage.getItem('globalConfig') || '{}');
      globalConfig.mcp = {
        servers: newServers,
        tools: newTools,
        lastUpdated: new Date().toISOString()
      };
      localStorage.setItem('globalConfig', JSON.stringify(globalConfig));
    } catch (error) {
      console.error('保存MCP配置失败:', error);
    }
  };

  // 连接MCP服务器
  const connectServer = async (serverId: string) => {
    setConnecting(true);
    try {
      const serverIndex = servers.findIndex(s => s.id === serverId);
      if (serverIndex === -1) return;

      // 更新服务器状态为连接中
      const updatedServers = [...servers];
      updatedServers[serverIndex] = {
        ...updatedServers[serverIndex],
        status: 'connecting'
      };
      setServers(updatedServers);

      // 模拟MCP连接过程
      const response = await fetch('/api/v1/mcp/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serverId,
          url: servers[serverIndex].url,
          config: servers[serverIndex].config
        })
      });

      if (!response.ok) throw new Error('连接失败');

      const result = await response.json();
      
      // 更新服务器状态和工具列表
      updatedServers[serverIndex] = {
        ...updatedServers[serverIndex],
        status: 'connected',
        tools: result.tools || [],
        lastConnected: new Date(),
        error: undefined
      };

      setServers(updatedServers);
      
      // 更新可用工具列表
      const newTools = result.tools || [];
      setAvailableTools(prev => [
        ...prev.filter(t => t.serverId !== serverId),
        ...newTools.map((tool: any) => ({ ...tool, serverId }))
      ]);

      saveMCPConfig(updatedServers, availableTools);
      message.success(`MCP服务器 "${servers[serverIndex].name}" 连接成功`);

    } catch (error) {
      // 连接失败，更新错误状态
      const updatedServers = [...servers];
      const serverIndex = updatedServers.findIndex(s => s.id === serverId);
      if (serverIndex !== -1) {
        updatedServers[serverIndex] = {
          ...updatedServers[serverIndex],
          status: 'error',
          error: error instanceof Error ? error.message : '未知错误'
        };
        setServers(updatedServers);
      }
      
      message.error(`连接MCP服务器失败: ${error}`);
    } finally {
      setConnecting(false);
    }
  };

  // 断开MCP服务器
  const disconnectServer = async (serverId: string) => {
    try {
      await fetch('/api/v1/mcp/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverId })
      });

      const updatedServers = servers.map(server => 
        server.id === serverId 
          ? { ...server, status: 'disconnected' as const }
          : server
      );
      
      setServers(updatedServers);
      
      // 移除该服务器的工具
      const updatedTools = availableTools.filter(tool => tool.serverId !== serverId);
      setAvailableTools(updatedTools);
      
      saveMCPConfig(updatedServers, updatedTools);
      message.info('MCP服务器已断开');

    } catch (error) {
      message.error(`断开MCP服务器失败: ${error}`);
    }
  };

  // 添加新的MCP服务器
  const handleAddServer = async (values: any) => {
    try {
      const newServer: MCPServer = {
        id: `server_${Date.now()}`,
        name: values.name,
        description: values.description,
        url: values.url,
        status: 'disconnected',
        tools: [],
        config: {
          autoConnect: values.autoConnect || false,
          timeout: values.timeout || 30000,
          retries: values.retries || 3
        }
      };

      const updatedServers = [...servers, newServer];
      setServers(updatedServers);
      saveMCPConfig(updatedServers, availableTools);
      
      setShowAddModal(false);
      form.resetFields();
      message.success('MCP服务器添加成功');

      // 如果启用自动连接，立即尝试连接
      if (values.autoConnect) {
        await connectServer(newServer.id);
      }

    } catch (error) {
      message.error(`添加MCP服务器失败: ${error}`);
    }
  };

  // 执行MCP工具
  const executeTool = async (tool: MCPTool, parameters: any) => {
    try {
      const response = await fetch('/api/v1/mcp/execute-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolId: tool.id,
          serverId: tool.serverId,
          parameters
        })
      });

      if (!response.ok) throw new Error('工具执行失败');

      const result = await response.json();
      message.success('工具执行完成');
      return result;

    } catch (error) {
      message.error(`工具执行失败: ${error}`);
      throw error;
    }
  };

  // 渲染服务器状态标识
  const renderServerStatus = (status: MCPServer['status']) => {
    const statusConfig = {
      connected: { color: 'success' as const, text: '已连接' },
      disconnected: { color: 'default' as const, text: '未连接' },
      connecting: { color: 'processing' as const, text: '连接中' },
      error: { color: 'error' as const, text: '错误' }
    };
    
    const config = statusConfig[status];
    return <Badge status={config.color} text={config.text} />;
  };

  // 渲染工具类别图标
  const renderToolIcon = (category: MCPTool['category']) => {
    const icons = {
      file: 'FILE',
      database: 'DB',
      api: 'API',
      analysis: 'ANALYSIS',
      automation: 'AUTO',
      other: 'TOOL'
    };
    return icons[category] || 'TOOL';
  };

  // 服务器表格列配置
  const serverColumns = [
    {
      title: '服务器名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: MCPServer) => (
        <Space>
          <ApiOutlined />
          <div>
            <div>{name}</div>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {record.description}
            </Text>
          </div>
        </Space>
      )
    },
    {
      title: 'URL',
      dataIndex: 'url', 
      key: 'url',
      render: (url: string) => <Text code>{url}</Text>
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: renderServerStatus
    },
    {
      title: '工具数量',
      key: 'toolCount',
      render: (record: MCPServer) => (
        <Badge count={record.tools.length} style={{ backgroundColor: '#52c41a' }} />
      )
    },
    {
      title: '操作',
      key: 'actions',
      render: (record: MCPServer) => (
        <Space>
          {record.status === 'connected' ? (
            <Button 
              size="small" 
              icon={<DisconnectOutlined />}
              onClick={() => disconnectServer(record.id)}
            >
              断开
            </Button>
          ) : (
            <Button 
              size="small" 
              type="primary"
              icon={<LinkOutlined />}
              loading={record.status === 'connecting'}
              onClick={() => connectServer(record.id)}
            >
              连接
            </Button>
          )}
          <Button 
            size="small" 
            icon={<SettingOutlined />}
          >
            配置
          </Button>
        </Space>
      )
    }
  ];

  // 工具表格列配置
  const toolColumns = [
    {
      title: '工具',
      key: 'tool',
      render: (record: MCPTool) => (
        <Space>
          <span style={{ fontSize: '16px' }}>
            {renderToolIcon(record.category)}
          </span>
          <div>
            <div>{record.name}</div>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {record.description}
            </Text>
          </div>
        </Space>
      )
    },
    {
      title: '类别',
      dataIndex: 'category',
      key: 'category',
      render: (category: string) => <Tag color="blue">{category}</Tag>
    },
    {
      title: '服务器',
      dataIndex: 'serverId',
      key: 'serverId',
      render: (serverId: string) => {
        const server = servers.find(s => s.id === serverId);
        return server ? server.name : serverId;
      }
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      render: (enabled: boolean) => (
        <Switch checked={enabled} size="small" />
      )
    },
    {
      title: '操作',
      key: 'actions',
      render: (record: MCPTool) => (
        <Space>
          <Button 
            size="small" 
            type="primary"
            icon={<PlayCircleOutlined />}
            onClick={() => {
              setSelectedTool(record);
              setShowToolModal(true);
            }}
          >
            执行
          </Button>
          <Button 
            size="small" 
            icon={<InfoCircleOutlined />}
          >
            详情
          </Button>
        </Space>
      )
    }
  ];

  return (
    <div>
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Title level={4} style={{ margin: 0 }}>
            <ToolOutlined /> MCP工具管理器
          </Title>
          <Space>
            <Button 
              icon={<ReloadOutlined />}
              onClick={loadMCPConfig}
            >
              刷新
            </Button>
            <Button 
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setShowAddModal(true)}
            >
              添加服务器
            </Button>
          </Space>
        </div>

        <Tabs defaultActiveKey="servers">
          <TabPane tab="MCP服务器" key="servers">
            <Table
              columns={serverColumns}
              dataSource={servers}
              rowKey="id"
              size="small"
              pagination={false}
            />
          </TabPane>
          
          <TabPane tab="可用工具" key="tools">
            <Table
              columns={toolColumns}
              dataSource={availableTools.filter(tool => tool.enabled)}
              rowKey="id"
              size="small"
              pagination={false}
            />
          </TabPane>

          <TabPane tab="预设服务器" key="presets">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
              {PRESET_MCP_SERVERS.map(preset => (
                <Card key={preset.id} size="small" hoverable>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                      <Title level={5} style={{ margin: '0 0 8px 0' }}>
                        {preset.name}
                      </Title>
                      <Paragraph style={{ fontSize: '12px', color: '#666', marginBottom: 8 }}>
                        {preset.description}
                      </Paragraph>
                      <div>
                        <Text type="secondary" style={{ fontSize: '11px' }}>
                          工具: {preset.tools.join(', ')}
                        </Text>
                      </div>
                    </div>
                    <Button size="small" type="primary">
                      添加
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          </TabPane>
        </Tabs>
      </Card>

      {/* 添加MCP服务器模态框 */}
      <Modal
        title="添加MCP服务器"
        open={showAddModal}
        onCancel={() => {
          setShowAddModal(false);
          form.resetFields();
        }}
        footer={null}
        width={600}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleAddServer}
        >
          <Form.Item
            name="name"
            label="服务器名称"
            rules={[{ required: true, message: '请输入服务器名称' }]}
          >
            <Input placeholder="例如: 文件系统工具" />
          </Form.Item>

          <Form.Item
            name="description"
            label="描述"
          >
            <Input.TextArea rows={2} placeholder="服务器功能描述" />
          </Form.Item>

          <Form.Item
            name="url"
            label="MCP URL"
            rules={[{ required: true, message: '请输入MCP服务器URL' }]}
          >
            <Input placeholder="mcp://localhost:8080 或 stdio://path/to/server" />
          </Form.Item>

          <Form.Item
            name="autoConnect"
            label="自动连接"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>

          <Divider />

          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setShowAddModal(false)}>
                取消
              </Button>
              <Button type="primary" htmlType="submit">
                添加
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 工具执行模态框 */}
      {selectedTool && (
        <Modal
          title={`执行工具: ${selectedTool.name}`}
          open={showToolModal}
          onCancel={() => {
            setShowToolModal(false);
            setSelectedTool(null);
          }}
          footer={null}
          width={600}
        >
          <Paragraph>{selectedTool.description}</Paragraph>
          
          <Form
            layout="vertical"
            onFinish={(values) => executeTool(selectedTool, values)}
          >
            {selectedTool.parameters.map(param => (
              <Form.Item
                key={param.name}
                name={param.name}
                label={param.name}
                rules={[{ required: param.required, message: `${param.name}是必填项` }]}
              >
                {param.type === 'boolean' ? (
                  <Switch />
                ) : param.type === 'number' ? (
                  <Input type="number" placeholder={param.description} />
                ) : (
                  <Input placeholder={param.description} />
                )}
              </Form.Item>
            ))}

            <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
              <Space>
                <Button onClick={() => setShowToolModal(false)}>
                  取消
                </Button>
                <Button type="primary" htmlType="submit">
                  执行
                </Button>
              </Space>
            </Form.Item>
          </Form>
        </Modal>
      )}
    </div>
  );
};

export default MCPManager;
