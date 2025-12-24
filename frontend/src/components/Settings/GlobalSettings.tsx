import React, { useState, useEffect } from 'react';
import {
  Card,
  Tabs,
  Button,
  Space,
  Form,
  Input,
  Select,
  Switch,
  Typography,
  message,
  Divider,
  Alert,
  Row,
  Col,
  Tag,
  Modal,
  Tooltip
} from 'antd';
import {
  SettingOutlined,
  SaveOutlined,
  ReloadOutlined,
  ExportOutlined,
  ImportOutlined,
  DeleteOutlined,
  ApiOutlined,
  RobotOutlined,
  BulbOutlined,
  EyeOutlined,
  SecurityScanOutlined,
  ExclamationCircleOutlined
} from '@ant-design/icons';
import MCPManager from '../MCP/MCPManager';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;
const { TextArea } = Input;
const { Option } = Select;

// 全局配置接口
interface GlobalConfig {
  mcp: {
    servers: any[];
    tools: any[];
    autoConnect: boolean;
    defaultTimeout: number;
  };
  agents: {
    library: any[];
    current: any;
    autoSwitch: boolean;
    defaultAgent: string;
  };
  ui: {
    theme: 'light' | 'dark' | 'auto';
    language: 'zh-CN' | 'en-US';
    compactMode: boolean;
    animations: boolean;
    autoSave: boolean;
  };
  auth: {
    defaultProvider: 'qwen' | 'openai';
    rememberCredentials: boolean;
    sessionTimeout: number;
  };
  analysis: {
    defaultDepth: 'basic' | 'detailed' | 'comprehensive';
    autoAnalyze: boolean;
    batchSize: number;
    cacheResults: boolean;
  };
  session: {
    defaultTokenLimit: number;
    autoCompress: boolean;
    compressionThreshold: number;
    saveHistory: boolean;
    maxHistoryItems: number;
  };
  advanced: {
    debugMode: boolean;
    logLevel: 'error' | 'warn' | 'info' | 'debug';
    performance: boolean;
    experimentalFeatures: boolean;
  };
}

const DEFAULT_CONFIG: GlobalConfig = {
  mcp: {
    servers: [],
    tools: [],
    autoConnect: true,
    defaultTimeout: 30000
  },
  agents: {
    library: [],
    current: null,
    autoSwitch: false,
    defaultAgent: ''
  },
  ui: {
    theme: 'light',
    language: 'zh-CN',
    compactMode: false,
    animations: true,
    autoSave: true
  },
  auth: {
    defaultProvider: 'qwen',
    rememberCredentials: true,
    sessionTimeout: 3600
  },
  analysis: {
    defaultDepth: 'detailed',
    autoAnalyze: true,
    batchSize: 10,
    cacheResults: true
  },
  session: {
    defaultTokenLimit: 4000,
    autoCompress: true,
    compressionThreshold: 80,
    saveHistory: true,
    maxHistoryItems: 100
  },
  advanced: {
    debugMode: false,
    logLevel: 'info',
    performance: true,
    experimentalFeatures: false
  }
};

interface GlobalSettingsProps {
  visible: boolean;
  onClose: () => void;
}

export const GlobalSettings: React.FC<GlobalSettingsProps> = ({
  visible,
  onClose
}) => {
  const [config, setConfig] = useState<GlobalConfig>(DEFAULT_CONFIG);
  const [activeTab, setActiveTab] = useState('ui');
  const [hasChanges, setHasChanges] = useState(false);
  const [form] = Form.useForm();

  // 加载配置
  useEffect(() => {
    if (visible) {
      loadConfig();
    }
  }, [visible]);

  const loadConfig = () => {
    try {
      const savedConfig = localStorage.getItem('globalConfig');
      if (savedConfig) {
        const parsed = JSON.parse(savedConfig);
        const mergedConfig = { ...DEFAULT_CONFIG, ...parsed };
        setConfig(mergedConfig);
        form.setFieldsValue(mergedConfig);
      }
    } catch (error) {
      console.error('加载配置失败:', error);
      message.error('加载配置失败，使用默认配置');
    }
  };

  // 保存配置
  const saveConfig = async () => {
    try {
      const values = await form.validateFields();
      const newConfig = { ...config, ...values };
      
      localStorage.setItem('globalConfig', JSON.stringify(newConfig));
      setConfig(newConfig);
      setHasChanges(false);
      
      message.success('配置已保存');
      
      // 触发配置更新事件
      window.dispatchEvent(new CustomEvent('globalConfigUpdated', { 
        detail: newConfig 
      }));
      
    } catch (error) {
      message.error('保存配置失败');
    }
  };

  // 重置配置
  const resetConfig = () => {
    Modal.confirm({
      title: '确认重置',
      icon: <ExclamationCircleOutlined />,
      content: '这将重置所有设置为默认值，此操作不可撤销。',
      onOk: () => {
        setConfig(DEFAULT_CONFIG);
        form.setFieldsValue(DEFAULT_CONFIG);
        setHasChanges(true);
        message.success('配置已重置为默认值');
      }
    });
  };

  // 导出配置
  const exportConfig = () => {
    const dataStr = JSON.stringify(config, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = 'web-analyzer-config.json';
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
    
    message.success('配置已导出');
  };

  // 导入配置
  const importConfig = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
          try {
            const importedConfig = JSON.parse(e.target?.result as string);
            const mergedConfig = { ...DEFAULT_CONFIG, ...importedConfig };
            setConfig(mergedConfig);
            form.setFieldsValue(mergedConfig);
            setHasChanges(true);
            message.success('配置已导入');
          } catch (error) {
            message.error('配置文件格式错误');
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };

  // 监听表单变化
  const handleFormChange = () => {
    setHasChanges(true);
  };

  // 渲染界面设置
  const renderUISettings = () => (
    <Form form={form} layout="vertical" onValuesChange={handleFormChange}>
      <Title level={5}>外观设置</Title>
      <Row gutter={16}>
        <Col span={8}>
          <Form.Item name={['ui', 'theme']} label="主题">
            <Select>
              <Option value="light">浅色</Option>
              <Option value="dark">深色</Option>
              <Option value="auto">跟随系统</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['ui', 'language']} label="语言">
            <Select>
              <Option value="zh-CN">简体中文</Option>
              <Option value="en-US">English</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['ui', 'compactMode']} label="紧凑模式" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={8}>
          <Form.Item name={['ui', 'animations']} label="动画效果" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['ui', 'autoSave']} label="自动保存" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
      </Row>

      <Divider />

      <Title level={5}>认证设置</Title>
      <Row gutter={16}>
        <Col span={12}>
          <Form.Item name={['auth', 'defaultProvider']} label="默认提供商">
            <Select>
              <Option value="qwen">Qwen OAuth</Option>
              <Option value="openai">OpenAI API</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item name={['auth', 'sessionTimeout']} label="会话超时(秒)">
            <Select>
              <Option value={1800}>30分钟</Option>
              <Option value={3600}>1小时</Option>
              <Option value={7200}>2小时</Option>
              <Option value={14400}>4小时</Option>
            </Select>
          </Form.Item>
        </Col>
      </Row>

      <Form.Item name={['auth', 'rememberCredentials']} label="记住登录信息" valuePropName="checked">
        <Switch />
      </Form.Item>
    </Form>
  );

  // 渲染分析设置
  const renderAnalysisSettings = () => (
    <Form form={form} layout="vertical" onValuesChange={handleFormChange}>
      <Title level={5}>分析配置</Title>
      <Row gutter={16}>
        <Col span={8}>
          <Form.Item name={['analysis', 'defaultDepth']} label="默认分析深度">
            <Select>
              <Option value="basic">基础扫描</Option>
              <Option value="detailed">详细分析</Option>
              <Option value="comprehensive">全面审查</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['analysis', 'batchSize']} label="批处理大小">
            <Select>
              <Option value={5}>5个文件</Option>
              <Option value={10}>10个文件</Option>
              <Option value={20}>20个文件</Option>
              <Option value={50}>50个文件</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['analysis', 'autoAnalyze']} label="自动分析" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
      </Row>

      <Form.Item name={['analysis', 'cacheResults']} label="缓存分析结果" valuePropName="checked">
        <Switch />
      </Form.Item>

      <Divider />

      <Title level={5}>会话管理</Title>
      <Row gutter={16}>
        <Col span={8}>
          <Form.Item name={['session', 'defaultTokenLimit']} label="默认Token限制">
            <Select>
              <Option value={2000}>2K</Option>
              <Option value={4000}>4K</Option>
              <Option value={8000}>8K</Option>
              <Option value={16000}>16K</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['session', 'compressionThreshold']} label="压缩阈值(%)">
            <Select>
              <Option value={70}>70%</Option>
              <Option value={80}>80%</Option>
              <Option value={90}>90%</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item name={['session', 'maxHistoryItems']} label="历史记录数">
            <Select>
              <Option value={50}>50条</Option>
              <Option value={100}>100条</Option>
              <Option value={200}>200条</Option>
              <Option value={500}>500条</Option>
            </Select>
          </Form.Item>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={12}>
          <Form.Item name={['session', 'autoCompress']} label="自动压缩" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item name={['session', 'saveHistory']} label="保存历史" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
      </Row>
    </Form>
  );

  // 渲染高级设置
  const renderAdvancedSettings = () => (
    <Form form={form} layout="vertical" onValuesChange={handleFormChange}>
      <Alert
        type="warning"
        showIcon
        title="高级设置"
        description="这些设置可能影响系统性能和稳定性，请谨慎修改。"
        style={{ marginBottom: 16 }}
      />

      <Title level={5}>调试选项</Title>
      <Row gutter={16}>
        <Col span={12}>
          <Form.Item name={['advanced', 'debugMode']} label="调试模式" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item name={['advanced', 'logLevel']} label="日志级别">
            <Select>
              <Option value="error">错误</Option>
              <Option value="warn">警告</Option>
              <Option value="info">信息</Option>
              <Option value="debug">调试</Option>
            </Select>
          </Form.Item>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={12}>
          <Form.Item name={['advanced', 'performance']} label="性能监控" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item name={['advanced', 'experimentalFeatures']} label="实验性功能" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
      </Row>

      <Divider />

      <Title level={5}>MCP配置</Title>
      <Row gutter={16}>
        <Col span={12}>
          <Form.Item name={['mcp', 'autoConnect']} label="自动连接MCP服务器" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item name={['mcp', 'defaultTimeout']} label="连接超时(毫秒)">
            <Select>
              <Option value={10000}>10秒</Option>
              <Option value={30000}>30秒</Option>
              <Option value={60000}>60秒</Option>
            </Select>
          </Form.Item>
        </Col>
      </Row>
    </Form>
  );

  // 渲染配置概览
  const renderConfigOverview = () => (
    <div>
      <Alert
        type="info"
        showIcon
        title="配置概览"
        description="当前系统配置的总体状态和关键信息。"
        style={{ marginBottom: 16 }}
      />

      <Row gutter={[16, 16]}>
        <Col span={12}>
          <Card size="small" title="MCP服务器">
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Text>
                已配置: <Tag color="blue">{config.mcp?.servers?.length || 0}</Tag>
              </Text>
              <Text>
                可用工具: <Tag color="green">{config.mcp?.tools?.length || 0}</Tag>
              </Text>
              <Text>
                自动连接: <Tag color={config.mcp?.autoConnect ? 'success' : 'default'}>
                  {config.mcp?.autoConnect ? '开启' : '关闭'}
                </Tag>
              </Text>
            </Space>
          </Card>
        </Col>

        <Col span={12}>
          <Card size="small" title="智能体">
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Text>
                智能体库: <Tag color="blue">{config.agents?.library?.length || 0}</Tag>
              </Text>
              <Text>
                当前智能体: <Tag color="green">
                  {config.agents?.current?.name || '未设置'}
                </Tag>
              </Text>
              <Text>
                自动切换: <Tag color={config.agents?.autoSwitch ? 'success' : 'default'}>
                  {config.agents?.autoSwitch ? '开启' : '关闭'}
                </Tag>
              </Text>
            </Space>
          </Card>
        </Col>

        <Col span={12}>
          <Card size="small" title="会话设置">
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Text>
                Token限制: <Tag color="blue">{config.session?.defaultTokenLimit}K</Tag>
              </Text>
              <Text>
                压缩阈值: <Tag color="orange">{config.session?.compressionThreshold}%</Tag>
              </Text>
              <Text>
                自动压缩: <Tag color={config.session?.autoCompress ? 'success' : 'default'}>
                  {config.session?.autoCompress ? '开启' : '关闭'}
                </Tag>
              </Text>
            </Space>
          </Card>
        </Col>

        <Col span={12}>
          <Card size="small" title="系统状态">
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Text>
                主题: <Tag color="blue">{config.ui?.theme}</Tag>
              </Text>
              <Text>
                调试模式: <Tag color={config.advanced?.debugMode ? 'warning' : 'success'}>
                  {config.advanced?.debugMode ? '开启' : '关闭'}
                </Tag>
              </Text>
              <Text>
                实验性功能: <Tag color={config.advanced?.experimentalFeatures ? 'purple' : 'default'}>
                  {config.advanced?.experimentalFeatures ? '开启' : '关闭'}
                </Tag>
              </Text>
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );

  if (!visible) return null;

  return (
    <Modal
      title={
        <Space>
          <SettingOutlined />
          <span>全局设置</span>
          {hasChanges && <Tag color="orange">有未保存更改</Tag>}
        </Space>
      }
      open={visible}
      onCancel={onClose}
      width={1200}
      footer={
        <Space>
          <Button onClick={onClose}>
            取消
          </Button>
          <Button icon={<ReloadOutlined />} onClick={resetConfig}>
            重置
          </Button>
          <Button icon={<ImportOutlined />} onClick={importConfig}>
            导入
          </Button>
          <Button icon={<ExportOutlined />} onClick={exportConfig}>
            导出
          </Button>
          <Button 
            type="primary" 
            icon={<SaveOutlined />} 
            onClick={saveConfig}
            disabled={!hasChanges}
          >
            保存设置
          </Button>
        </Space>
      }
    >
      <Tabs 
        activeKey={activeTab} 
        onChange={setActiveTab}
        items={[
          {
            key: 'overview',
            label: (
              <Space>
                <EyeOutlined />
                概览
              </Space>
            ),
            children: renderConfigOverview()
          },
          {
            key: 'ui',
            label: (
              <Space>
                <BulbOutlined />
                界面与认证
              </Space>
            ),
            children: renderUISettings()
          },
          {
            key: 'analysis',
            label: (
              <Space>
                <SecurityScanOutlined />
                分析与会话
              </Space>
            ),
            children: renderAnalysisSettings()
          },
          {
            key: 'mcp',
            label: (
              <Space>
                <ApiOutlined />
                MCP工具
              </Space>
            ),
            children: <MCPManager />
          },
          {
            key: 'agents',
            label: (
              <Space>
                <RobotOutlined />
                智能体
              </Space>
            ),
            children: (
              <div style={{ padding: '20px', textAlign: 'center', color: '#999' }}>
                <RobotOutlined style={{ fontSize: '48px', marginBottom: '16px' }} />
                <p>AI智能体功能已移除</p>
                <p>此应用现在专注于网络流量录制和分析</p>
              </div>
            )
          },
          {
            key: 'advanced',
            label: (
              <Space>
                <SettingOutlined />
                高级
              </Space>
            ),
            children: renderAdvancedSettings()
          }
        ]}
      />
    </Modal>
  );
};

export default GlobalSettings;
