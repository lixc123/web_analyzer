import React, { useState, useEffect } from 'react';
import {
  Card,
  Steps,
  Button,
  Space,
  Form,
  Input,
  Select,
  Typography,
  message,
  Alert,
  Row,
  Col,
  Checkbox,
  Progress,
  Tag,
  Divider
} from 'antd';
import {
  FolderOutlined,
  FileOutlined,
  SettingOutlined,
  RocketOutlined,
  CheckCircleOutlined,
  BulbOutlined
} from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;
const { Option } = Select;

// 项目配置接口
interface ProjectConfig {
  name: string;
  description: string;
  type: 'web-crawling' | 'data-analysis' | 'reverse-engineering' | 'security-audit' | 'general';
  directory: string;
  agent: string;
  tools: string[];
  excludePatterns: string[];
  analysisDepth: 'basic' | 'detailed' | 'comprehensive';
  autoAnalysis: boolean;
  sessionSettings: {
    tokenLimit: number;
    compressionThreshold: number;
    autoCompress: boolean;
  };
}

// 项目模板
const PROJECT_TEMPLATES = {
  'web-crawling': {
    name: '网页爬虫项目',
    description: '专注于网页数据抓取和分析的项目配置',
    suggestedAgent: 'crawler-expert',
    tools: ['web-recorder', 'python-executor', 'database'],
    excludePatterns: ['*.log', 'node_modules/**', '__pycache__/**'],
    analysisDepth: 'detailed' as const,
    filePatterns: ['**/*.py', '**/*.js', '**/*.html', '**/*.css'],
    icon: 'crawler'
  },
  'data-analysis': {
    name: '数据分析项目', 
    description: '数据处理、统计分析和可视化项目',
    suggestedAgent: 'data-analyst',
    tools: ['python-executor', 'database', 'filesystem'],
    excludePatterns: ['*.csv', '*.xlsx', 'data/**', 'temp/**'],
    analysisDepth: 'comprehensive' as const,
    filePatterns: ['**/*.py', '**/*.r', '**/*.sql', '**/*.ipynb'],
    icon: 'analysis'
  },
  'reverse-engineering': {
    name: '逆向工程项目',
    description: '软件逆向分析和安全研究项目',
    suggestedAgent: 'reverse-engineer',
    tools: ['python-executor', 'filesystem'],
    excludePatterns: ['*.exe', '*.dll', 'temp/**'],
    analysisDepth: 'comprehensive' as const,
    filePatterns: ['**/*.py', '**/*.c', '**/*.cpp', '**/*.asm'],
    icon: 'reverse'
  },
  'security-audit': {
    name: '安全审计项目',
    description: '安全漏洞扫描和渗透测试项目', 
    suggestedAgent: 'security-analyst',
    tools: ['python-executor', 'database', 'web-recorder'],
    excludePatterns: ['logs/**', '*.log', 'reports/**'],
    analysisDepth: 'detailed' as const,
    filePatterns: ['**/*.py', '**/*.sh', '**/*.ps1', '**/*.yml'],
    icon: 'security'
  },
  'general': {
    name: '通用项目',
    description: '适用于各种开发和分析任务的通用配置',
    suggestedAgent: 'coder-expert',
    tools: ['filesystem', 'python-executor'],
    excludePatterns: ['node_modules/**', '.git/**', '*.log'],
    analysisDepth: 'basic' as const,
    filePatterns: ['**/*'],
    icon: 'general'
  }
};

interface ProjectInitializerProps {
  onInitComplete: (config: ProjectConfig) => void;
  onCancel: () => void;
  visible: boolean;
}

export const ProjectInitializer: React.FC<ProjectInitializerProps> = ({
  onInitComplete,
  onCancel,
  visible
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [projectConfig, setProjectConfig] = useState<Partial<ProjectConfig>>({});
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [isInitializing, setIsInitializing] = useState(false);
  const [initProgress, setInitProgress] = useState(0);
  const [availableAgents, setAvailableAgents] = useState<any[]>([]);
  const [availableTools, setAvailableTools] = useState<any[]>([]);
  const [form] = Form.useForm();

  // 加载可用的智能体和工具
  useEffect(() => {
    if (visible) {
      loadAvailableResources();
    }
  }, [visible]);

  const loadAvailableResources = async () => {
    try {
      // 加载智能体
      const globalConfig = JSON.parse(localStorage.getItem('globalConfig') || '{}');
      const agents = globalConfig.agents?.library || [];
      setAvailableAgents(agents);

      // 加载MCP工具
      const tools = globalConfig.mcp?.tools || [];
      setAvailableTools(tools);
    } catch (error) {
      console.error('加载资源失败:', error);
    }
  };

  // 选择项目模板
  const selectTemplate = (templateId: string) => {
    const template = PROJECT_TEMPLATES[templateId as keyof typeof PROJECT_TEMPLATES];
    setSelectedTemplate(templateId);
    
    setProjectConfig({
      type: templateId as ProjectConfig['type'],
      tools: template.tools,
      excludePatterns: template.excludePatterns,
      analysisDepth: template.analysisDepth,
      autoAnalysis: true,
      sessionSettings: {
        tokenLimit: 4000,
        compressionThreshold: 80,
        autoCompress: true
      }
    });

    // 查找建议的智能体
    const suggestedAgent = availableAgents.find(agent => 
      agent.specialty === template.suggestedAgent || 
      agent.name.toLowerCase().includes(template.suggestedAgent.split('-')[0])
    );

    if (suggestedAgent) {
      setProjectConfig(prev => ({ ...prev, agent: suggestedAgent.id }));
    }
  };

  // 下一步
  const nextStep = () => {
    if (currentStep < 3) {
      setCurrentStep(currentStep + 1);
    }
  };

  // 上一步
  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  // 完成初始化
  const completeInitialization = async () => {
    setIsInitializing(true);
    setInitProgress(0);

    try {
      const values = await form.validateFields();
      const finalConfig: ProjectConfig = {
        ...projectConfig,
        ...values
      } as ProjectConfig;

      // 模拟初始化过程
      for (let i = 0; i <= 100; i += 10) {
        setInitProgress(i);
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      // 保存项目配置到会话存储
      const sessionConfig = {
        project: finalConfig,
        initTime: new Date().toISOString(),
        status: 'initialized'
      };
      
      sessionStorage.setItem('projectConfig', JSON.stringify(sessionConfig));

      message.success('项目初始化完成！');
      onInitComplete(finalConfig);

    } catch (error) {
      message.error(`项目初始化失败: ${error}`);
    } finally {
      setIsInitializing(false);
      setInitProgress(0);
    }
  };

  // 渲染模板选择步骤
  const renderTemplateStep = () => (
    <div>
      <Title level={4}>选择项目模板</Title>
      <Paragraph type="secondary">
        选择最适合你项目需求的模板，系统将自动配置相应的智能体和工具。
      </Paragraph>
      
      <Row gutter={[16, 16]}>
        {Object.entries(PROJECT_TEMPLATES).map(([key, template]) => (
          <Col xs={24} sm={12} md={8} key={key}>
            <Card
              hoverable
              style={{
                border: selectedTemplate === key ? '2px solid #1890ff' : '1px solid #d9d9d9',
                textAlign: 'center'
              }}
              onClick={() => selectTemplate(key)}
            >
              <div style={{ fontSize: '32px', marginBottom: 12 }}>
                {template.icon}
              </div>
              <Title level={5}>{template.name}</Title>
              <Paragraph style={{ fontSize: '12px', marginBottom: 16 }}>
                {template.description}
              </Paragraph>
              <Space orientation="vertical" size="small">
                <Text type="secondary" style={{ fontSize: '11px' }}>
                  建议智能体: {template.suggestedAgent}
                </Text>
                <Text type="secondary" style={{ fontSize: '11px' }}>
                  分析深度: {template.analysisDepth}
                </Text>
              </Space>
            </Card>
          </Col>
        ))}
      </Row>
      
      {selectedTemplate && (
        <Alert
          style={{ marginTop: 16 }}
          type="info"
          showIcon
          title={`模板信息: ${selectedTemplate}`}
          description={
            <div>
              <p>已选择: <strong>{PROJECT_TEMPLATES[selectedTemplate as keyof typeof PROJECT_TEMPLATES].name}</strong></p>
              <p>建议工具: {PROJECT_TEMPLATES[selectedTemplate as keyof typeof PROJECT_TEMPLATES].tools.join(', ')}</p>
            </div>
          }
        />
      )}
    </div>
  );

  // 渲染基本配置步骤
  const renderBasicConfigStep = () => (
    <Form form={form} layout="vertical">
      <Title level={4}>项目基本信息</Title>
      
      <Row gutter={16}>
        <Col span={12}>
          <Form.Item
            name="name"
            label="项目名称"
            rules={[{ required: true, message: '请输入项目名称' }]}
          >
            <Input placeholder="例如: 电商网站爬虫" />
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item
            name="directory"
            label="项目目录"
            rules={[{ required: true, message: '请选择项目目录' }]}
          >
            <Space.Compact style={{ width: '100%' }}>
              <Input 
                placeholder="/path/to/project" 
                style={{ width: 'calc(100% - 60px)' }}
              />
              <Button icon={<FolderOutlined />} size="small">
                选择
              </Button>
            </Space.Compact>
          </Form.Item>
        </Col>
      </Row>

      <Form.Item
        name="description"
        label="项目描述"
      >
        <TextArea rows={3} placeholder="简要描述项目目标和功能..." />
      </Form.Item>

      <Row gutter={16}>
        <Col span={12}>
          <Form.Item
            name="agent"
            label="指派智能体"
            initialValue={projectConfig.agent}
          >
            <Select placeholder="选择专家智能体">
              {availableAgents.map(agent => (
                <Option key={agent.id} value={agent.id}>
                  <Space>
                    <span>{agent.avatar || 'AI'}</span>
                    <span>{agent.name}</span>
                    <Tag>{agent.specialty}</Tag>
                  </Space>
                </Option>
              ))}
            </Select>
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item
            name="analysisDepth"
            label="分析深度"
            initialValue={projectConfig.analysisDepth}
          >
            <Select>
              <Option value="basic">基础扫描</Option>
              <Option value="detailed">详细分析</Option>
              <Option value="comprehensive">全面审查</Option>
            </Select>
          </Form.Item>
        </Col>
      </Row>
    </Form>
  );

  // 渲染高级配置步骤
  const renderAdvancedConfigStep = () => (
    <Form form={form} layout="vertical">
      <Title level={4}>高级配置</Title>
      
      <Form.Item
        name="tools"
        label="启用工具"
        initialValue={projectConfig.tools}
      >
        <Checkbox.Group>
          <Row>
            {availableTools.map(tool => (
              <Col span={8} key={tool.id}>
                <Checkbox value={tool.id}>
                  <Space>
                    <span>{tool.category === 'file' ? 'FILE' : 
                          tool.category === 'database' ? 'DB' :
                          tool.category === 'automation' ? 'AUTO' : 'TOOL'}</span>
                    <span>{tool.name}</span>
                  </Space>
                </Checkbox>
              </Col>
            ))}
          </Row>
        </Checkbox.Group>
      </Form.Item>

      <Form.Item
        name="excludePatterns"
        label="排除模式"
        initialValue={projectConfig.excludePatterns}
      >
        <Select
          mode="tags"
          style={{ width: '100%' }}
          placeholder="添加排除的文件模式，如 *.log, node_modules/**"
          tokenSeparators={[',']}
        >
          <Option value="*.log">*.log</Option>
          <Option value="node_modules/**">node_modules/**</Option>
          <Option value="__pycache__/**">__pycache__/**</Option>
          <Option value=".git/**">.git/**</Option>
        </Select>
      </Form.Item>

      <Divider />

      <Title level={5}>会话设置</Title>
      <Row gutter={16}>
        <Col span={8}>
          <Form.Item
            name={['sessionSettings', 'tokenLimit']}
            label="Token限制"
            initialValue={projectConfig.sessionSettings?.tokenLimit}
          >
            <Select>
              <Option value={2000}>2K (轻量)</Option>
              <Option value={4000}>4K (标准)</Option>
              <Option value={8000}>8K (扩展)</Option>
              <Option value={16000}>16K (大型)</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item
            name={['sessionSettings', 'compressionThreshold']}
            label="压缩阈值(%)"
            initialValue={projectConfig.sessionSettings?.compressionThreshold}
          >
            <Select>
              <Option value={70}>70%</Option>
              <Option value={80}>80%</Option>
              <Option value={90}>90%</Option>
            </Select>
          </Form.Item>
        </Col>
        <Col span={8}>
          <Form.Item
            name={['sessionSettings', 'autoCompress']}
            label="自动压缩"
            valuePropName="checked"
            initialValue={projectConfig.sessionSettings?.autoCompress}
          >
            <Checkbox>启用自动压缩</Checkbox>
          </Form.Item>
        </Col>
      </Row>
    </Form>
  );

  // 渲染确认步骤
  const renderConfirmStep = () => (
    <div>
      <Title level={4}>确认配置</Title>
      <Alert
        type="info"
        showIcon
        title="请确认以下配置信息"
        description="配置将保存到当前会话，可以随时修改。"
        style={{ marginBottom: 16 }}
      />

      <Card size="small">
        <Row gutter={[16, 16]}>
          <Col span={12}>
            <Text strong>项目类型:</Text>
            <div>{PROJECT_TEMPLATES[selectedTemplate as keyof typeof PROJECT_TEMPLATES]?.name}</div>
          </Col>
          <Col span={12}>
            <Text strong>分析深度:</Text>
            <div>{projectConfig.analysisDepth}</div>
          </Col>
          <Col span={12}>
            <Text strong>智能体:</Text>
            <div>{availableAgents.find(a => a.id === projectConfig.agent)?.name}</div>
          </Col>
          <Col span={12}>
            <Text strong>Token限制:</Text>
            <div>{projectConfig.sessionSettings?.tokenLimit}K</div>
          </Col>
          <Col span={24}>
            <Text strong>启用工具:</Text>
            <div style={{ marginTop: 4 }}>
              <Space wrap>
                {(projectConfig.tools || []).map(toolId => {
                  const tool = availableTools.find(t => t.id === toolId);
                  return tool ? <Tag key={toolId}>{tool.name}</Tag> : null;
                })}
              </Space>
            </div>
          </Col>
        </Row>
      </Card>

      {isInitializing && (
        <Card size="small" style={{ marginTop: 16 }}>
          <Progress 
            percent={initProgress}
            status="active"
            format={percent => `初始化中... ${percent}%`}
          />
        </Card>
      )}
    </div>
  );

  const steps = [
    {
      title: '选择模板',
      icon: <FileOutlined />,
      content: renderTemplateStep()
    },
    {
      title: '基本配置', 
      icon: <SettingOutlined />,
      content: renderBasicConfigStep()
    },
    {
      title: '高级设置',
      icon: <BulbOutlined />,
      content: renderAdvancedConfigStep()
    },
    {
      title: '确认初始化',
      icon: <RocketOutlined />,
      content: renderConfirmStep()
    }
  ];

  if (!visible) return null;

  return (
    <Card style={{ width: '100%', maxWidth: 1000 }}>
      <Title level={3} style={{ textAlign: 'center', marginBottom: 24 }}>
        <RocketOutlined /> 项目初始化向导
      </Title>

      <Steps 
        current={currentStep} 
        style={{ marginBottom: 32 }}
        items={steps.map((step, index) => ({
          key: index,
          title: step.title,
          icon: step.icon
        }))}
      />

      <div style={{ minHeight: 400, marginBottom: 24 }}>
        {steps[currentStep].content}
      </div>

      <div style={{ textAlign: 'right' }}>
        <Space>
          <Button onClick={onCancel}>
            取消
          </Button>
          {currentStep > 0 && (
            <Button onClick={prevStep}>
              上一步
            </Button>
          )}
          {currentStep < steps.length - 1 && (
            <Button 
              type="primary" 
              onClick={nextStep}
              disabled={currentStep === 0 && !selectedTemplate}
            >
              下一步
            </Button>
          )}
          {currentStep === steps.length - 1 && (
            <Button 
              type="primary" 
              onClick={completeInitialization}
              loading={isInitializing}
              icon={<CheckCircleOutlined />}
            >
              完成初始化
            </Button>
          )}
        </Space>
      </div>
    </Card>
  );
};

export default ProjectInitializer;
