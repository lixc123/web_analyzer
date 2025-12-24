import React, { useState, useRef } from 'react';
import { Space, Button, Dropdown, Typography, Tag, AutoComplete } from 'antd';
import { SendOutlined, ToolOutlined, BulbOutlined } from '@ant-design/icons';
import { useAuth } from '../Auth/AuthProvider';

const { Text } = Typography;

// 命令类型定义
export interface Command {
  name: string;
  description: string;
  category: 'session' | 'model' | 'analysis' | 'system' | 'help';
  aliases?: string[];
  args?: CommandArg[];
  examples?: string[];
}

export interface CommandArg {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'select';
  required?: boolean;
  description?: string;
  options?: string[];
}

// qwen-code命令映射到Web版本 - 完整增强版
const WEB_COMMANDS: Command[] = [
  // MCP工具管理命令 - 极高优先级
  {
    name: 'mcp',
    description: 'MCP服务器和工具管理',
    category: 'system',
    args: [
      { name: 'action', type: 'select', options: ['list', 'connect', 'disconnect', 'status'], required: false },
      { name: 'server_id', type: 'string', description: '服务器ID' },
    ],
    examples: ['/mcp', '/mcp list', '/mcp connect filesystem', '/mcp status'],
  },
  {
    name: 'tools',
    description: '显示和管理MCP工具',
    category: 'system',
    args: [
      { name: 'action', type: 'select', options: ['list', 'execute', 'help'], required: false },
      { name: 'tool_name', type: 'string', description: '工具名称' },
    ],
    examples: ['/tools', '/tools list', '/tools execute read_file', '/tools help'],
  },

  // 智能体管理命令 - 高优先级
  {
    name: 'agents',
    description: '智能体库管理',
    category: 'system',
    args: [
      { name: 'action', type: 'select', options: ['list', 'switch', 'create', 'info'], required: false },
      { name: 'agent_name', type: 'string', description: '智能体名称或ID' },
    ],
    examples: ['/agents', '/agents list', '/agents switch crawler-expert', '/agents info'],
  },
  {
    name: 'use-agent',
    description: '为当前会话指派专家智能体',
    category: 'session',
    args: [
      { name: 'agent_name', type: 'string', description: '智能体名称', required: true },
    ],
    examples: ['/use-agent crawler-expert', '/use-agent security-analyst'],
  },

  // 项目和文件管理命令
  {
    name: 'init',
    description: '初始化当前项目配置',
    category: 'system',
    args: [
      { name: 'project_type', type: 'select', options: ['web-crawling', 'data-analysis', 'reverse-engineering', 'security-audit', 'general'], required: false },
    ],
    examples: ['/init', '/init web-crawling', '/init security-audit'],
  },
  {
    name: 'directory',
    description: '扫描和分析项目目录',
    category: 'analysis',
    args: [
      { name: 'action', type: 'select', options: ['scan', 'analyze', 'select'], required: false },
      { name: 'path', type: 'string', description: '目录路径' },
    ],
    examples: ['/directory', '/directory scan /path/to/project', '/directory analyze'],
  },
  {
    name: 'files',
    description: '文件选择和分析',
    category: 'analysis',
    args: [
      { name: 'action', type: 'select', options: ['select', 'analyze', 'clear'], required: false },
      { name: 'pattern', type: 'string', description: '文件模式' },
    ],
    examples: ['/files', '/files select *.py', '/files analyze', '/files clear'],
  },

  // 会话管理命令 - 中优先级
  {
    name: 'compress',
    description: '压缩会话历史以节省token',
    category: 'session',
    args: [
      { name: 'strategy', type: 'select', options: ['conservative', 'balanced', 'aggressive'], required: false },
    ],
    examples: ['/compress', '/compress balanced', '/compress aggressive'],
  },
  {
    name: 'clear',
    description: '清除当前会话历史',
    category: 'session',
    examples: ['/clear'],
  },
  {
    name: 'stats',
    description: '显示当前会话统计信息',
    category: 'session',
    examples: ['/stats'],
  },
  {
    name: 'memory',
    description: '管理对话记忆',
    category: 'session',
    args: [
      { name: 'action', type: 'select', options: ['show', 'add', 'clear'], required: true },
      { name: 'content', type: 'string', description: '记忆内容' },
    ],
    examples: ['/memory show', '/memory add "重要信息"', '/memory clear'],
  },
  {
    name: 'context',
    description: '管理会话上下文',
    category: 'session',
    args: [
      { name: 'action', type: 'select', options: ['show', 'set', 'clear'], required: true },
      { name: 'context_data', type: 'string', description: '上下文数据' },
    ],
    examples: ['/context show', '/context set project_info', '/context clear'],
  },
  
  // 模型管理命令
  {
    name: 'model',
    description: '切换AI模型',
    category: 'model',
    args: [
      { name: 'model_name', type: 'select', options: ['qwen-coder', 'qwen-plus', 'qwen-vision', 'gpt-4', 'gpt-3.5-turbo'], required: false },
    ],
    examples: ['/model', '/model qwen-coder', '/model qwen-vision'],
  },
  {
    name: 'auth',
    description: '切换认证方式',
    category: 'model',
    examples: ['/auth'],
  },
  
  // 分析命令
  {
    name: 'analyze',
    description: '分析指定内容',
    category: 'analysis',
    args: [
      { name: 'type', type: 'select', options: ['code', 'requests', 'entropy', 'security', 'files'], required: true },
      { name: 'target', type: 'string', description: '分析目标' },
    ],
    examples: ['/analyze code', '/analyze files selected', '/analyze security'],
  },
  {
    name: 'export',
    description: '导出分析结果',
    category: 'analysis',
    args: [
      { name: 'format', type: 'select', options: ['json', 'csv', 'pdf', 'markdown'], required: true },
      { name: 'session_id', type: 'string', description: '会话ID' },
    ],
    examples: ['/export json', '/export pdf current', '/export markdown'],
  },
  {
    name: 'report',
    description: '生成项目分析报告',
    category: 'analysis',
    args: [
      { name: 'type', type: 'select', options: ['summary', 'detailed', 'security'], required: false },
    ],
    examples: ['/report', '/report detailed', '/report security'],
  },
  
  // 系统命令
  {
    name: 'settings',
    description: '打开全局设置面板',
    category: 'system',
    examples: ['/settings'],
  },
  {
    name: 'theme',
    description: '切换主题',
    category: 'system',
    args: [
      { name: 'theme', type: 'select', options: ['light', 'dark', 'auto'], required: true },
    ],
    examples: ['/theme dark', '/theme light', '/theme auto'],
  },
  {
    name: 'workspace',
    description: '工作区设置',
    category: 'system',
    args: [
      { name: 'action', type: 'select', options: ['load', 'save', 'reset'], required: false },
    ],
    examples: ['/workspace', '/workspace save', '/workspace load'],
  },
  
  // 帮助命令
  {
    name: 'help',
    description: '显示帮助信息',
    category: 'help',
    aliases: ['?'],
    args: [
      { name: 'command', type: 'string', description: '特定命令名称' },
    ],
    examples: ['/help', '/help mcp', '/help agents', '/?'],
  },
  {
    name: 'docs',
    description: '打开文档',
    category: 'help',
    examples: ['/docs'],
  },
  {
    name: 'version',
    description: '显示版本信息',
    category: 'help',
    examples: ['/version'],
  },
];

interface CommandInputProps {
  onCommand: (command: string, args: any[]) => Promise<void>;
  onMessage: (message: string) => Promise<void>;
  disabled?: boolean;
  placeholder?: string;
}

export const CommandInput: React.FC<CommandInputProps> = ({
  onCommand,
  onMessage,
  disabled = false,
  placeholder = "输入消息或使用 / 开始命令...",
}) => {
  const { isAuthenticated } = useAuth();
  const [input, setInput] = useState('');
  const [suggestions, setSuggestions] = useState<{ value: string; label: React.ReactNode }[]>([]);
  const [showCommandHelp, setShowCommandHelp] = useState(false);
  const inputRef = useRef<any>(null);

  // 解析输入中的命令
  const parseCommand = (text: string) => {
    if (!text.startsWith('/')) return null;
    
    const parts = text.slice(1).split(' ');
    const commandName = parts[0];
    const args = parts.slice(1);
    
    const command = WEB_COMMANDS.find(cmd => 
      cmd.name === commandName || cmd.aliases?.includes(commandName)
    );
    
    return command ? { command, args } : null;
  };

  // 生成命令建议
  const generateSuggestions = (text: string) => {
    if (!text.startsWith('/')) {
      setSuggestions([]);
      return;
    }

    const commandText = text.slice(1);
    const filteredCommands = WEB_COMMANDS.filter(cmd =>
      cmd.name.toLowerCase().includes(commandText.toLowerCase()) ||
      cmd.aliases?.some(alias => alias.toLowerCase().includes(commandText.toLowerCase()))
    );

    const suggestions = filteredCommands.map(cmd => ({
      value: `/${cmd.name}`,
      label: (
        <div style={{ padding: '4px 0' }}>
          <Space>
            <Text strong>/{cmd.name}</Text>
            <Tag color="blue">{cmd.category}</Tag>
          </Space>
          <div style={{ fontSize: '12px', color: '#666', marginTop: 2 }}>
            {cmd.description}
          </div>
          {cmd.examples && (
            <div style={{ fontSize: '11px', color: '#999', marginTop: 2 }}>
              示例: {cmd.examples[0]}
            </div>
          )}
        </div>
      ),
    }));

    setSuggestions(suggestions);
  };

  // 处理输入变化
  const handleInputChange = (value: string) => {
    setInput(value);
    generateSuggestions(value);
    
    // 显示命令帮助
    setShowCommandHelp(value.startsWith('/') && value.length > 1);
  };

  // 处理发送
  const handleSend = async () => {
    if (!input.trim()) return;
    
    const parsedCommand = parseCommand(input);
    
    if (parsedCommand) {
      // 执行命令
      await onCommand(parsedCommand.command.name, parsedCommand.args);
    } else {
      // 发送普通消息
      await onMessage(input);
    }
    
    setInput('');
    setSuggestions([]);
    setShowCommandHelp(false);
  };

  // 处理键盘事件
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    } else if (e.key === 'Tab' && suggestions.length > 0) {
      e.preventDefault();
      setInput(suggestions[0].value);
      setSuggestions([]);
    }
  };

  // 快捷命令菜单
  const quickCommands = [
    { key: 'help', label: '帮助 (/help)', icon: <BulbOutlined /> },
    { key: 'clear', label: '清除会话 (/clear)', icon: <ToolOutlined /> },
    { key: 'stats', label: '会话统计 (/stats)', icon: <ToolOutlined /> },
    { key: 'model', label: '切换模型 (/model)', icon: <ToolOutlined /> },
  ];

  const handleQuickCommand = (key: string) => {
    setInput(`/${key} `);
    inputRef.current?.focus();
  };

  return (
    <div>
      <Space.Compact style={{ width: '100%' }}>
        <AutoComplete
          ref={inputRef}
          value={input}
          onChange={handleInputChange}
          onKeyDown={handleKeyPress}
          options={suggestions}
          style={{ flex: 1 }}
          disabled={disabled || !isAuthenticated}
          placeholder={isAuthenticated ? placeholder : "请先登录..."}
          filterOption={false}
          notFoundContent={null}
          dropdownMatchSelectWidth={false}
          dropdownStyle={{ minWidth: 300 }}
        />
        
        <Dropdown
          menu={{
            items: quickCommands.map(cmd => ({
              key: cmd.key,
              label: cmd.label,
              icon: cmd.icon,
              onClick: () => handleQuickCommand(cmd.key),
            })),
          }}
          trigger={['click']}
          disabled={disabled || !isAuthenticated}
        >
          <Button icon={<ToolOutlined />} />
        </Dropdown>
        
        <Button
          type="primary"
          icon={<SendOutlined />}
          onClick={handleSend}
          disabled={disabled || !isAuthenticated || !input.trim()}
        />
      </Space.Compact>

      {/* 命令帮助提示 */}
      {showCommandHelp && (
        <div style={{ 
          marginTop: 8, 
          padding: 8, 
          background: '#f6ffed', 
          border: '1px solid #b7eb8f',
          borderRadius: 4 
        }}>
          <Text type="secondary" style={{ fontSize: '12px' }}>
            提示: 使用 Tab 键快速补全命令，Enter 发送，Shift+Enter 换行
          </Text>
        </div>
      )}

      {/* 可用命令类别显示 */}
      {input === '/' && (
        <div style={{ marginTop: 8 }}>
          <Text type="secondary" style={{ fontSize: '12px' }}>
            可用命令类别:
          </Text>
          <div style={{ marginTop: 4 }}>
            <Space wrap>
              <Tag color="green">session (会话管理)</Tag>
              <Tag color="blue">model (模型管理)</Tag>
              <Tag color="orange">analysis (分析工具)</Tag>
              <Tag color="purple">system (系统设置)</Tag>
              <Tag color="cyan">help (帮助信息)</Tag>
            </Space>
          </div>
        </div>
      )}
    </div>
  );
};

export default CommandInput;
