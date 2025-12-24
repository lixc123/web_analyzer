# Web Analyzer 命令分类设计

## 全局设置命令 (Global Settings)
这些命令影响整个应用的配置，跨所有会话生效：

### MCP & 工具管理
- `/mcp` - MCP服务器管理（连接/断开/配置）
- `/tools` - 显示和管理可用工具
- `/mcp-config` - MCP服务器配置

### 智能体管理  
- `/agents` - 全局智能体库管理
- `/agent-create` - 创建新的专家智能体
- `/agent-import` - 导入智能体配置

### 认证与模型
- `/auth` - 切换认证方式
- `/model` - 切换默认模型（全局）
- `/providers` - 管理API提供商

### 界面与系统
- `/theme` - 主题设置
- `/settings` - 全局系统设置
- `/docs` - 打开文档

## 项目/会话设置命令 (Project/Session Settings)
这些命令只影响当前会话或特定项目：

### 项目初始化
- `/init` - 初始化当前项目配置
- `/project-config` - 项目特定配置
- `/workspace` - 工作区设置

### 文件与目录
- `/directory` - 扫描和分析项目目录
- `/files` - 文件选择和分析
- `/exclude` - 设置项目排除规则

### 会话管理
- `/clear` - 清除当前会话历史
- `/compress` - 压缩当前会话
- `/stats` - 当前会话统计
- `/memory` - 当前会话记忆管理
- `/context` - 会话上下文管理

### 分析命令
- `/analyze` - 分析当前项目内容
- `/export` - 导出当前会话分析结果
- `/report` - 生成项目分析报告

### 会话专家
- `/use-agent` - 为当前会话指派专家智能体
- `/agent-mode` - 切换会话智能体模式

## 命令优先级实现计划

### 极高优先级
1. **MCP扩展能力** (`/mcp`, `/tools`) - 全局
2. **工具箱面板** - 显示MCP服务器状态

### 高优先级  
3. **多智能体管理** (`/agents`) - 全局
4. **专家库界面** - 智能体选择和管理
5. **项目初始化** (`/init`) - 项目级别

### 中优先级
6. **会话压缩** (`/compress`) - 会话级别
7. **交互式文件树** (`/directory`) - 项目级别
8. **Token优化监控** - 会话级别

## 技术架构设计

### 全局配置存储
```
localStorage.globalConfig = {
  mcp: { servers: [], tools: [] },
  agents: { library: [], default: null },
  auth: { defaultProvider: 'qwen' },
  ui: { theme: 'light', layout: 'default' }
}
```

### 项目配置存储
```
sessionStorage.projectConfig = {
  id: 'project_123',
  init: { directory: '/path', excludes: [] },
  agent: { current: 'coder-expert' },
  context: { files: [], memory: [] },
  analysis: { results: [], reports: [] }
}
```

### 会话状态存储
```
sessionStorage.sessionState = {
  id: 'session_456', 
  messages: [],
  tokens: { used: 1200, limit: 4000 },
  compressed: false,
  agent: 'current-expert'
}
```
