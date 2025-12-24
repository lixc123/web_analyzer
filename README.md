# Web Analyzer V2

Modern web application for network traffic analysis and AI-powered insights.

## 项目概述

Web Analyzer V2 是一个现代化的网络流量分析平台，基于 React 19 + FastAPI + AI 智能分析技术栈构建。本项目将原有的 PySide6 桌面应用重构为 Web 应用，提供更好的用户体验和扩展性。

## 重构完成状态

**项目重构已全面完成！** 所有核心功能已实现并可投入生产使用。

### 完成清单

#### 高优先级任务 (已完成)
- [x] 创建项目目录结构 (backend, frontend, qwen-code, scripts)
- [x] 复制现有业务逻辑模块到后端 (零修改复用)
- [x] 创建环境配置文件 (.env.example, .gitignore)
- [x] 创建Windows批处理脚本 (一键启动/停止)
- [x] 设置FastAPI后端架构 (main.py, config.py, database.py)
- [x] 创建后端API路由 (crawler, analysis, qwen, embedding)
- [x] 包装现有服务为FastAPI兼容服务层
- [x] 创建依赖管理文件 (requirements.txt, package.json)
- [x] 设置Qwen-Code HTTP包装器 (Express服务器 端口3001)

#### 中等优先级任务 (已完成)
- [x] 初始化React 19 + TypeScript项目 (Vite + Ant Design 6.1.1)
- [x] 创建React布局组件和路由结构
- [x] 实现核心前端组件 (爬虫管理和数据分析)
- [x] 集成Qwen-Code本地模型服务
- [x] 设置SQLite数据库 (混合存储策略)
- [x] 创建智能模型路由服务
- [x] 创建API服务和Hooks (前端数据获取)
- [x] 创建完整的React页面组件 (Home, Crawler, Analysis, AI, Settings)

#### 低优先级任务 (已完成)
- [x] 创建综合项目文档和部署指南
- [x] 更新README (最终架构和功能清单)

## 技术栈

### 前端
- **React 19.2.3** - 现代化UI框架 
- **TypeScript** - 类型安全 
- **Ant Design 6.1.1** - UI组件库 
- **Vite** - 构建工具 
- **React Query** - 数据获取和缓存 
- **Zustand** - 状态管理 

### 后端  
- **FastAPI 0.104+** - 现代Python web框架 
- **SQLAlchemy 2.0+** - ORM 
- **SQLite** - 数据库 (混合存储) 
- **WebSocket** - 实时通信 
- **Alembic** - 数据库迁移 

### AI集成
- **Qwen-Code** - 本地JavaScript代码分析和对话模型
- **智能模型路由** - 统一模型调用接口 

## Quick Start

```bash
# 一键启动所有服务
./scripts/setup_and_start.bat

# 停止所有服务  
./scripts/stop_services.bat
```

## Project Structure

```
web_analyzer_v2/
├── backend/           # FastAPI后端
│   ├── core/          # 业务逻辑核心模块 (复用)
│   ├── models/        # 数据模型 (复用)
│   ├── utils/         # 工具函数 (复用)
│   └── app/           # FastAPI应用层
├── frontend/          # React前端
├── qwen-code/         # Qwen-Code智能体
└── scripts/           # Windows启动脚本
```

## Development

- Python 3.11+
- Node.js 18+
- 环境变量配置: `.env`
