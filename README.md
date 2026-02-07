# Web Analyzer V2 - 网络流量分析平台

现代化的网络流量分析平台，支持HTTP/HTTPS代理抓包、Native Hook、实时数据推送和AI智能分析。

## 🎉 项目概述

Web Analyzer V2 是一个功能强大的网络流量分析平台，基于 React 19 + FastAPI + mitmproxy 技术栈构建。提供完整的代理抓包、数据分析、Native Hook和实时监控功能。

### ✨ 核心特性

- 🔍 **HTTP/HTTPS代理抓包** - 支持Web、移动端、桌面应用
- 🔐 **自动证书管理** - CA证书自动生成、安装、过期检查
- 🎯 **Native Hook** - 基于Frida的Windows应用Hook（绕过SSL固定）
- 📊 **实时数据推送** - WebSocket实时推送请求/响应/状态
- 💾 **数据导出** - 支持HAR和CSV格式导出
- 🔧 **过滤规则** - 灵活的请求过滤系统（支持持久化）
- 🛡️ **防火墙检查** - 自动检查Windows防火墙状态
- 📱 **移动端支持** - iOS/Android证书安装向导
- 🤖 **AI智能分析** - 集成AI终端服务（CLI桥接）

## 🚀 快速开始

### 环境要求

- Python 3.9+
- Node.js 18+
- Windows 10/11（部分功能）

### 一键启动

```bash
# 克隆项目
git clone <repository-url>
cd web_analyzer_v2

# 启动所有服务（后端 + 前端 + AI）
start_all.bat
```

服务地址：
- 前端: http://localhost:5173
- 后端API: http://localhost:8000
- API文档: http://localhost:8000/docs

## 📋 功能清单

### ✅ 已完成功能（v2.0.0）

#### 代理服务
- ✅ HTTP/HTTPS代理服务器
- ✅ 自动证书生成和管理
- ✅ 系统代理自动配置（Windows）
- ✅ 多设备连接支持
- ✅ 实时流量捕获

#### 实时推送
- ✅ WebSocket实时连接 (`/ws/proxy-events`)
- ✅ 请求/响应实时推送
- ✅ 代理状态变化推送
- ✅ 心跳检测和自动重连

#### 数据管理
- ✅ 请求列表展示和搜索
- ✅ 请求详情查看
- ✅ HAR格式导出（HTTP Archive 1.2）
- ✅ CSV格式导出
- ✅ 按来源/平台过滤

#### 过滤规则
- ✅ 包含/排除规则（白名单/黑名单）
- ✅ 通配符和正则表达式支持
- ✅ 规则启用/禁用
- ✅ SQLite数据库持久化

#### 证书管理
- ✅ CA证书自动生成
- ✅ Windows系统安装/卸载
- ✅ 移动端证书下载
- ✅ 证书过期检查和提醒
- ✅ 证书重新生成
- ✅ 二维码生成

#### Native Hook（Windows）
- ✅ Frida进程附加/分离
- ✅ 脚本注入和模板管理
- ✅ WinHTTP API Hook
- ✅ SSL证书验证绕过
- ✅ Hook记录展示
- ✅ 脚本开发指南

#### 系统监控
- ✅ 防火墙状态检查（Windows）
- ✅ 端口规则检查
- ✅ 配置建议生成
- ✅ 设备识别和统计

#### AI智能分析
- ✅ AI终端服务集成
- ✅ 代码生成和分析
- ✅ 智能问答

## 🔧 重构完成状态

**项目重构已全面完成！** 所有核心功能已实现并可投入生产使用。

### 完成清单

#### 高优先级任务 (已完成)
- [x] 创建项目目录结构 (backend, frontend, scripts)
- [x] 复制现有业务逻辑模块到后端 (零修改复用)
- [x] 创建环境配置文件 (.env.example, .gitignore)
- [x] 创建Windows批处理脚本 (一键启动/停止)
- [x] 设置FastAPI后端架构 (main.py, config.py, database.py)
- [x] 创建后端API路由 (crawler, analysis, qwen, embedding, proxy, filters, native_hook)
- [x] 包装现有服务为FastAPI兼容服务层
- [x] 创建依赖管理文件 (requirements.txt, package.json)
- [x] 设置AI终端HTTP包装器 (Express服务器 端口3001)

#### 中等优先级任务 (已完成)
- [x] 初始化React 19 + TypeScript项目 (Vite + Ant Design 6.1.1)
- [x] 创建React布局组件和路由结构
- [x] 实现核心前端组件 (爬虫管理、数据分析、代理抓包、Native Hook)
- [x] 集成AI终端服务
- [x] 设置SQLite数据库 (混合存储策略)
- [x] 创建智能模型路由服务
- [x] 创建API服务和Hooks (前端数据获取)
- [x] 创建完整的React页面组件 (Home, Crawler, Analysis, AI, Settings, ProxyCapture, NativeHook)
- [x] WebSocket实时推送集成
- [x] 数据导出功能（HAR/CSV）
- [x] 过滤规则持久化
- [x] 证书管理增强
- [x] 防火墙状态检查

#### 低优先级任务 (已完成)
- [x] 创建综合项目文档和部署指南
- [x] 更新README (最终架构和功能清单)
- [x] Native Hook脚本开发指南
- [x] API测试套件
- [x] 集成测试套件

## 技术栈

### 前端
- **React 19.2.3** - 现代化UI框架 
- **TypeScript** - 类型安全 
- **Ant Design 6.1.1** - UI组件库 
- **Vite** - 构建工具 
- **Axios** - HTTP客户端
- **WebSocket** - 实时通信

### 后端  
- **FastAPI 0.104+** - 现代Python web框架 
- **SQLAlchemy 2.0+** - ORM 
- **SQLite** - 数据库 (混合存储) 
- **WebSocket** - 实时通信 
- **Alembic** - 数据库迁移 

### AI集成
- **AI终端服务** - 本地CLI桥接和交互终端
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
├── backend/terminal_service/ # Node.js 终端服务
└── scripts/           # Windows启动脚本
```

## Development

- Python 3.11+
- Node.js 18+
- 环境变量配置: `.env`
