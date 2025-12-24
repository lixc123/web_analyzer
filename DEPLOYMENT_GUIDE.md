# Web Analyzer V2 部署指南

## 系统要求

### 软件依赖
- **Python 3.9+** - 后端FastAPI服务
- **Node.js 18.0+** - 前端React和Qwen-Code包装器
- **npm 8.0+** - 包管理器
- **Git** - 版本控制

### 硬件推荐
- **内存**: 最少 4GB，推荐 8GB+
- **存储**: 最少 2GB 可用空间
- **CPU**: 2核心以上
- **网络**: 需要访问硅基流动API

## 快速开始

### 1. 环境配置

复制环境变量配置文件：
```bash
cd web_analyzer_v2
cp .env.example .env
```

编辑 `.env` 文件，配置必需的API密钥：
```env
# API配置 - 本地Qwen-Code模型无需配置
# OPENAI_API_KEY=sk-your-api-key-here (本地模型不需要)
# OPENAI_BASE_URL=http://localhost:3001 (本地Qwen服务)
# OPENAI_MODEL=qwen-code (本地模型)

# 服务端口配置
BACKEND_PORT=8000
FRONTEND_PORT=3000
QWEN_CODE_PORT=3001

# 数据库配置
DATABASE_URL=sqlite:///./data/web_analyzer.db
DATA_DIR=./data
LOG_DIR=./logs

# 调试和安全
DEBUG=False
SECRET_KEY=your-secret-key-here
CORS_ORIGINS=http://localhost:3000

# 缓存配置
CACHE_TTL=3600
MAX_CACHE_SIZE=1000
```

### 2. 一键启动 (推荐)

运行自动化脚本：
```bash
cd scripts
./setup_and_start.bat
```

这个脚本将会：
- ✅ 检查Python和Node.js环境
- ✅ 安装所有依赖包
- ✅ 设置环境变量
- ✅ 启动所有服务 (后端、前端、Qwen-Code)

### 3. 手动部署

如果需要手动控制每个步骤：

#### 3.1 后端部署
```bash
cd backend

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 启动服务
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 3.2 前端部署
```bash
cd frontend

# 安装依赖
npm install

# 开发模式启动
npm run dev

# 或生产构建
npm run build
npm run preview
```

#### 3.3 Qwen-Code包装器
```bash
cd qwen-code

# 安装依赖
npm install

# 启动服务
npm start
```

## 服务验证

### 健康检查端点
- **后端**: http://localhost:8000/health
- **Qwen-Code**: http://localhost:3001/health
- **前端**: http://localhost:3000

### 系统访问
- **主界面**: http://localhost:3000
- **API文档**: http://localhost:8000/docs
- **API Redoc**: http://localhost:8000/redoc

## 生产环境部署

### 1. 使用Docker (推荐)

创建 `docker-compose.yml`:
```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///./data/web_analyzer.db
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    depends_on:
      - backend

  qwen-code:
    build: ./qwen-code
    ports:
      - "3001:3001"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./Roo-Code:/app/Roo-Code
```

启动生产环境：
```bash
docker-compose up -d
```

### 2. 使用PM2 (Node.js进程管理)

安装PM2：
```bash
npm install -g pm2
```

创建 `ecosystem.config.js`:
```javascript
module.exports = {
  apps: [
    {
      name: 'web-analyzer-backend',
      cwd: './backend',
      script: 'uvicorn',
      args: 'app.main:app --host 0.0.0.0 --port 8000',
      interpreter: 'python',
      env: {
        NODE_ENV: 'production'
      }
    },
    {
      name: 'web-analyzer-frontend',
      cwd: './frontend',
      script: 'npm',
      args: 'run preview',
      env: {
        NODE_ENV: 'production'
      }
    },
    {
      name: 'qwen-code-wrapper',
      cwd: './qwen-code',
      script: 'server-wrapper.js',
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
};
```

启动服务：
```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### 3. 使用Nginx反向代理

Nginx配置示例 (`/etc/nginx/sites-available/web-analyzer`):
```nginx
server {
    listen 80;
    server_name your-domain.com;

    # 前端静态文件
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # 后端API
    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }

    # Qwen-Code API
    location /qwen/ {
        proxy_pass http://localhost:3001/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 故障排除

### 常见问题

#### 1. Qwen-Code服务无法访问
**症状**: Qwen-Code模型调用失败
**解决**: 检查Qwen-Code服务是否在端口3001正常运行

#### 2. 端口被占用
**症状**: 服务启动失败，提示端口被占用
**解决**: 
```bash
# 查找占用端口的进程
netstat -ano | findstr :8000
# 终止进程
taskkill /PID <进程ID> /F
```

#### 3. Qwen-Code CLI未找到
**症状**: Qwen-Code包装器健康检查失败
**解决**: 确保 `Roo-Code` 目录存在且包含CLI文件

#### 4. 前端构建失败
**症状**: React应用编译错误
**解决**: 
```bash
# 清除缓存
npm cache clean --force
# 删除node_modules重新安装
rm -rf node_modules
npm install
```

#### 5. 数据库连接失败
**症状**: 后端启动时数据库错误
**解决**: 
```bash
# 确保数据目录存在
mkdir -p data logs
# 检查数据库文件权限
chmod 755 data/
```

### 日志分析

#### 后端日志
```bash
# 查看实时日志
tail -f logs/backend.log

# 搜索错误
grep "ERROR" logs/backend.log
```

#### 前端日志
```bash
# 开发模式查看控制台
# 生产模式查看Nginx日志
tail -f /var/log/nginx/access.log
```

#### Qwen-Code包装器日志
```bash
# 查看包装器日志
tail -f logs/qwen-code.log
```

## 性能优化

### 1. 缓存配置
- 调整 `CACHE_TTL` 和 `MAX_CACHE_SIZE`
- 使用Redis替代内存缓存 (生产环境)

### 2. 数据库优化
- 定期清理过期数据
- 为频繁查询的字段添加索引

### 3. 前端优化
- 启用Gzip压缩
- 配置CDN加速静态资源
- 实施懒加载

### 4. 系统监控
- 使用PM2监控进程状态
- 配置日志轮转
- 设置资源使用警报

## 安全考虑

### 1. API密钥安全
- 不要在代码中硬编码密钥
- 使用环境变量或密钥管理服务
- 定期轮换API密钥

### 2. 网络安全
- 配置防火墙规则
- 使用HTTPS (生产环境)
- 限制CORS来源

### 3. 数据安全
- 定期备份数据库
- 加密敏感数据
- 实施访问控制

## 维护指南

### 1. 定期维护任务
- 清理临时文件: `rm -rf qwen-code/temp/*`
- 清理日志文件: `find logs/ -name "*.log" -mtime +30 -delete`
- 更新依赖包: `pip install --upgrade -r requirements.txt`

### 2. 数据备份
```bash
# 备份数据库
cp data/web_analyzer.db backups/web_analyzer_$(date +%Y%m%d).db

# 备份配置
tar -czf backups/config_$(date +%Y%m%d).tar.gz .env scripts/
```

### 3. 系统更新
```bash
# 停止服务
./scripts/stop_services.bat

# 拉取最新代码
git pull origin main

# 更新依赖
pip install -r backend/requirements.txt
npm install --prefix frontend
npm install --prefix qwen-code

# 重启服务
./scripts/setup_and_start.bat
```

## 技术支持

如需技术支持，请提供以下信息：
- 操作系统版本
- Python和Node.js版本
- 错误日志片段
- 详细的问题描述和重现步骤

---

**注意**: 这是生产就绪的Web Analyzer V2系统。在部署到生产环境之前，请确保所有安全配置都已正确设置。
