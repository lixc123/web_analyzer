# 环境配置说明

## 前端环境变量配置

前端项目现在支持通过环境变量配置 API 和 WebSocket 的连接地址，方便在不同环境下部署。

### 配置文件

- `.env.development` - 开发环境配置
- `.env.production` - 生产环境配置
- `.env.example` - 配置示例文件

### 环境变量说明

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `VITE_API_BASE_URL` | API 基础 URL（不包含 /api/v1） | `http://localhost:8000` |
| `VITE_WS_BASE_URL` | WebSocket 基础 URL | `ws://localhost:8000` |

### 使用方法

#### 1. 开发环境

创建 `.env.development` 文件：

```bash
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_BASE_URL=ws://localhost:8000
```

#### 2. 生产环境

创建 `.env.production` 文件：

**方式一：使用完整 URL**
```bash
VITE_API_BASE_URL=https://your-domain.com
VITE_WS_BASE_URL=wss://your-domain.com
```

**方式二：使用相对路径（推荐）**
```bash
# 留空表示使用相对路径，自动适配当前域名
VITE_API_BASE_URL=
VITE_WS_BASE_URL=
```

#### 3. 局域网部署

如果需要在局域网内访问：

```bash
VITE_API_BASE_URL=http://192.168.1.100:8000
VITE_WS_BASE_URL=ws://192.168.1.100:8000
```

### 自动检测逻辑

如果没有配置环境变量，系统会自动检测：

1. **localhost/127.0.0.1**: 使用 `http://localhost:8000`
2. **HTTPS 协议**: 使用 `https://当前域名` 和 `wss://当前域名`
3. **局域网 IP**: 使用 `http://IP:8000` 和 `ws://IP:8000`

### 验证配置

启动开发服务器后，打开浏览器控制台，检查网络请求的目标地址是否正确。

```bash
# 开发环境
npm run dev

# 生产构建
npm run build
```

### 注意事项

1. 修改环境变量后需要重启开发服务器
2. 生产环境构建时会读取 `.env.production` 文件
3. 环境变量文件不应提交到版本控制系统（已在 .gitignore 中配置）
4. 如果使用 HTTPS，WebSocket 也必须使用 WSS 协议

## 后端配置

后端默认监听 `0.0.0.0:8000`，可以通过以下方式修改：

### 方式一：修改配置文件

编辑 `backend/app/config.py`：

```python
backend_port = 8000  # 修改为其他端口
```

### 方式二：环境变量

```bash
export BACKEND_PORT=8080
python -m app.main
```

### 方式三：命令行参数

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 常见部署场景

### 场景1：前后端同服务器，不同端口

```bash
# 后端
backend_port = 8000

# 前端 .env.production
VITE_API_BASE_URL=http://your-domain.com:8000
VITE_WS_BASE_URL=ws://your-domain.com:8000
```

### 场景2：前后端同域名，通过 Nginx 反向代理

```bash
# Nginx 配置
location /api/ {
    proxy_pass http://localhost:8000;
}

location /ws/ {
    proxy_pass http://localhost:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}

# 前端 .env.production（使用相对路径）
VITE_API_BASE_URL=
VITE_WS_BASE_URL=
```

### 场景3：前后端不同域名（需要配置 CORS）

```bash
# 后端 config.py
cors_origins = ["https://frontend-domain.com"]

# 前端 .env.production
VITE_API_BASE_URL=https://api-domain.com
VITE_WS_BASE_URL=wss://api-domain.com
```

## 故障排查

### 问题1：API 请求 404

检查：
1. 环境变量配置是否正确
2. 后端服务是否启动
3. 浏览器控制台查看实际请求的 URL

### 问题2：WebSocket 连接失败

检查：
1. WebSocket URL 协议是否正确（ws/wss）
2. 防火墙是否允许 WebSocket 连接
3. 如果使用 HTTPS，必须使用 WSS

### 问题3：跨域错误

检查：
1. 后端 CORS 配置是否包含前端域名
2. 是否使用了正确的协议（http/https）
