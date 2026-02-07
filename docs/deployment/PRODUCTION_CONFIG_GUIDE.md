# 🚀 Web Analyzer V2 - 生产环境配置指南

> **清理完成时间**: 2026-01-21
> **清理方案**: 方案A - 保守清理
> **节省空间**: 约 290MB

---

## ✅ 已完成的清理项

- ✅ **历史数据已清空** (290MB)
  - `data/sessions/` - 14,357个历史会话文件
  - `data/requests.json` - 556KB历史请求
  - `data/sessions.json` - 15KB会话索引

- ✅ **Python缓存已删除** (2288个文件)
  - 283个 `__pycache__` 目录
  - 所有 `.pyc` 编译文件

- ✅ **测试文件已删除**
  - `backend/tests/` - 8个测试文件

- ✅ **IDE配置已删除**
  - `.vscode/` - VSCode配置
  - `.claude/` - Claude Code配置

- ✅ **日志文件已清空**
  - `logs/` 目录
  - `backend/logs/` 目录

---

## ⚠️ 必须手动完成的配置修改

### 1️⃣ 修改 `.env` 文件（最高优先级）

**当前配置** (`.env.example`):
```env
DEBUG=true              # ❌ 必须改为 false
LOG_LEVEL=INFO          # ⚠️ 建议改为 WARNING
```

**生产环境配置**:
```env
# 开发模式配置
DEBUG=false                    # ✅ 关闭调试模式
LOG_LEVEL=WARNING              # ✅ 减少日志输出

# 安全配置
SECRET_KEY=<生成的随机密钥>    # ✅ 必须更换（见下方生成方法）

# 数据库配置
DATABASE_URL=sqlite:///./data/app.db

# 服务端口配置
BACKEND_PORT=8000
FRONTEND_PORT=3000

# 缓存配置
CACHE_TTL=3600
CACHE_MAX_SIZE=1000

# WebSocket配置
WEBSOCKET_TIMEOUT=300
```

#### 🔑 生成安全的 SECRET_KEY

**方法1: 使用 Python**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**方法2: 使用 OpenSSL**
```bash
openssl rand -hex 32
```

**方法3: 在线生成**
访问: https://randomkeygen.com/ (选择 "CodeIgniter Encryption Keys")

**示例输出**:
```
a7f3c9e2b8d4f1a6c5e9b2d8f4a1c7e3b9d5f2a8c6e1b4d7f3a9c2e8b5d1f6a4
```

将生成的密钥复制到 `.env` 文件中：
```env
SECRET_KEY=a7f3c9e2b8d4f1a6c5e9b2d8f4a1c7e3b9d5f2a8c6e1b4d7f3a9c2e8b5d1f6a4
```

---

### 2️⃣ 修改 `backend/app/config.py`

#### 问题1: CORS配置过于宽松（第48-54行）

**当前配置**:
```python
cors_origins: list = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "*"  # ❌ 允许所有来源 - 生产环境禁止！
]
```

**生产环境配置**:
```python
cors_origins: list = [
    "https://yourdomain.com",           # ✅ 替换为实际域名
    "https://www.yourdomain.com",       # ✅ 如有www子域名
    "https://api.yourdomain.com",       # ✅ 如有API子域名
    # 删除所有 localhost 和 "*"
]
```

**修改步骤**:
1. 打开 `backend/app/config.py`
2. 找到第48-54行的 `cors_origins` 配置
3. 删除 `"*"` 和所有 `localhost` 地址
4. 添加实际的生产域名（必须使用 HTTPS）

#### 问题2: SECRET_KEY使用默认值（第60行）

**当前配置**:
```python
secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
```

**处理方式**:
- ✅ 已在 `.env` 文件中设置 `SECRET_KEY`
- ✅ 代码会自动读取环境变量
- ⚠️ 确保 `.env` 文件中的 `SECRET_KEY` 已更换

---

### 3️⃣ 修改 `frontend/vite.config.ts`

#### 问题: 开启了 sourcemap（第41行）

**当前配置**:
```typescript
build: {
  outDir: 'dist',
  sourcemap: true,  // ❌ 会暴露源代码
  ...
}
```

**生产环境配置**:
```typescript
build: {
  outDir: 'dist',
  sourcemap: false,  // ✅ 关闭 sourcemap
  ...
}
```

**修改步骤**:
1. 打开 `frontend/vite.config.ts`
2. 找到第41行的 `sourcemap: true`
3. 改为 `sourcemap: false`

**为什么要关闭 sourcemap？**
- 🔒 防止源代码泄露
- 📦 减少构建包大小（约30-50%）
- ⚡ 提升加载速度

---

### 4️⃣ 修改 `backend/app/main.py` (可选优化)

#### 问题: 日志级别为 INFO（第7-10行）

**当前配置**:
```python
logging.basicConfig(
    level=logging.INFO,  # ⚠️ 生产环境建议改为 WARNING
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

**生产环境配置**:
```python
logging.basicConfig(
    level=logging.WARNING,  # ✅ 只记录警告和错误
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

**或者使用环境变量**:
```python
import os
log_level = os.getenv("LOG_LEVEL", "WARNING")
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

---

## 🔍 配置验证清单

完成上述修改后，请逐项检查：

### 安全配置
- [ ] `.env` 中 `DEBUG=false`
- [ ] `.env` 中 `SECRET_KEY` 已更换为随机密钥（64位十六进制）
- [ ] `config.py` 中 `cors_origins` 已删除 `"*"`
- [ ] `config.py` 中 `cors_origins` 已删除所有 `localhost` 地址
- [ ] `config.py` 中 `cors_origins` 只包含实际生产域名
- [ ] 所有域名使用 HTTPS（不是 HTTP）

### 性能配置
- [ ] `.env` 中 `LOG_LEVEL=WARNING`
- [ ] `vite.config.ts` 中 `sourcemap: false`
- [ ] `main.py` 中日志级别为 `WARNING`（可选）

### 数据清理
- [ ] `data/sessions/` 目录为空
- [ ] `data/requests.json` 已删除
- [ ] `data/sessions.json` 已删除
- [ ] `logs/` 目录为空
- [ ] `backend/logs/` 目录为空

### 文件清理
- [ ] `backend/tests/` 已删除
- [ ] `__pycache__/` 目录已全部删除
- [ ] `.pyc` 文件已全部删除
- [ ] `.vscode/` 已删除
- [ ] `.claude/` 已删除

---

## 🚀 重新构建和部署

### 步骤1: 重新构建前端

```bash
cd frontend
npm run build
```

**预期输出**:
```
✓ built in 15s
dist/index.html                   0.45 kB
dist/assets/index-abc123.js       250 kB
dist/assets/index-abc123.css      50 kB
```

**检查点**:
- ✅ 构建成功无错误
- ✅ `dist/` 目录已生成
- ✅ 无 `.map` 文件（sourcemap已关闭）

### 步骤2: 测试启动

```bash
# 返回项目根目录
cd ..

# 启动服务
start_all.bat
```

**检查点**:
- ✅ 后端启动成功（端口8000）
- ✅ 前端启动成功（端口3000）
- ✅ 无错误日志
- ✅ 日志级别为 WARNING

### 步骤3: 功能验证

访问 `http://localhost:3000` 并测试：

- [ ] 页面正常加载
- [ ] API接口可访问
- [ ] WebSocket连接正常
- [ ] 代理功能正常
- [ ] 无控制台错误
- [ ] 无敏感信息泄露

---

## 📊 配置对比表

| 配置项 | 开发环境 | 生产环境 | 影响 |
|--------|----------|----------|------|
| **DEBUG** | `true` | `false` | 关闭调试信息 |
| **LOG_LEVEL** | `INFO` | `WARNING` | 减少日志输出 |
| **SECRET_KEY** | 默认值 | 随机密钥 | 提升安全性 |
| **CORS** | `*` | 指定域名 | 防止跨域攻击 |
| **sourcemap** | `true` | `false` | 隐藏源码 |
| **日志级别** | `INFO` | `WARNING` | 减少I/O |

---

## 🔐 安全检查清单

### 敏感信息检查
- [ ] 无硬编码的密码或密钥
- [ ] 无API密钥泄露
- [ ] 无数据库连接字符串泄露
- [ ] `.env` 文件未提交到Git（已在 `.gitignore` 中）

### 访问控制检查
- [ ] CORS已正确配置
- [ ] 无 `*` 通配符
- [ ] 所有域名使用HTTPS
- [ ] WebSocket连接已限制来源

### 代码安全检查
- [ ] 无 `console.log` 泄露敏感信息
- [ ] 无 `print()` 泄露敏感信息
- [ ] 错误信息不暴露内部细节
- [ ] 调试模式已关闭

---

## 📝 环境变量完整示例

### `.env` (生产环境)

```env
# ========================================
# Web Analyzer V2 - 生产环境配置
# ========================================

# 开发模式配置
DEBUG=false
LOG_LEVEL=WARNING

# 安全配置
SECRET_KEY=a7f3c9e2b8d4f1a6c5e9b2d8f4a1c7e3b9d5f2a8c6e1b4d7f3a9c2e8b5d1f6a4

# 数据库配置
DATABASE_URL=sqlite:///./data/app.db

# 服务端口配置
BACKEND_PORT=8000
FRONTEND_PORT=3000

# 缓存配置
CACHE_TTL=3600
CACHE_MAX_SIZE=1000

# WebSocket配置
WEBSOCKET_TIMEOUT=300

# 代理服务配置
PROXY_PORT=8888
```

---

## 🆘 常见问题

### Q1: 修改配置后服务无法启动？
**A**: 检查以下项：
1. `.env` 文件格式是否正确（无多余空格）
2. `SECRET_KEY` 是否为有效的十六进制字符串
3. 端口是否被占用
4. 日志文件查看详细错误信息

### Q2: CORS错误 "Access-Control-Allow-Origin"？
**A**:
1. 确认 `config.py` 中的 `cors_origins` 包含前端域名
2. 确认域名协议正确（HTTP vs HTTPS）
3. 确认没有多余的斜杠（如 `https://domain.com/`）

### Q3: 前端构建后页面空白？
**A**:
1. 检查浏览器控制台错误
2. 确认 `dist/` 目录已生成
3. 确认后端API可访问
4. 清除浏览器缓存

### Q4: 如何回滚配置？
**A**:
1. 恢复 `.env.example` 的内容到 `.env`
2. 恢复 `config.py` 中的 `cors_origins` 添加 `"*"`
3. 恢复 `vite.config.ts` 中的 `sourcemap: true`

---

## 📞 技术支持

如遇到问题，请检查：
1. 📋 本配置指南
2. 📄 `DEPLOYMENT_GUIDE.md` - 部署指南
3. 📝 `README.md` - 项目说明
4. 🔍 日志文件 `logs/` 和 `backend/logs/`

---

## ✅ 配置完成确认

完成所有配置后，请确认：

- [x] 已清理历史数据和缓存
- [ ] 已修改 `.env` 文件
- [ ] 已修改 `config.py` 文件
- [ ] 已修改 `vite.config.ts` 文件
- [ ] 已重新构建前端
- [ ] 已测试启动服务
- [ ] 已验证所有功能
- [ ] 已检查安全配置

**恭喜！您的项目已准备好部署到生产环境！** 🎉

---

**最后更新**: 2026-01-21
**版本**: 1.0
**适用于**: Web Analyzer V2
