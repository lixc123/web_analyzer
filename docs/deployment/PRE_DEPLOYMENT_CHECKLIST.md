# ✅ Web Analyzer V2 - 生产部署检查清单

> **使用说明**: 在部署到生产环境前，请逐项检查并勾选。所有 🔴 标记的项目必须完成。

---

## 📋 部署前检查清单

### 🔴 P0 - 必须完成（安全关键）

#### 1. 环境变量配置
- [ ] `.env` 文件中 `DEBUG=false`
- [ ] `.env` 文件中 `LOG_LEVEL=WARNING` 或 `ERROR`
- [ ] `.env` 文件中 `SECRET_KEY` 已更换为64位随机十六进制字符串
- [ ] `.env` 文件未提交到Git仓库（检查 `.gitignore`）

**验证命令**:
```bash
# 检查 DEBUG 配置
grep "DEBUG=" .env

# 检查 SECRET_KEY 长度（应为64个字符）
grep "SECRET_KEY=" .env | wc -c

# 检查 .env 是否在 .gitignore 中
grep ".env" .gitignore
```

---

#### 2. CORS配置
- [ ] `backend/app/config.py` 第53行的 `"*"` 已删除
- [ ] `cors_origins` 中所有 `localhost` 地址已删除
- [ ] `cors_origins` 只包含实际生产域名
- [ ] 所有域名使用 `https://`（不是 `http://`）

**验证命令**:
```bash
# 检查是否还有 "*"
grep -n '"*"' backend/app/config.py

# 检查是否还有 localhost
grep -n 'localhost' backend/app/config.py
```

**正确示例**:
```python
cors_origins: list = [
    "https://yourdomain.com",
    "https://www.yourdomain.com",
]
```

---

#### 3. 前端构建配置
- [ ] `frontend/vite.config.ts` 第41行 `sourcemap: false`
- [ ] 已执行 `npm run build` 重新构建
- [ ] `frontend/dist/` 目录已生成
- [ ] `dist/` 目录中无 `.map` 文件

**验证命令**:
```bash
# 检查 sourcemap 配置
grep -n "sourcemap:" frontend/vite.config.ts

# 检查是否有 .map 文件
find frontend/dist -name "*.map"
```

---

#### 4. 数据清理
- [ ] `data/sessions/` 目录为空或已删除
- [ ] `data/requests.json` 已删除
- [ ] `data/sessions.json` 已删除
- [ ] `logs/` 目录为空
- [ ] `backend/logs/` 目录为空

**验证命令**:
```bash
# 检查 sessions 目录
ls -la data/sessions/ | wc -l

# 检查历史数据文件
ls -la data/*.json 2>/dev/null
```

---

#### 5. 测试和缓存清理
- [ ] `backend/tests/` 目录已删除
- [ ] 所有 `__pycache__/` 目录已删除
- [ ] 所有 `.pyc` 文件已删除
- [ ] `.vscode/` 目录已删除
- [ ] `.claude/` 目录已删除

**验证命令**:
```bash
# 检查测试目录
ls backend/tests 2>/dev/null

# 检查 __pycache__
find . -type d -name "__pycache__"

# 检查 .pyc 文件
find . -name "*.pyc"
```

---

### 🟡 P1 - 强烈建议（性能优化）

#### 6. 日志配置
- [ ] `backend/app/main.py` 日志级别为 `WARNING`
- [ ] 前端代码中的 `console.log` 已移除或条件化
- [ ] 后端代码中的 `print()` 已替换为 `logger`

**验证命令**:
```bash
# 检查前端 console.log（应该很少或没有）
grep -r "console.log" frontend/src/ | wc -l

# 检查后端 print（应该没有）
grep -r "print(" backend/ --include="*.py" | grep -v "# print" | wc -l
```

---

#### 7. 依赖包管理
- [ ] `requirements.txt` 已更新到最新版本
- [ ] `package.json` 依赖版本已锁定
- [ ] 无已知的安全漏洞（运行安全扫描）

**验证命令**:
```bash
# Python依赖安全检查
pip install safety
safety check -r backend/requirements.txt

# Node.js依赖安全检查
cd frontend && npm audit
```

---

#### 8. 性能配置
- [ ] 缓存配置已优化（`CACHE_TTL`, `CACHE_MAX_SIZE`）
- [ ] WebSocket超时已设置（`WEBSOCKET_TIMEOUT`）
- [ ] 数据库连接池已配置（如适用）

---

### 🟢 P2 - 可选优化（建议完成）

#### 9. 文档清理
- [ ] 开发文档已删除或移至单独仓库
- [ ] `README.md` 已更新为生产版本
- [ ] 保留 `DEPLOYMENT_GUIDE.md` 和 `PRODUCTION_CONFIG_GUIDE.md`

---

#### 10. Git仓库
- [ ] 已决定是否保留 `.git/` 目录
- [ ] 如保留，确保 `.gitignore` 正确配置
- [ ] 敏感文件未提交到Git

**验证命令**:
```bash
# 检查 Git 历史中是否有敏感文件
git log --all --full-history -- .env
git log --all --full-history -- "*.key"
```

---

## 🚀 部署步骤检查

### 步骤1: 环境准备
- [ ] 生产服务器已准备就绪
- [ ] 必要的端口已开放（8000, 3000, 8888）
- [ ] 防火墙规则已配置
- [ ] SSL证书已安装（如使用HTTPS）

---

### 步骤2: 代码部署
- [ ] 代码已上传到生产服务器
- [ ] `.env` 文件已单独配置（不从Git拉取）
- [ ] 文件权限已正确设置

---

### 步骤3: 依赖安装
- [ ] Python虚拟环境已创建
- [ ] Python依赖已安装: `pip install -r requirements.txt`
- [ ] Node.js依赖已安装: `npm ci --production`
- [ ] 前端已构建: `npm run build`

**验证命令**:
```bash
# 检查Python依赖
pip list

# 检查Node.js依赖
npm list --depth=0
```

---

### 步骤4: 服务启动
- [ ] 后端服务已启动
- [ ] 前端服务已启动（或使用Nginx托管）
- [ ] 代理服务已启动
- [ ] 所有服务健康检查通过

**验证命令**:
```bash
# 检查后端服务
curl http://localhost:8000/api/health

# 检查前端服务
curl http://localhost:3000

# 检查进程
ps aux | grep python
ps aux | grep node
```

---

### 步骤5: 功能验证
- [ ] 前端页面可正常访问
- [ ] API接口响应正常
- [ ] WebSocket连接正常
- [ ] 代理功能正常
- [ ] 数据库读写正常
- [ ] 日志正常输出

---

## 🔐 安全检查

### 代码安全
- [ ] 无硬编码的密码或密钥
- [ ] 无SQL注入风险
- [ ] 无XSS攻击风险
- [ ] 无CSRF攻击风险
- [ ] 输入验证已实施

---

### 网络安全
- [ ] HTTPS已启用（生产环境）
- [ ] CORS已正确配置
- [ ] 敏感端口未对外暴露
- [ ] 防火墙规则已配置
- [ ] DDoS防护已启用（如适用）

---

### 数据安全
- [ ] 数据库已备份
- [ ] 敏感数据已加密
- [ ] 日志不包含敏感信息
- [ ] 文件上传已限制（如适用）
- [ ] 会话管理已配置

---

## 📊 性能检查

### 响应时间
- [ ] API响应时间 < 200ms（平均）
- [ ] 页面加载时间 < 3s
- [ ] WebSocket连接时间 < 1s

**测试命令**:
```bash
# API响应时间测试
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/api/health

# 创建 curl-format.txt
echo "time_total: %{time_total}s\n" > curl-format.txt
```

---

### 资源使用
- [ ] CPU使用率 < 70%（空闲时）
- [ ] 内存使用率 < 80%
- [ ] 磁盘空间充足（> 20% 可用）
- [ ] 网络带宽充足

**监控命令**:
```bash
# CPU和内存
top -b -n 1 | head -20

# 磁盘空间
df -h

# 网络连接
netstat -an | grep ESTABLISHED | wc -l
```

---

## 🔍 监控和日志

### 日志配置
- [ ] 日志级别已设置为 WARNING 或 ERROR
- [ ] 日志轮转已配置
- [ ] 日志存储路径已设置
- [ ] 日志不包含敏感信息

---

### 监控配置
- [ ] 服务健康检查已配置
- [ ] 错误告警已配置
- [ ] 性能监控已配置
- [ ] 磁盘空间监控已配置

---

## 📝 文档检查

### 必备文档
- [ ] `README.md` - 项目说明
- [ ] `DEPLOYMENT_GUIDE.md` - 部署指南
- [ ] `PRODUCTION_CONFIG_GUIDE.md` - 配置指南
- [ ] API文档（如适用）

---

### 运维文档
- [ ] 启动/停止脚本
- [ ] 备份/恢复流程
- [ ] 故障排查指南
- [ ] 联系人信息

---

## 🆘 回滚计划

### 回滚准备
- [ ] 已备份当前生产版本
- [ ] 已准备回滚脚本
- [ ] 已测试回滚流程
- [ ] 已记录回滚步骤

---

### 回滚触发条件
- [ ] 服务无法启动
- [ ] 关键功能失效
- [ ] 性能严重下降
- [ ] 安全漏洞发现

---

## ✅ 最终确认

### 部署前最后检查
- [ ] 所有 🔴 P0 项目已完成
- [ ] 所有 🟡 P1 项目已完成（强烈建议）
- [ ] 已在测试环境验证
- [ ] 已通知相关人员
- [ ] 已准备回滚方案
- [ ] 已安排值班人员

---

### 部署时间选择
- [ ] 选择低峰时段部署
- [ ] 已预留足够的验证时间
- [ ] 已通知用户（如需要）

---

### 部署后验证
- [ ] 所有服务正常运行
- [ ] 功能验证通过
- [ ] 性能指标正常
- [ ] 无错误日志
- [ ] 用户反馈正常

---

## 📞 紧急联系

### 技术支持
- **开发负责人**: _______________
- **运维负责人**: _______________
- **紧急联系电话**: _______________

### 外部服务
- **云服务商支持**: _______________
- **CDN服务商支持**: _______________
- **数据库服务商支持**: _______________

---

## 📊 检查进度

### 完成度统计
- 🔴 P0 必须项: _____ / 5 (100%)
- 🟡 P1 建议项: _____ / 3 (___%)
- 🟢 P2 可选项: _____ / 2 (___%)

### 总体评估
- [ ] **可以部署** - 所有P0项目已完成，P1项目完成80%以上
- [ ] **需要改进** - 部分P0项目未完成，需要先完成
- [ ] **不建议部署** - 多个关键项目未完成，存在重大风险

---

## 🎯 快速检查命令

将以下命令保存为 `pre_deployment_check.sh`，一键执行所有检查：

```bash
#!/bin/bash
echo "=========================================="
echo "  Web Analyzer V2 - 部署前检查"
echo "=========================================="
echo ""

# 1. 检查环境变量
echo "[1/10] 检查环境变量..."
if grep -q "DEBUG=false" .env; then
    echo "  ✓ DEBUG=false"
else
    echo "  ✗ DEBUG 未设置为 false"
fi

if grep -q "SECRET_KEY=" .env && [ $(grep "SECRET_KEY=" .env | wc -c) -gt 50 ]; then
    echo "  ✓ SECRET_KEY 已设置"
else
    echo "  ✗ SECRET_KEY 未设置或过短"
fi

# 2. 检查CORS配置
echo ""
echo "[2/10] 检查CORS配置..."
if grep -q '"*"' backend/app/config.py; then
    echo "  ✗ CORS 仍包含 '*'"
else
    echo "  ✓ CORS 已限制"
fi

# 3. 检查sourcemap
echo ""
echo "[3/10] 检查sourcemap配置..."
if grep -q "sourcemap: false" frontend/vite.config.ts; then
    echo "  ✓ sourcemap 已关闭"
else
    echo "  ✗ sourcemap 仍然开启"
fi

# 4. 检查历史数据
echo ""
echo "[4/10] 检查历史数据..."
session_count=$(ls -1 data/sessions/ 2>/dev/null | wc -l)
if [ $session_count -eq 0 ]; then
    echo "  ✓ 历史数据已清空"
else
    echo "  ✗ 仍有 $session_count 个历史会话"
fi

# 5. 检查测试文件
echo ""
echo "[5/10] 检查测试文件..."
if [ ! -d "backend/tests" ]; then
    echo "  ✓ 测试文件已删除"
else
    echo "  ✗ 测试文件仍存在"
fi

# 6. 检查缓存文件
echo ""
echo "[6/10] 检查Python缓存..."
pycache_count=$(find . -type d -name "__pycache__" 2>/dev/null | wc -l)
if [ $pycache_count -eq 0 ]; then
    echo "  ✓ Python缓存已清理"
else
    echo "  ✗ 仍有 $pycache_count 个 __pycache__ 目录"
fi

# 7. 检查前端构建
echo ""
echo "[7/10] 检查前端构建..."
if [ -d "frontend/dist" ]; then
    echo "  ✓ 前端已构建"
    map_count=$(find frontend/dist -name "*.map" 2>/dev/null | wc -l)
    if [ $map_count -eq 0 ]; then
        echo "  ✓ 无 sourcemap 文件"
    else
        echo "  ✗ 仍有 $map_count 个 .map 文件"
    fi
else
    echo "  ✗ 前端未构建"
fi

# 8. 检查日志目录
echo ""
echo "[8/10] 检查日志目录..."
log_count=$(ls -1 logs/ 2>/dev/null | wc -l)
if [ $log_count -eq 0 ]; then
    echo "  ✓ 日志已清空"
else
    echo "  ⚠ 有 $log_count 个日志文件"
fi

# 9. 检查IDE配置
echo ""
echo "[9/10] 检查IDE配置..."
if [ ! -d ".vscode" ] && [ ! -d ".claude" ]; then
    echo "  ✓ IDE配置已删除"
else
    echo "  ⚠ IDE配置仍存在"
fi

# 10. 检查依赖
echo ""
echo "[10/10] 检查依赖..."
if [ -f "backend/requirements.txt" ]; then
    echo "  ✓ requirements.txt 存在"
else
    echo "  ✗ requirements.txt 不存在"
fi

if [ -f "frontend/package.json" ]; then
    echo "  ✓ package.json 存在"
else
    echo "  ✗ package.json 不存在"
fi

echo ""
echo "=========================================="
echo "  检查完成！"
echo "=========================================="
```

**使用方法**:
```bash
chmod +x pre_deployment_check.sh
./pre_deployment_check.sh
```

---

**检查清单版本**: 1.0
**最后更新**: 2026-01-21
**适用于**: Web Analyzer V2
