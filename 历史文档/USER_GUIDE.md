# Web Analyzer V2 用户使用指南

## 📖 目录

1. [系统简介](#系统简介)
2. [快速开始](#快速开始)
3. [代理捕获功能](#代理捕获功能)
4. [Native Hook功能](#native-hook功能)
5. [常见问题](#常见问题)
6. [最佳实践](#最佳实践)

---

## 系统简介

Web Analyzer V2 是一个强大的三合一网络分析工具，集成了：

- **🌐 代理捕获**: 捕获HTTP/HTTPS流量（浏览器、桌面应用、移动设备）
- **📱 移动端支持**: 完整的移动设备配置向导和证书管理
- **🔧 Native Hook**: 基于Frida的Windows应用程序动态Hook（可选功能）

### 核心特性

✅ **零配置启动** - 一键启动代理服务
✅ **HTTPS自动解密** - 自动生成和管理CA证书
✅ **实时流量监控** - WebSocket实时推送请求数据
✅ **多设备支持** - 同时捕获多个设备的流量
✅ **智能过滤** - 按域名、方法、状态码过滤请求
✅ **Native Hook** - 可选的Windows应用程序Hook功能

---

## 快速开始

### 1. 启动系统

#### 后端启动
```bash
cd backend
python main.py
```

后端将在 `http://localhost:8000` 启动

#### 前端启动
```bash
cd frontend
npm install
npm run dev
```

前端将在 `http://localhost:5173` 启动

### 2. 访问系统

打开浏览器访问: `http://localhost:5173`

### 3. 启动代理服务

1. 进入 **"代理捕获"** 页面
2. 在 **"代理控制"** 标签页中
3. 配置代理端口（默认8888）
4. 点击 **"启动代理服务"** 按钮

✅ 看到 **"运行中"** 状态表示启动成功

---

## 代理捕获功能

### 📋 代理控制

#### 基本配置

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| 代理端口 | 代理服务监听端口 | 8888 |
| 系统代理 | 自动设置Windows系统代理 | 关闭 |

#### 状态监控

- **代理端口**: 当前监听的端口号
- **连接客户端**: 当前连接的设备数量
- **总请求数**: 累计捕获的请求数量

#### 操作按钮

- **启动代理服务**: 启动mitmproxy代理
- **停止代理服务**: 停止代理并清空连接
- **刷新状态**: 手动刷新代理状态

### 📱 移动端配置

#### 配置步骤

**第一步: 连接到同一网络**
- 确保移动设备和电脑在同一WiFi网络

**第二步: 配置代理**

**iOS设备:**
1. 打开 **设置 > WiFi**
2. 点击已连接WiFi右侧的 **(i)** 图标
3. 滚动到底部，点击 **配置代理**
4. 选择 **手动**
5. 输入:
   - 服务器: `<本机IP>`
   - 端口: `8888`
6. 点击 **存储**

**Android设备:**
1. 打开 **设置 > WiFi**
2. 长按已连接的WiFi
3. 选择 **修改网络**
4. 展开 **高级选项**
5. 代理选择 **手动**
6. 输入:
   - 代理主机名: `<本机IP>`
   - 代理端口: `8888`
7. 点击 **保存**

**第三步: 安装证书**

**方法1: 扫码安装（推荐）**
1. 在 **"移动端配置"** 标签页
2. 使用手机浏览器扫描二维码
3. 下载并安装证书

**方法2: 访问mitm.it**
1. 在移动设备浏览器访问: `http://mitm.it`
2. 点击对应平台的证书下载链接
3. 按照提示安装证书

**iOS证书信任设置:**
1. 安装证书后，打开 **设置 > 通用 > 关于本机**
2. 滚动到底部，点击 **证书信任设置**
3. 找到 **mitmproxy** 证书
4. 开启 **针对根证书启用完全信任**

**Android证书安装:**
1. 下载证书文件
2. 打开 **设置 > 安全 > 加密与凭据**
3. 点击 **从存储设备安装**
4. 选择下载的证书文件
5. 输入锁屏密码确认

### 🔐 证书管理

#### 证书状态

系统会显示证书的当前状态:
- **证书文件**: 是否已生成CA证书
- **Windows系统**: 是否已安装到系统证书存储区

#### Windows证书安装

**自动安装（推荐）:**
1. 在 **"证书管理"** 标签页
2. 点击 **"Windows 安装证书"** 按钮
3. 在弹出的UAC对话框中点击 **"是"**
4. 等待安装完成

**手动安装:**
1. 点击 **"下载 CA 证书"**
2. 双击下载的 `mitmproxy-ca-cert.cer` 文件
3. 点击 **"安装证书"**
4. 选择 **"当前用户"**
5. 选择 **"将所有的证书都放入下列存储"**
6. 点击 **"浏览"**，选择 **"受信任的根证书颁发机构"**
7. 点击 **"确定"** 完成安装

#### 证书卸载

**Windows卸载:**
1. 在 **"证书管理"** 标签页
2. 点击 **"Windows 卸载证书"** 按钮
3. 确认卸载操作

**移动端卸载:**
- **iOS**: 设置 > 通用 > VPN与设备管理 > 配置描述文件 > 删除描述文件
- **Android**: 设置 > 安全 > 加密与凭据 > 用户凭据 > 删除证书

### 📊 请求列表

#### 功能特性

- **实时更新**: WebSocket实时推送新请求
- **智能过滤**: 多维度过滤请求
- **详情查看**: 查看完整的请求/响应数据
- **数据导出**: 导出请求数据为JSON

#### 过滤选项

| 过滤器 | 说明 | 示例 |
|--------|------|------|
| 域名搜索 | 按域名关键词过滤 | `api.example.com` |
| 请求方法 | 按HTTP方法过滤 | GET, POST, PUT |
| 状态码 | 按响应状态码过滤 | 200, 404, 500 |

#### 请求详情

点击任意请求可查看:
- **基本信息**: URL、方法、状态码、时间
- **请求头**: 完整的请求头信息
- **请求体**: POST/PUT请求的Body数据
- **响应头**: 完整的响应头信息
- **响应体**: 响应内容（支持JSON格式化）

### 👥 设备列表

#### 设备信息

系统自动识别连接的设备:
- **设备名称**: 设备的主机名
- **IP地址**: 设备的IP地址
- **平台**: iOS, Android, Windows, macOS, Linux
- **首次连接**: 设备首次连接时间
- **最后活动**: 设备最后一次请求时间
- **请求数**: 该设备的总请求数

#### 设备过滤

**按平台过滤:**
- 全部设备
- 移动设备（iOS + Android）
- 桌面设备（Windows + macOS + Linux）
- iOS
- Android
- Windows

**按连接状态过滤:**
- 全部
- 在线（5分钟内有活动）
- 离线（5分钟以上无活动）

---

## Native Hook功能

> ⚠️ **注意**: Native Hook是可选功能，需要安装Frida框架

### 🔧 环境准备

#### 安装Frida

```bash
pip install frida frida-tools
```

#### 验证安装

```bash
frida --version
```

### 📱 Hook流程

#### 1. 查看进程列表

1. 进入 **"Native Hook"** 页面
2. 在 **"进程管理"** 标签页
3. 点击 **"刷新进程列表"**
4. 查看所有运行中的进程

#### 2. 附加到进程

**方法1: 按进程名附加**
1. 在进程列表中找到目标进程
2. 点击 **"附加"** 按钮

**方法2: 按PID附加**
1. 输入进程PID
2. 点击 **"附加到PID"** 按钮

✅ 附加成功后会创建一个Hook会话

#### 3. 注入Hook脚本

**使用内置模板:**
1. 在 **"脚本模板"** 标签页
2. 选择一个模板（如 "Windows API Hook"）
3. 点击 **"注入脚本"** 按钮

**使用自定义脚本:**
1. 在 **"自定义脚本"** 标签页
2. 编写Frida JavaScript代码
3. 点击 **"注入脚本"** 按钮

#### 4. 查看Hook记录

1. 进入 **"Hook记录"** 标签页
2. 实时查看捕获的API调用
3. 可按会话、Hook类型过滤

#### 5. 分离进程

1. 在 **"会话管理"** 标签页
2. 找到活动会话
3. 点击 **"分离"** 按钮

### 📝 Hook脚本模板

#### 内置模板

| 模板名称 | 说明 | 分类 |
|---------|------|------|
| windows_api_hooks | Windows API Hook（网络+加密） | network |
| network_monitor | 网络请求监控 | network |
| crypto_monitor | 加密操作监控 | crypto |

#### 自定义模板

**创建模板:**
1. 在 **"脚本模板"** 标签页
2. 点击 **"创建模板"** 按钮
3. 填写模板信息:
   - 模板名称
   - 描述
   - 分类
   - 脚本代码
4. 点击 **"保存"**

**模板参数:**

模板支持参数替换，使用 `{{参数名}}` 语法:

```javascript
// 模板代码
Interceptor.attach(Module.findExportByName("{{module}}", "{{function}}"), {
    onEnter: function(args) {
        console.log("Called {{function}}");
    }
});

// 使用时传入参数
// module: "kernel32.dll"
// function: "CreateFileW"
```

### 🎯 Hook示例

#### 示例1: Hook网络API

```javascript
// Hook WinHTTP API
var winhttp = Module.findExportByName("winhttp.dll", "WinHttpSendRequest");

Interceptor.attach(winhttp, {
    onEnter: function(args) {
        console.log("[WinHTTP] Sending request");

        // 发送到后端
        send({
            type: "network",
            api: "WinHttpSendRequest",
            timestamp: Date.now()
        });
    },
    onLeave: function(retval) {
        console.log("[WinHTTP] Request completed");
    }
});
```

#### 示例2: Hook加密API

```javascript
// Hook CryptEncrypt
var crypt = Module.findExportByName("advapi32.dll", "CryptEncrypt");

Interceptor.attach(crypt, {
    onEnter: function(args) {
        var dataLen = args[4].toInt32();

        send({
            type: "crypto",
            api: "CryptEncrypt",
            data_length: dataLen,
            timestamp: Date.now()
        });
    }
});
```

---

## 常见问题

### Q1: 代理启动失败，提示端口被占用

**解决方案:**
1. 更改代理端口（如改为8889）
2. 或关闭占用8888端口的程序:
   ```bash
   # Windows查找占用端口的进程
   netstat -ano | findstr :8888

   # 结束进程
   taskkill /PID <进程ID> /F
   ```

### Q2: 移动设备配置代理后无法上网

**可能原因:**
- 代理服务未启动
- IP地址配置错误
- 防火墙阻止连接

**解决方案:**
1. 确认代理服务状态为 **"运行中"**
2. 检查IP地址是否正确（在"代理控制"页面查看本机IP）
3. 关闭Windows防火墙或添加例外:
   ```
   控制面板 > Windows Defender 防火墙 > 允许应用通过防火墙
   添加端口: 8888 (TCP)
   ```

### Q3: HTTPS网站无法访问或显示证书错误

**原因:** 未安装或未信任CA证书

**解决方案:**
1. 确认证书已安装（在"证书管理"页面查看状态）
2. Windows: 使用"Windows 安装证书"按钮
3. iOS: 确认已在"证书信任设置"中启用完全信任
4. Android: 确认证书已安装到"用户凭据"

### Q4: 看不到任何请求

**检查清单:**
- [ ] 代理服务是否启动
- [ ] 设备代理配置是否正确
- [ ] 证书是否已安装
- [ ] 防火墙是否阻止连接
- [ ] 是否在"设备列表"中看到设备

**调试步骤:**
1. 在移动设备浏览器访问: `http://mitm.it`
2. 如果能访问，说明代理配置正确
3. 如果不能访问，检查IP和端口配置

### Q5: Native Hook附加进程失败

**可能原因:**
- Frida未安装
- 目标进程权限不足
- 进程已退出

**解决方案:**
1. 确认Frida已安装: `frida --version`
2. 以管理员身份运行系统
3. 确认目标进程仍在运行

### Q6: Hook记录为空

**可能原因:**
- 脚本未正确注入
- 目标API未被调用
- 脚本代码有错误

**解决方案:**
1. 检查脚本是否注入成功
2. 在脚本中添加调试日志
3. 确认目标API确实被应用调用

---

## 最佳实践

### 🎯 代理捕获最佳实践

#### 1. 性能优化

**减少不必要的流量:**
- 使用域名过滤，只关注目标域名
- 定期清空请求列表
- 关闭不需要的设备连接

**批量操作:**
- 使用导出功能保存重要数据
- 定期备份证书文件

#### 2. 安全建议

**证书管理:**
- ⚠️ 不要将CA证书分享给他人
- ⚠️ 测试完成后及时卸载证书
- ⚠️ 定期更换CA证书

**网络安全:**
- 只在可信网络环境使用
- 不要在公共WiFi下使用
- 注意保护捕获的敏感数据

#### 3. 调试技巧

**快速定位问题:**
1. 使用域名搜索快速找到目标请求
2. 按状态码过滤找出错误请求
3. 查看请求时间线分析性能

**移动端调试:**
1. 使用Safari/Chrome远程调试配合代理
2. 查看Console日志和Network面板
3. 对比代理捕获的数据验证

### 🔧 Native Hook最佳实践

#### 1. Hook策略

**选择性Hook:**
- 只Hook必要的API
- 避免Hook高频调用的函数
- 使用条件判断减少日志

**示例:**
```javascript
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        // 只记录特定条件的调用
        if (args[0].toInt32() > 1000) {
            send({...});
        }
    }
});
```

#### 2. 脚本开发

**模块化设计:**
```javascript
// 定义Hook模块
var NetworkHook = {
    init: function() {
        this.hookWinHTTP();
        this.hookWinINet();
    },

    hookWinHTTP: function() {
        // Hook WinHTTP API
    },

    hookWinINet: function() {
        // Hook WinINet API
    }
};

// 初始化
NetworkHook.init();
```

**错误处理:**
```javascript
try {
    var func = Module.findExportByName("module.dll", "Function");
    if (func) {
        Interceptor.attach(func, {...});
    } else {
        console.log("Function not found");
    }
} catch (e) {
    console.log("Error: " + e.message);
}
```

#### 3. 性能优化

**减少日志输出:**
- 使用采样策略（如每10次记录1次）
- 只记录关键参数
- 避免在onEnter/onLeave中执行耗时操作

**内存管理:**
- 及时清理Hook记录
- 不使用时分离进程
- 避免内存泄漏

### 📊 数据分析最佳实践

#### 1. 请求分析

**API分析:**
1. 导出请求数据
2. 使用工具分析API调用模式
3. 识别关键接口和参数

**性能分析:**
1. 按响应时间排序
2. 找出慢请求
3. 分析网络瓶颈

#### 2. 安全分析

**敏感数据检测:**
- 搜索关键词: password, token, key, secret
- 检查是否使用HTTPS
- 验证加密实现

**漏洞发现:**
- 测试参数注入
- 检查认证机制
- 分析会话管理

---

## 📞 技术支持

### 日志位置

**后端日志:**
```
backend/logs/app.log
```

**前端控制台:**
```
浏览器开发者工具 > Console
```

### 问题反馈

如遇到问题，请提供:
1. 系统版本信息
2. 错误日志
3. 复现步骤
4. 环境信息（操作系统、Python版本等）

---

## 📝 更新日志

### v2.0.0 (当前版本)

**新增功能:**
- ✅ 完整的代理捕获功能
- ✅ 移动端配置向导
- ✅ 证书自动管理
- ✅ 设备识别和过滤
- ✅ Native Hook集成（可选）
- ✅ Hook脚本模板系统
- ✅ 实时WebSocket通信
- ✅ 响应式布局支持

**改进:**
- 🎨 优化UI/UX设计
- ⚡ 提升性能和稳定性
- 📱 增强移动端支持
- 🔒 加强安全性

---

## 🎓 学习资源

### 代理技术
- [mitmproxy文档](https://docs.mitmproxy.org/)
- [HTTP/HTTPS协议](https://developer.mozilla.org/zh-CN/docs/Web/HTTP)

### Frida Hook
- [Frida官方文档](https://frida.re/docs/home/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [Frida示例代码](https://github.com/frida/frida-examples)

### 前端技术
- [React文档](https://react.dev/)
- [Ant Design](https://ant.design/)
- [TypeScript](https://www.typescriptlang.org/)

---

**祝您使用愉快！** 🎉
