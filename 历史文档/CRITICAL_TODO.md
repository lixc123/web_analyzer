# 关键功能缺失清单

> 本文档列出项目中真正重要且缺失的功能，按优先级排序

## 当前项目状态

### 已实现的核心功能 ✅
- 浏览器网络请求录制（Playwright + CDP）
- JavaScript Hook系统（fetch、XHR、localStorage、sessionStorage、IndexedDB、DOM、Navigation、Console、Performance）
- Windows系统代理设置（注册表操作）
- 移动端代理抓包（mitmproxy + 设备识别）
- 代码生成（Python/JavaScript回放脚本）
- HAR格式导出
- 调用栈捕获和关联
- 实时WebSocket推送

### 未实现的Hook类型 ❌
**重要说明：** 项目目前**没有实现传统意义上的内存Hook**，只有应用层Hook。

**已实现的Hook层级：**
- ✅ JavaScript API Hook（浏览器层面）- 通过注入脚本拦截浏览器API
- ✅ 网络代理Hook（系统层面）- 通过代理服务器拦截HTTP/HTTPS流量

**未实现的内存Hook：**
- ❌ 进程内存读写（ReadProcessMemory/WriteProcessMemory）
- ❌ 函数地址Hook（Inline Hook / IAT Hook / EAT Hook）
- ❌ Native函数拦截（Hook Windows API如CreateFile、RegOpenKey等）
- ❌ DLL注入（LoadLibrary注入、远程线程注入）
- ❌ 内核级Hook（SSDT Hook、IRP Hook）
- ❌ 移动端Native Hook（需要Frida/Xposed）

**如需内存Hook功能，需要集成：**
- **Frida** - 跨平台动态插桩框架（推荐）
- **Detours** - Microsoft的API Hook库（Windows）
- **WinDivert** - 内核级网络包拦截（Windows）
- **Xposed/LSPosed** - Android框架Hook（需要root）

**结论：** 当前是**非侵入式的应用层Hook**，适用于Web逆向分析。如需深度逆向（如破解软件、游戏外挂、恶意软件分析），需要补充内存Hook能力。

---

## 数据获取功能现状分析

### 已实现的数据获取 ✅
- **网络数据**：HTTP/HTTPS请求（fetch、XHR）
- **存储数据**：localStorage、sessionStorage、IndexedDB（仅监控操作，未导出完整数据）
- **用户交互**：点击、输入、滚动等事件
- **DOM变化**：MutationObserver监控
- **性能数据**：页面加载时间、资源加载

### 缺失的数据获取功能 ❌

**1. 存储数据完整导出**
- ❌ localStorage/sessionStorage完整快照导出
- ❌ IndexedDB数据库结构和数据导出
- ❌ Cookie完整列表和属性
- ❌ Cache Storage内容

**2. 应用状态数据**
- ❌ Redux/Vuex/MobX等状态管理数据
- ❌ 全局变量快照（window对象关键属性）
- ❌ React/Vue组件状态树

**3. 实时通信数据**
- ❌ WebSocket消息（重要！）

---

## 第一优先级：核心逆向能力缺失

### 1. WebSocket Hook 和协议解析 ✅
**重要性：极高**
**状态：已完成**

**已实现功能：**
- ✅ WebSocket连接拦截（`new WebSocket()`）
- ✅ 消息发送/接收Hook（`send()`、`onmessage`）
- ✅ 连接状态追踪（open、close、error）
- ✅ 消息数据类型识别（string、Blob、ArrayBuffer）
- ✅ 消息大小统计和预览（超过1000字符自动截断）
- ✅ 调用栈捕获

**实现位置：**
- `backend/core/js_hooks.py:376-489` - JS_HOOK_WEBSOCKET模块
- `backend/core/network_recorder.py:180-183` - WebSocket事件处理
- `backend/core/network_recorder.py:503-549` - _process_websocket_event方法

---

### 2. Crypto API Hook ✅
**重要性：极高**
**状态：已完成**

**已实现功能：**
- ✅ crypto.subtle.encrypt/decrypt 拦截
- ✅ crypto.subtle.sign/verify 拦截
- ✅ crypto.subtle.digest 拦截（SHA系列哈希）
- ✅ crypto.getRandomValues 拦截
- ✅ 加密参数记录（算法、数据大小、数据预览）
- ✅ 结果捕获（加密/解密结果、哈希值、签名）
- ✅ 错误捕获和调用栈记录

**实现位置：**
- `backend/core/js_hooks.py:491-666` - JS_HOOK_CRYPTO模块
- 支持所有Web Crypto API操作

---

### 3. 参数签名分析工具 ✅
**重要性：高**
**状态：已完成**

**已实现功能：**
- ✅ 自动识别请求中的签名参数（sign、signature、token等）
- ✅ 识别时间戳/nonce参数
- ✅ 检测签名算法特征（MD5、SHA1、SHA256、Base64、JWT）
- ✅ 参数频率统计和置信度计算
- ✅ 参数组合模式分析
- ✅ 签名值长度和格式分析

**实现位置：**
- `backend/utils/signature_analyzer.py` - SignatureAnalyzer类
- 支持从URL参数和POST数据中提取签名信息

**分析结果示例：**
```json
{
  "signature_params": [
    {"name": "sign", "frequency": 10, "confidence": 1.0}
  ],
  "algorithm_hints": [
    {"param": "sign", "algorithm": "MD5", "value_length": 32}
  ],
  "patterns": [
    {"type": "parameter_combination", "params": ["sign", "timestamp", "nonce"]}
  ]
}
```

---

### 4. 存储数据完整导出 ✅
**重要性：高**
**状态：已完成**

**已实现功能：**
- ✅ localStorage完整快照导出（所有key-value）
- ✅ sessionStorage完整快照导出
- ✅ Cookie完整列表导出
- ✅ IndexedDB数据库列表、表结构、完整数据导出
- ✅ 自动在页面加载后导出所有存储数据
- ✅ 数据统计（key数量、cookie数量、数据库数量）

**实现位置：**
- `backend/core/js_hooks.py:668-770` - JS_HOOK_STORAGE_EXPORT模块
- 页面加载2秒后自动导出所有存储数据

**导出数据格式：**
```json
{
  "localStorage": {"key1": "value1", ...},
  "sessionStorage": {...},
  "cookies": [{"name": "...", "value": "..."}],
  "indexedDB": {
    "database1": {
      "version": 1,
      "stores": ["store1", "store2"],
      "data": {...}
    }
  }
}
```

---

### 5. 应用状态捕获（Redux/Vuex等）✅
**重要性：中高**
**状态：已完成**

**已实现功能：**
- ✅ Redux DevTools Extension集成和状态捕获
- ✅ Vuex状态树捕获（mutation和state）
- ✅ Pinia状态管理捕获
- ✅ 全局变量快照（__INITIAL_STATE__、__PRELOADED_STATE__等）

**实现位置：**
- `backend/core/js_hooks.py:772-850` - JS_HOOK_STATE_MANAGEMENT模块
- Hook Redux DevTools的connect和subscribe方法
- Hook Vuex的commit方法捕获mutation
- 定时捕获Pinia的state.value
- 捕获常见全局状态变量

**捕获数据格式：**
```javascript
// Redux
[STATE_REDUX] {"timestamp": 1234567890, "state": {...}, "action": {...}}

// Vuex
[STATE_VUEX] {"timestamp": 1234567890, "mutation": "SET_USER", "payload": {...}, "state": {...}}

// Pinia
[STATE_PINIA] {"timestamp": 1234567890, "store": "user", "state": {...}}

// Global
[STATE_GLOBAL] {"timestamp": 1234567890, "snapshot": {...}}
```

---

## 第二优先级：开发效率提升

### 6. JavaScript代码美化器 ✅
**重要性：中高**
**状态：已完成**

**已实现功能：**
- ✅ 自动格式化压缩的JS代码
- ✅ 使用jsbeautifier库进行代码美化
- ✅ 提供API接口供前端调用

**实现位置：**
- `backend/utils/js_beautifier.py` - 代码美化工具模块
- `backend/app/api/v1/analysis.py:260-268` - API接口
- `backend/requirements.txt:34` - 添加jsbeautifier依赖

**API使用示例：**
```bash
POST /api/v1/analysis/beautify-js
{
  "code": "function test(){console.log('hello');}"
}

# 返回
{
  "beautified_code": "function test() {\n  console.log('hello');\n}"
}
```

---

### 7. 请求依赖关系图 ✅
**重要性：中高**
**状态：已完成**

**已实现功能：**
- ✅ 基于时间戳构建依赖图
- ✅ 识别请求间的数据传递（响应→请求参数）
- ✅ 自动检测数据依赖关系
- ✅ 生成节点和边的图数据结构

**实现位置：**
- `backend/utils/dependency_analyzer.py` - DependencyAnalyzer类
- `backend/app/api/v1/analysis.py:274-283` - API接口

**API使用示例：**
```bash
POST /api/v1/analysis/dependency-graph
{
  "requests": [
    {"id": "req1", "url": "https://api.example.com/login", "method": "POST", "timestamp": 1000, "response": {"token": "abc123"}},
    {"id": "req2", "url": "https://api.example.com/user?token=abc123", "method": "GET", "timestamp": 2000}
  ]
}

# 返回
{
  "nodes": [
    {"id": "req1", "url": "https://api.example.com/login", "method": "POST", "timestamp": 1000},
    {"id": "req2", "url": "https://api.example.com/user", "method": "GET", "timestamp": 2000}
  ],
  "edges": [
    {"source": "req1", "target": "req2", "type": "data_flow"}
  ]
}
```

---

### 8. 自动重放验证工具 ✅
**重要性：中**
**状态：已完成**

**已实现功能：**
- ✅ 一键批量执行回放脚本
- ✅ 自动对比响应差异（状态码、响应体）
- ✅ 识别失败原因（签名错误、token过期、参数缺失）
- ✅ 生成验证报告

**实现位置：**
- `backend/utils/replay_validator.py` - ReplayValidator类
- `backend/app/api/v1/analysis.py:286-295` - API接口

**API使用示例：**
```bash
POST /api/v1/analysis/replay-validate
{
  "requests": [
    {
      "id": "req1",
      "url": "https://api.example.com/user",
      "method": "GET",
      "headers": {"Authorization": "Bearer token"},
      "response": {"status_code": 200, "body": "{\"name\":\"test\"}"}
    }
  ]
}

# 返回
{
  "total": 1,
  "success": 1,
  "failed": 0,
  "results": [
    {
      "request_id": "req1",
      "url": "https://api.example.com/user",
      "status": "success",
      "diff": {"match": true, "status_code_match": true, "body_match": true},
      "failure_reason": null
    }
  ]
}
```

---

## 第三优先级：高级功能

### 9. 反混淆引擎（可选）🟢
**重要性：中低**

**说明：** 处理obfuscator.io等混淆器的代码，技术难度高，可以先用第三方工具。

**建议：** 集成现有工具（如webcrack、deobfuscate.io）而非自己实现。

---

### 10. Frida集成（移动端Native Hook）🟢
**重要性：中低**

**说明：** 支持Android/iOS原生层Hook，需要Frida环境，复杂度高。

**建议：** 作为独立模块，不影响核心功能。

---

## 实现建议

### 立即开始（本周）
1. **WebSocket Hook** - 补齐协议支持
2. **Crypto API Hook** - 加密分析核心
3. **存储数据完整导出** - 获取应用完整状态

### 短期规划（本月）
4. **参数签名分析** - 提升逆向效率
5. **应用状态捕获** - Redux/Vuex等状态管理
6. **代码美化器** - 改善代码可读性

### 中期规划（下月）
7. **依赖关系图** - 可视化分析
8. **自动重放验证** - 提升测试效率

---

## 不建议实现的功能

以下功能增益较小或可用替代方案：

- ❌ Canvas/WebGL Hook - 使用场景少
- ❌ 完整的反混淆引擎 - 可用第三方工具
- ❌ AI辅助分析 - 锦上添花但非核心
- ❌ 验证码识别 - 可用第三方服务
- ❌ 浏览器指纹伪造 - playwright-stealth已覆盖
- ❌ PostMessage/BroadcastChannel Hook - 使用场景少
- ❌ Clipboard/Notification/Geolocation API Hook - 非核心数据源
- ❌ SharedWorker/ServiceWorker通信拦截 - 复杂度高，使用场景少

---

## 总结

**核心缺失（必须补充）：**
1. ✅ WebSocket Hook - 实时通信协议（已完成）
2. ✅ Crypto API Hook - 加密分析（已完成）
3. ✅ 存储数据完整导出 - 应用状态获取（已完成）
4. ✅ 参数签名分析 - 自动化逆向（已完成）
5. ✅ 应用状态捕获 - Redux/Vuex等（已完成）

**所有核心功能已完成！✅**

**效率提升（建议补充）：**
6. ✅ 代码美化器（已完成）
7. ✅ 依赖关系图（已完成）
8. ✅ 自动重放验证（已完成）

**所有第二优先级功能已完成！✅**

**数据获取整合说明：**
当前项目在**数据获取方面的核心短板**：
- ✅ 网络请求数据（HTTP/HTTPS）- 完善
- ⚠️ 存储数据（localStorage/IndexedDB）- 仅监控操作，未导出完整数据
- ❌ 实时通信数据（WebSocket）- 完全缺失
- ❌ 应用状态数据（Redux/Vuex）- 完全缺失

**补充上述核心功能后，将实现完整的Web应用数据获取能力，成为功能完善的Web逆向分析平台。**

---

*文档创建时间: 2026-01-19*
*项目版本: Web Analyzer V2*
