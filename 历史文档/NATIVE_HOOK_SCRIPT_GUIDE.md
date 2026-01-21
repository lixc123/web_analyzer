# Native Hook 脚本开发指南

> 版本: 1.0
> 更新日期: 2026-01-21

---

## 📖 目录

1. [简介](#简介)
2. [快速开始](#快速开始)
3. [Frida基础](#frida基础)
4. [脚本模板](#脚本模板)
5. [常用Hook场景](#常用hook场景)
6. [调试技巧](#调试技巧)
7. [最佳实践](#最佳实践)
8. [常见问题](#常见问题)

---

## 简介

Native Hook 功能基于 [Frida](https://frida.re/) 框架，允许你在运行时动态注入JavaScript代码到目标进程，实现函数拦截、参数修改、返回值篡改等高级功能。

### 适用场景

- Windows桌面应用抓包（绕过证书固定）
- API调用监控和分析
- 函数参数和返回值追踪
- 内存数据读取和修改
- 加密算法逆向分析

### 前置要求

- Python 3.7+
- Frida (`pip install frida frida-tools`)
- 目标进程的基本了解（函数名、模块名等）

---

## 快速开始

### 1. 启动Native Hook服务

```bash
# 启动后端服务
python start_backend_windows.py
```

### 2. 在Web界面操作

1. 打开浏览器访问 `http://localhost:8000`
2. 进入 "Native Hook" 页面
3. 选择目标进程
4. 点击"附加"按钮
5. 选择或编写Hook脚本
6. 点击"注入脚本"

### 3. 查看Hook结果

Hook记录会实时显示在页面下方，包括：
- 函数调用信息
- 参数值
- 返回值
- 调用栈（如果启用）

---

## Frida基础

### 脚本结构

Frida脚本使用JavaScript编写，基本结构如下：

```javascript
// 1. 获取模块
const module = Process.getModuleByName("target.dll");

// 2. 获取函数地址
const funcAddress = module.getExportByName("FunctionName");

// 3. Hook函数
Interceptor.attach(funcAddress, {
    onEnter: function(args) {
        // 函数调用前执行
        console.log("Function called!");
        console.log("Arg1:", args[0]);
    },
    onLeave: function(retval) {
        // 函数返回前执行
        console.log("Return value:", retval);
    }
});
```

### 核心API

#### Process对象

```javascript
// 获取模块
Process.getModuleByName("kernel32.dll")

// 枚举所有模块
Process.enumerateModules()

// 获取当前进程ID
Process.id

// 获取进程架构
Process.arch  // 'x64' 或 'ia32'
```

#### Module对象

```javascript
// 获取导出函数地址
module.getExportByName("CreateFileW")

// 枚举所有导出函数
module.enumerateExports()

// 获取模块基址
module.base

// 获取模块大小
module.size
```

#### Interceptor对象

```javascript
// 附加到函数
Interceptor.attach(address, callbacks)

// 替换函数实现
Interceptor.replace(address, implementation)

// 分离Hook
Interceptor.detach()
```

#### Memory对象

```javascript
// 读取内存
Memory.readUtf8String(address)
Memory.readByteArray(address, length)
Memory.readPointer(address)

// 写入内存
Memory.writeUtf8String(address, string)
Memory.writeByteArray(address, bytes)

// 分配内存
Memory.alloc(size)
```

---

## 脚本模板

### 1. HTTP请求拦截（WinHTTP）

```javascript
// Hook WinHTTP API 拦截HTTP请求
const winhttp = Process.getModuleByName("winhttp.dll");

// Hook WinHttpSendRequest
const sendRequest = winhttp.getExportByName("WinHttpSendRequest");
Interceptor.attach(sendRequest, {
    onEnter: function(args) {
        const hRequest = args[0];
        console.log("[WinHttpSendRequest] Called");
        
        // 读取请求头
        if (!args[1].isNull()) {
            const headers = Memory.readUtf16String(args[1]);
            console.log("Headers:", headers);
        }
        
        // 读取请求体
        const dataLength = args[3].toInt32();
        if (dataLength > 0 && !args[4].isNull()) {
            const data = Memory.readByteArray(args[4], dataLength);
            console.log("Body:", hexdump(data));
        }
    },
    onLeave: function(retval) {
        console.log("Return:", retval);
    }
});

// Hook WinHttpReceiveResponse
const receiveResponse = winhttp.getExportByName("WinHttpReceiveResponse");
Interceptor.attach(receiveResponse, {
    onEnter: function(args) {
        console.log("[WinHttpReceiveResponse] Called");
    }
});
```

### 2. SSL证书验证绕过

```javascript
// 绕过SSL证书验证（WinHTTP）
const winhttp = Process.getModuleByName("winhttp.dll");

// Hook WinHttpSetOption
const setOption = winhttp.getExportByName("WinHttpSetOption");
Interceptor.attach(setOption, {
    onEnter: function(args) {
        const option = args[1].toInt32();
        
        // WINHTTP_OPTION_SECURITY_FLAGS = 31
        if (option === 31) {
            console.log("[SSL] Intercepting security flags");
            
            // 设置忽略所有SSL错误的标志
            const flags = ptr(0x3300); // 忽略所有证书错误
            args[2] = flags;
        }
    }
});
```

### 3. 函数参数追踪

```javascript
// 追踪特定函数的所有调用
const module = Process.getModuleByName("target.dll");
const funcAddress = module.getExportByName("TargetFunction");

Interceptor.attach(funcAddress, {
    onEnter: function(args) {
        console.log("\\n=== Function Called ===");
        console.log("Timestamp:", new Date().toISOString());
        
        // 打印参数
        for (let i = 0; i < 4; i++) {
            console.log(`Arg${i}:`, args[i]);
            
            // 尝试读取字符串
            try {
                const str = Memory.readUtf8String(args[i]);
                if (str && str.length > 0 && str.length < 1000) {
                    console.log(`  -> String: ${str}`);
                }
            } catch (e) {}
        }
        
        // 打印调用栈
        console.log("\\nBacktrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\\n"));
    },
    onLeave: function(retval) {
        console.log("Return value:", retval);
        console.log("======================\\n");
    }
});
```

### 4. 加密函数Hook

```javascript
// Hook加密函数，记录输入输出
const crypto = Process.getModuleByName("cryptodll.dll");
const encryptFunc = crypto.getExportByName("EncryptData");

Interceptor.attach(encryptFunc, {
    onEnter: function(args) {
        // 保存输入数据
        this.inputData = Memory.readByteArray(args[0], args[1].toInt32());
        this.inputLength = args[1].toInt32();
        
        console.log("[Encrypt] Input:");
        console.log(hexdump(this.inputData));
    },
    onLeave: function(retval) {
        // 读取输出数据
        const outputData = Memory.readByteArray(retval, this.inputLength);
        
        console.log("[Encrypt] Output:");
        console.log(hexdump(outputData));
    }
});
```

### 5. 返回值修改

```javascript
// 修改函数返回值
const module = Process.getModuleByName("target.dll");
const checkLicense = module.getExportByName("CheckLicense");

Interceptor.attach(checkLicense, {
    onLeave: function(retval) {
        console.log("Original return value:", retval);
        
        // 强制返回成功（1）
        retval.replace(1);
        
        console.log("Modified return value:", retval);
    }
});
```

---

## 常用Hook场景

### 场景1：抓取HTTPS请求（绕过证书固定）

**目标**: 抓取使用证书固定的应用的HTTPS流量

**方案**: Hook SSL验证函数，强制返回成功

```javascript
// WinHTTP证书验证绕过
const winhttp = Process.getModuleByName("winhttp.dll");

// 方法1：Hook WinHttpSetOption
const setOption = winhttp.getExportByName("WinHttpSetOption");
Interceptor.attach(setOption, {
    onEnter: function(args) {
        const option = args[1].toInt32();
        if (option === 31) { // WINHTTP_OPTION_SECURITY_FLAGS
            args[2] = ptr(0x3300); // 忽略所有证书错误
        }
    }
});

// 方法2：Hook证书验证回调
// 需要根据具体应用调整
```

### 场景2：API调用监控

**目标**: 监控应用的所有网络请求

**方案**: Hook网络相关API

```javascript
// Hook多个网络API
const apis = [
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "InternetReadFile",
    "HttpSendRequestW"
];

apis.forEach(apiName => {
    try {
        const addr = Module.findExportByName(null, apiName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log(`[${apiName}] Called`);
                    console.log("Args:", args[0], args[1], args[2]);
                }
            });
            console.log(`Hooked: ${apiName}`);
        }
    } catch (e) {
        console.log(`Failed to hook ${apiName}: ${e}`);
    }
});
```

### 场景3：内存数据提取

**目标**: 从内存中提取敏感数据（如密钥、token）

**方案**: Hook数据处理函数，读取内存

```javascript
// Hook数据处理函数
const processData = Module.findExportByName("app.exe", "ProcessData");

Interceptor.attach(processData, {
    onEnter: function(args) {
        // 读取数据缓冲区
        const dataPtr = args[0];
        const dataLen = args[1].toInt32();
        
        const data = Memory.readByteArray(dataPtr, dataLen);
        const dataStr = Memory.readUtf8String(dataPtr, dataLen);
        
        console.log("Data (hex):", hexdump(data));
        console.log("Data (string):", dataStr);
        
        // 搜索特定模式（如JWT token）
        if (dataStr.includes("eyJ")) {
            console.log("!!! Found JWT token:", dataStr);
        }
    }
});
```

---

## 调试技巧

### 1. 日志输出

```javascript
// 基础日志
console.log("Message");
console.warn("Warning");
console.error("Error");

// 格式化输出
console.log("Value:", value, "Type:", typeof value);

// 十六进制dump
console.log(hexdump(buffer));
```

### 2. 异常处理

```javascript
try {
    // 可能出错的代码
    const str = Memory.readUtf8String(ptr);
} catch (e) {
    console.error("Error:", e.message);
    console.error("Stack:", e.stack);
}
```

### 3. 条件断点

```javascript
Interceptor.attach(funcAddress, {
    onEnter: function(args) {
        // 只在特定条件下记录
        const param = args[0].toInt32();
        if (param > 1000) {
            console.log("Large parameter detected:", param);
        }
    }
});
```

### 4. 性能优化

```javascript
// 避免频繁的字符串操作
let callCount = 0;
Interceptor.attach(funcAddress, {
    onEnter: function(args) {
        callCount++;
        
        // 每100次调用才输出一次
        if (callCount % 100 === 0) {
            console.log("Called", callCount, "times");
        }
    }
});
```

---

## 最佳实践

### 1. 脚本组织

```javascript
// 使用立即执行函数避免全局污染
(function() {
    'use strict';
    
    // 配置
    const CONFIG = {
        targetModule: "target.dll",
        logLevel: "info"
    };
    
    // 工具函数
    function log(msg) {
        if (CONFIG.logLevel === "info") {
            console.log(`[Hook] ${msg}`);
        }
    }
    
    // Hook逻辑
    function hookFunction() {
        // ...
    }
    
    // 初始化
    hookFunction();
})();
```

### 2. 错误处理

```javascript
function safeHook(moduleName, functionName) {
    try {
        const module = Process.getModuleByName(moduleName);
        const func = module.getExportByName(functionName);
        
        Interceptor.attach(func, {
            onEnter: function(args) {
                // Hook逻辑
            }
        });
        
        console.log(`✓ Hooked: ${moduleName}!${functionName}`);
        return true;
    } catch (e) {
        console.error(`✗ Failed to hook ${moduleName}!${functionName}: ${e.message}`);
        return false;
    }
}
```

### 3. 模块化

```javascript
// 创建Hook管理器
const HookManager = {
    hooks: [],
    
    add: function(address, callbacks) {
        const hook = Interceptor.attach(address, callbacks);
        this.hooks.push(hook);
        return hook;
    },
    
    removeAll: function() {
        this.hooks.forEach(h => h.detach());
        this.hooks = [];
    }
};

// 使用
HookManager.add(funcAddress, {
    onEnter: function(args) {
        // ...
    }
});
```

---

## 常见问题

### Q1: 找不到模块或函数

**问题**: `Error: unable to find module 'xxx.dll'`

**解决方案**:
```javascript
// 1. 检查模块是否已加载
Process.enumerateModules().forEach(m => {
    console.log(m.name);
});

// 2. 使用模块加载事件
Process.setExceptionHandler(function(details) {
    console.log("Exception:", details);
    return true;
});

// 3. 延迟Hook
setTimeout(function() {
    // Hook代码
}, 1000);
```

### Q2: 进程崩溃

**原因**: 
- 错误的参数修改
- 内存访问违规
- 栈破坏

**解决方案**:
```javascript
// 1. 添加异常处理
Process.setExceptionHandler(function(details) {
    console.error("Crash detected:", details);
    return false; // 不处理，让进程崩溃以便调试
});

// 2. 只读取，不修改
Interceptor.attach(funcAddress, {
    onEnter: function(args) {
        // 只记录，不修改
        console.log("Args:", args[0]);
    }
});
```

### Q3: Hook不生效

**检查清单**:
1. 确认进程已附加
2. 确认模块和函数名正确
3. 确认函数确实被调用了
4. 检查是否有反调试保护

```javascript
// 添加调试信息
console.log("Script loaded");

const module = Process.getModuleByName("target.dll");
console.log("Module found:", module.name);

const func = module.getExportByName("Function");
console.log("Function address:", func);

Interceptor.attach(func, {
    onEnter: function(args) {
        console.log("!!! Function called !!!");
    }
});
```

### Q4: 如何Hook未导出的函数

**方案1**: 使用偏移地址
```javascript
const module = Process.getModuleByName("target.dll");
const funcAddress = module.base.add(0x12345); // 偏移地址

Interceptor.attach(funcAddress, {
    // ...
});
```

**方案2**: 使用模式扫描
```javascript
const pattern = "48 89 5C 24 ?? 48 89 74 24 ??";
const results = Memory.scanSync(module.base, module.size, pattern);

if (results.length > 0) {
    const funcAddress = results[0].address;
    Interceptor.attach(funcAddress, {
        // ...
    });
}
```

---

## 参考资源

- [Frida官方文档](https://frida.re/docs/home/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [Frida CodeShare](https://codeshare.frida.re/)
- [Frida Handbook](https://learnfrida.info/)

---

## 更新日志

- **2026-01-21**: 初始版本发布

---

*文档维护: 开发团队*
*最后更新: 2026-01-21*
