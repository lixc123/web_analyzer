# 多平台网络请求录制系统设计方案

## 一、概述

本方案旨在扩展现有的网页爬虫录制功能，增加以下三大能力：
1. **Windows桌面应用请求捕获** - 通过代理/钩子技术捕获桌面应用的HTTP(S)请求
2. **移动端请求录制** - 类似Charles的代理方式，手机配置代理后捕获请求
3. **统一的请求管理界面** - 整合所有来源的请求数据

## 二、技术方案对比

### 2.1 Windows应用请求捕获方案

| 方案 | 原理 | 优点 | 缺点 | 推荐度 |
|------|------|------|------|--------|
| **系统代理** | 设置Windows系统代理 | 简单、无侵入 | 部分应用不走系统代理 | ⭐⭐⭐⭐ |
| **WinDivert** | 内核级网络包拦截 | 能捕获所有流量 | 需要驱动签名、复杂 | ⭐⭐⭐ |
| **API Hook** | Hook WinHTTP/WinINet | 精准控制 | 需要注入、兼容性问题 | ⭐⭐ |
| **Fiddler Core** | 成熟的代理库 | 功能完善 | 商业授权 | ⭐⭐⭐ |

### 2.2 移动端请求捕获方案

| 方案 | 原理 | 优点 | 缺点 | 推荐度 |
|------|------|------|------|--------|
| **HTTP代理** | 手机配置WiFi代理 | 简单通用 | 需要安装CA证书 | ⭐⭐⭐⭐⭐ |
| **VPN模式** | 创建本地VPN | 无需配置代理 | 实现复杂 | ⭐⭐ |
| **ADB转发** | USB连接转发 | 稳定 | 需要USB连接 | ⭐⭐⭐ |

## 三、推荐架构设计

### 3.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Analyzer V2                          │
│                      (统一管理界面)                              │
├─────────────────────────────────────────────────────────────────┤
│                     请求数据统一存储层                           │
│              (SQLite/JSON + 实时WebSocket推送)                  │
├──────────────┬──────────────────┬───────────────────────────────┤
│   网页录制    │   桌面应用录制    │        移动端录制             │
│  (现有功能)   │   (新增模块)      │       (新增模块)              │
│              │                  │                               │
│  Playwright  │  mitmproxy核心   │    mitmproxy代理服务          │
│  CDP协议     │  + 系统代理设置   │    + CA证书管理               │
└──────────────┴──────────────────┴───────────────────────────────┘
```

### 3.2 核心技术选型

**推荐使用 mitmproxy 作为核心代理引擎**

理由：
1. Python原生，与现有后端技术栈一致
2. 开源免费，MIT协议
3. 支持HTTP/HTTPS/WebSocket
4. 提供Python API，易于集成
5. 自动生成CA证书
6. 活跃的社区支持

```bash
# 安装
pip install mitmproxy
```

## 四、详细模块设计

### 4.1 代理服务核心模块

```
backend/
├── proxy/
│   ├── __init__.py
│   ├── proxy_server.py      # 代理服务器主类
│   ├── request_handler.py   # 请求处理器
│   ├── cert_manager.py      # CA证书管理
│   ├── system_proxy.py      # 系统代理设置(Windows)
│   └── filters.py           # 请求过滤规则
```

### 4.2 代理服务器核心代码设计

```python
# proxy_server.py
import asyncio
from mitmproxy import options
from mitmproxy.tools import dump
from mitmproxy import http
from typing import Callable, Optional
import threading

class ProxyServer:
    """统一代理服务器 - 支持桌面和移动端"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None
    ):
        self.host = host
        self.port = port
        self.on_request = on_request
        self.on_response = on_response
        self._master = None
        self._thread = None
        self._running = False

    def start(self):
        """启动代理服务器"""
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=True  # 允许自签名证书
        )
        self._master = dump.DumpMaster(opts)
        self._master.addons.add(RequestInterceptor(
            self.on_request,
            self.on_response
        ))

        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._running = True
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(asyncio.new_event_loop())
        self._master.run()

    def stop(self):
        """停止代理服务器"""
        if self._master:
            self._master.shutdown()
        self._running = False

class RequestInterceptor:
    """请求拦截器"""

    def __init__(self, on_request, on_response):
        self.on_request = on_request
        self.on_response = on_response

    def request(self, flow: http.HTTPFlow):
        """拦截请求"""
        if self.on_request:
            self.on_request({
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "body": flow.request.get_text(),
                "timestamp": flow.request.timestamp_start
            })

    def response(self, flow: http.HTTPFlow):
        """拦截响应"""
        if self.on_response:
            self.on_response({
                "url": flow.request.pretty_url,
                "status": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "body": flow.response.get_text()[:10000],  # 限制大小
                "size": len(flow.response.content),
                "timestamp": flow.response.timestamp_end
            })
```

### 4.3 Windows系统代理设置模块

```python
# system_proxy.py
import winreg
import ctypes
from typing import Optional

class WindowsSystemProxy:
    """Windows系统代理管理器"""

    INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self):
        self._original_settings = None

    def enable_proxy(self, host: str = "127.0.0.1", port: int = 8888):
        """启用系统代理"""
        # 保存原始设置
        self._original_settings = self.get_current_settings()

        proxy_server = f"{host}:{port}"

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.INTERNET_SETTINGS,
                0,
                winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
                # 设置不代理的地址
                winreg.SetValueEx(
                    key, "ProxyOverride", 0, winreg.REG_SZ,
                    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;192.168.*"
                )

            # 通知系统设置已更改
            self._refresh_settings()
            return True
        except Exception as e:
            print(f"设置代理失败: {e}")
            return False

    def disable_proxy(self):
        """禁用系统代理"""
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.INTERNET_SETTINGS,
                0,
                winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

            self._refresh_settings()
            return True
        except Exception as e:
            print(f"禁用代理失败: {e}")
            return False

    def restore_original(self):
        """恢复原始代理设置"""
        if self._original_settings:
            if self._original_settings.get("enabled"):
                self.enable_proxy(
                    self._original_settings.get("host", ""),
                    self._original_settings.get("port", 0)
                )
            else:
                self.disable_proxy()

    def get_current_settings(self) -> dict:
        """获取当前代理设置"""
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.INTERNET_SETTINGS
            ) as key:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
                server = winreg.QueryValueEx(key, "ProxyServer")[0]

                host, port = "", 0
                if ":" in server:
                    host, port = server.rsplit(":", 1)
                    port = int(port)

                return {"enabled": bool(enabled), "host": host, "port": port}
        except:
            return {"enabled": False, "host": "", "port": 0}

    def _refresh_settings(self):
        """刷新系统网络设置"""
        INTERNET_OPTION_REFRESH = 37
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
```

### 4.4 CA证书管理模块

```python
# cert_manager.py
import os
import subprocess
from pathlib import Path
from mitmproxy import certs
import qrcode
from io import BytesIO
import base64

class CertManager:
    """CA证书管理器"""

    def __init__(self, cert_dir: str = None):
        if cert_dir is None:
            cert_dir = os.path.expanduser("~/.mitmproxy")
        self.cert_dir = Path(cert_dir)
        self.ca_cert_path = self.cert_dir / "mitmproxy-ca-cert.pem"
        self.ca_cert_cer = self.cert_dir / "mitmproxy-ca-cert.cer"

    def ensure_ca_exists(self) -> bool:
        """确保CA证书存在，不存在则生成"""
        if not self.ca_cert_path.exists():
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            # mitmproxy会自动生成证书
            return False
        return True

    def get_cert_path(self) -> str:
        """获取CA证书路径"""
        return str(self.ca_cert_path)

    def get_cert_for_mobile(self) -> dict:
        """获取移动端安装所需的证书信息"""
        if not self.ca_cert_path.exists():
            return {"error": "CA证书不存在"}

        with open(self.ca_cert_path, "rb") as f:
            cert_content = f.read()

        return {
            "path": str(self.ca_cert_path),
            "content_base64": base64.b64encode(cert_content).decode(),
            "filename": "mitmproxy-ca-cert.pem"
        }

    def generate_qr_code(self, download_url: str) -> str:
        """生成证书下载二维码(Base64)"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(download_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")

        return base64.b64encode(buffer.getvalue()).decode()

    def install_cert_windows(self) -> bool:
        """在Windows系统中安装CA证书到受信任的根证书"""
        try:
            # 使用certutil安装证书
            result = subprocess.run(
                ["certutil", "-addstore", "-user", "Root", str(self.ca_cert_path)],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            print(f"安装证书失败: {e}")
            return False

    def uninstall_cert_windows(self) -> bool:
        """从Windows系统中移除CA证书"""
        try:
            result = subprocess.run(
                ["certutil", "-delstore", "-user", "Root", "mitmproxy"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            print(f"移除证书失败: {e}")
            return False

    def get_mobile_install_instructions(self, server_ip: str, port: int) -> dict:
        """获取移动端证书安装说明"""
        return {
            "ios": {
                "steps": [
                    f"1. 确保手机和电脑在同一WiFi网络",
                    f"2. 手机WiFi设置中配置HTTP代理: {server_ip}:{port}",
                    f"3. 用Safari打开 http://mitm.it",
                    f"4. 点击Apple图标下载证书",
                    f"5. 设置 -> 通用 -> VPN与设备管理 -> 安装证书",
                    f"6. 设置 -> 通用 -> 关于本机 -> 证书信任设置 -> 启用mitmproxy"
                ]
            },
            "android": {
                "steps": [
                    f"1. 确保手机和电脑在同一WiFi网络",
                    f"2. 手机WiFi设置中配置HTTP代理: {server_ip}:{port}",
                    f"3. 用浏览器打开 http://mitm.it",
                    f"4. 点击Android图标下载证书",
                    f"5. 设置 -> 安全 -> 加密与凭据 -> 安装证书",
                    f"6. 选择CA证书并安装"
                ],
                "note": "Android 7.0+的应用默认不信任用户证书，需要root或修改应用"
            }
        }
```

## 五、API接口设计

### 5.1 代理服务API

```python
# backend/app/api/v1/proxy.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter(prefix="/proxy", tags=["代理服务"])

class ProxyConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8888
    enable_system_proxy: bool = False  # 是否设置系统代理
    filter_hosts: List[str] = []       # 过滤的域名

class ProxyStatus(BaseModel):
    running: bool
    host: str
    port: int
    system_proxy_enabled: bool
    connected_clients: int
    total_requests: int

# 启动代理服务
@router.post("/start")
async def start_proxy(config: ProxyConfig):
    """启动代理服务器"""
    pass

# 停止代理服务
@router.post("/stop")
async def stop_proxy():
    """停止代理服务器"""
    pass

# 获取代理状态
@router.get("/status", response_model=ProxyStatus)
async def get_proxy_status():
    """获取代理服务器状态"""
    pass

# 获取本机IP地址(供移动端配置)
@router.get("/local-ip")
async def get_local_ip():
    """获取本机局域网IP"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return {"ip": ip}

# 下载CA证书
@router.get("/cert/download")
async def download_cert():
    """下载CA证书文件"""
    pass

# 获取证书安装说明
@router.get("/cert/instructions")
async def get_cert_instructions():
    """获取各平台证书安装说明"""
    pass

# 生成证书下载二维码
@router.get("/cert/qrcode")
async def get_cert_qrcode():
    """生成证书下载页面的二维码"""
    pass
```

### 5.2 请求过滤API

```python
# backend/app/api/v1/filters.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/filters", tags=["请求过滤"])

class FilterRule(BaseModel):
    id: str
    name: str
    type: str  # "include" | "exclude"
    pattern: str  # 正则表达式或通配符
    enabled: bool = True

@router.get("/rules")
async def get_filter_rules() -> List[FilterRule]:
    """获取所有过滤规则"""
    pass

@router.post("/rules")
async def add_filter_rule(rule: FilterRule):
    """添加过滤规则"""
    pass

@router.delete("/rules/{rule_id}")
async def delete_filter_rule(rule_id: str):
    """删除过滤规则"""
    pass

@router.put("/rules/{rule_id}")
async def update_filter_rule(rule_id: str, rule: FilterRule):
    """更新过滤规则"""
    pass
```

## 六、前端界面设计

### 6.1 新增页面/组件

```
frontend/src/
├── pages/
│   └── ProxyCapture/
│       ├── index.tsx           # 代理录制主页面
│       ├── ProxyControl.tsx    # 代理控制面板
│       ├── MobileSetup.tsx     # 移动端配置向导
│       └── CertManager.tsx     # 证书管理组件
├── components/
│   └── proxy/
│       ├── ProxyStatus.tsx     # 代理状态显示
│       ├── QRCodeDisplay.tsx   # 二维码显示
│       └── DeviceList.tsx      # 已连接设备列表
```

### 6.2 代理控制面板设计

```tsx
// ProxyControl.tsx
import React, { useState } from 'react';

interface ProxyConfig {
  port: number;
  enableSystemProxy: boolean;
  captureHttps: boolean;
}

export const ProxyControl: React.FC = () => {
  const [config, setConfig] = useState<ProxyConfig>({
    port: 8888,
    enableSystemProxy: false,
    captureHttps: true
  });
  const [isRunning, setIsRunning] = useState(false);
  const [localIP, setLocalIP] = useState('');

  const handleStart = async () => {
    // 调用API启动代理
    const response = await fetch('/api/v1/proxy/start', {
      method: 'POST',
      body: JSON.stringify(config)
    });
    if (response.ok) {
      setIsRunning(true);
      // 获取本机IP
      const ipRes = await fetch('/api/v1/proxy/local-ip');
      const { ip } = await ipRes.json();
      setLocalIP(ip);
    }
  };

  return (
    <div className="proxy-control">
      <h2>代理服务控制</h2>

      {/* 配置区域 */}
      <div className="config-section">
        <label>
          代理端口:
          <input
            type="number"
            value={config.port}
            onChange={e => setConfig({...config, port: +e.target.value})}
          />
        </label>

        <label>
          <input
            type="checkbox"
            checked={config.enableSystemProxy}
            onChange={e => setConfig({...config, enableSystemProxy: e.target.checked})}
          />
          自动设置系统代理 (Windows桌面应用)
        </label>

        <label>
          <input
            type="checkbox"
            checked={config.captureHttps}
            onChange={e => setConfig({...config, captureHttps: e.target.checked})}
          />
          捕获HTTPS请求
        </label>
      </div>

      {/* 控制按钮 */}
      <div className="control-buttons">
        {!isRunning ? (
          <button onClick={handleStart}>启动代理</button>
        ) : (
          <button onClick={() => setIsRunning(false)}>停止代理</button>
        )}
      </div>

      {/* 连接信息 */}
      {isRunning && localIP && (
        <div className="connection-info">
          <h3>移动端配置信息</h3>
          <p>代理地址: <strong>{localIP}:{config.port}</strong></p>
          <p>请在手机WiFi设置中配置HTTP代理</p>
        </div>
      )}
    </div>
  );
};
```

### 6.3 移动端配置向导

```tsx
// MobileSetup.tsx
import React, { useState, useEffect } from 'react';

export const MobileSetup: React.FC<{ proxyIP: string; proxyPort: number }> = ({
  proxyIP,
  proxyPort
}) => {
  const [qrCode, setQrCode] = useState('');
  const [platform, setPlatform] = useState<'ios' | 'android'>('ios');
  const [instructions, setInstructions] = useState<string[]>([]);

  useEffect(() => {
    // 获取二维码
    fetch('/api/v1/proxy/cert/qrcode')
      .then(res => res.json())
      .then(data => setQrCode(data.qrcode));

    // 获取安装说明
    fetch('/api/v1/proxy/cert/instructions')
      .then(res => res.json())
      .then(data => setInstructions(data[platform].steps));
  }, [platform]);

  return (
    <div className="mobile-setup">
      <h2>移动端配置向导</h2>

      {/* 平台选择 */}
      <div className="platform-tabs">
        <button
          className={platform === 'ios' ? 'active' : ''}
          onClick={() => setPlatform('ios')}
        >
          iOS
        </button>
        <button
          className={platform === 'android' ? 'active' : ''}
          onClick={() => setPlatform('android')}
        >
          Android
        </button>
      </div>

      {/* 配置步骤 */}
      <div className="setup-steps">
        <h3>配置步骤</h3>
        <ol>
          {instructions.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      </div>

      {/* 二维码 */}
      <div className="qr-section">
        <h3>扫码下载证书</h3>
        {qrCode && <img src={`data:image/png;base64,${qrCode}`} alt="证书下载二维码" />}
        <p>或访问: http://mitm.it</p>
      </div>

      {/* 代理配置信息 */}
      <div className="proxy-info">
        <h3>代理配置</h3>
        <p>服务器: <code>{proxyIP}</code></p>
        <p>端口: <code>{proxyPort}</code></p>
      </div>
    </div>
  );
};
```

## 七、数据流设计

### 7.1 请求数据统一模型

```python
# models/unified_request.py
from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime

class RequestSource(Enum):
    WEB_BROWSER = "web_browser"      # 网页录制
    DESKTOP_APP = "desktop_app"      # 桌面应用
    MOBILE_IOS = "mobile_ios"        # iOS设备
    MOBILE_ANDROID = "mobile_android" # Android设备

@dataclass
class UnifiedRequest:
    """统一请求记录模型"""
    id: str
    source: RequestSource
    device_info: Optional[str]  # 设备信息

    # 请求信息
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    timestamp: float

    # 响应信息
    status_code: Optional[int]
    response_headers: Optional[Dict[str, str]]
    response_body: Optional[str]
    response_size: Optional[int]
    response_time: Optional[float]  # 响应时间(ms)

    # 元数据
    content_type: Optional[str]
    is_https: bool
    host: str
    path: str
    tags: list = None  # 用户标签

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source.value,
            "device_info": self.device_info,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_size": self.response_size,
            "response_time": self.response_time,
            "content_type": self.content_type,
            "is_https": self.is_https,
            "host": self.host,
            "path": self.path,
            "tags": self.tags or []
        }
```

### 7.2 实时数据推送

```python
# app/websocket/proxy_events.py
from fastapi import WebSocket
from typing import Set
import json
import asyncio

class ProxyEventBroadcaster:
    """代理事件广播器 - 实时推送请求到前端"""

    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._queue = asyncio.Queue()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self._connections.discard(websocket)

    async def broadcast_request(self, request_data: dict):
        """广播新请求"""
        message = json.dumps({
            "type": "new_request",
            "data": request_data
        })

        dead_connections = set()
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except:
                dead_connections.add(ws)

        self._connections -= dead_connections

    async def broadcast_status(self, status: dict):
        """广播代理状态变化"""
        message = json.dumps({
            "type": "proxy_status",
            "data": status
        })

        for ws in self._connections.copy():
            try:
                await ws.send_text(message)
            except:
                self._connections.discard(ws)

# 全局广播器实例
proxy_broadcaster = ProxyEventBroadcaster()
```

## 八、实现步骤规划

### 8.1 第一阶段：核心代理服务 (优先级: 高)

| 步骤 | 任务 | 依赖 |
|------|------|------|
| 1 | 安装mitmproxy依赖 | 无 |
| 2 | 实现ProxyServer基础类 | 步骤1 |
| 3 | 实现RequestInterceptor | 步骤2 |
| 4 | 集成到现有FastAPI应用 | 步骤3 |
| 5 | 添加代理API路由 | 步骤4 |

### 8.2 第二阶段：Windows桌面应用支持 (优先级: 高)

| 步骤 | 任务 | 依赖 |
|------|------|------|
| 1 | 实现WindowsSystemProxy类 | 第一阶段 |
| 2 | 实现CA证书自动安装 | 第一阶段 |
| 3 | 添加系统代理开关API | 步骤1,2 |
| 4 | 前端添加桌面应用录制选项 | 步骤3 |

### 8.3 第三阶段：移动端支持 (优先级: 中)

| 步骤 | 任务 | 依赖 |
|------|------|------|
| 1 | 实现CertManager类 | 第一阶段 |
| 2 | 添加证书下载API | 步骤1 |
| 3 | 实现二维码生成 | 步骤2 |
| 4 | 前端添加移动端配置向导 | 步骤3 |
| 5 | 添加设备识别功能 | 步骤4 |

### 8.4 第四阶段：数据整合与优化 (优先级: 中)

| 步骤 | 任务 | 依赖 |
|------|------|------|
| 1 | 统一请求数据模型 | 第一阶段 |
| 2 | 实现WebSocket实时推送 | 步骤1 |
| 3 | 整合到现有请求列表界面 | 步骤2 |
| 4 | 添加来源过滤功能 | 步骤3 |
| 5 | 导出功能支持多来源 | 步骤4 |

## 九、依赖清单

### 9.1 Python依赖

```txt
# requirements.txt 新增
mitmproxy>=10.0.0      # 核心代理引擎
qrcode[pil]>=7.4       # 二维码生成
pywin32>=306           # Windows API (仅Windows)
```

### 9.2 前端依赖

```json
{
  "dependencies": {
    "qrcode.react": "^3.1.0"
  }
}
```

## 十、注意事项与风险

### 10.1 安全注意事项

| 风险 | 说明 | 缓解措施 |
|------|------|----------|
| CA证书泄露 | 私钥泄露可导致中间人攻击 | 证书仅存储在本地，不上传 |
| 敏感数据捕获 | 可能捕获密码等敏感信息 | 提供敏感字段自动脱敏选项 |
| 系统代理残留 | 程序异常退出后代理未恢复 | 添加异常处理和清理机制 |

### 10.2 兼容性注意事项

**Windows桌面应用**
- 部分应用使用自己的证书存储，不信任系统证书
- 某些应用实现了证书固定(Certificate Pinning)
- UWP应用可能不走系统代理

**移动端**
- Android 7.0+ 应用默认不信任用户安装的CA证书
- iOS需要手动信任证书
- 部分应用实现了SSL Pinning

### 10.3 解决方案

```python
# 针对不走系统代理的应用，可以使用Proxifier等工具强制代理
# 或者使用更底层的WinDivert方案

# 针对SSL Pinning的应用：
# 1. Android: 使用Frida脚本绕过 (需要root)
# 2. iOS: 使用SSL Kill Switch (需要越狱)
# 3. 或者使用应用的调试版本
```

## 十一、类似工具参考

| 工具 | 平台 | 特点 | 开源 |
|------|------|------|------|
| Charles | 跨平台 | 功能全面，UI友好 | 否 |
| Fiddler | Windows | 功能强大，插件丰富 | 否 |
| mitmproxy | 跨平台 | 命令行，可编程 | 是 |
| Proxyman | macOS/iOS | 原生体验好 | 否 |
| HTTP Toolkit | 跨平台 | 现代UI，自动配置 | 部分 |

## 十二、总结

本方案采用 **mitmproxy** 作为核心代理引擎，通过以下方式实现多平台请求录制：

1. **Windows桌面应用**: 自动设置系统代理 + 安装CA证书
2. **移动端(iOS/Android)**: 手动配置WiFi代理 + 安装CA证书
3. **统一管理**: 所有请求汇总到同一界面，支持按来源过滤

**优势**:
- 技术栈统一(Python)，与现有项目无缝集成
- 开源免费，无授权问题
- 功能完善，社区活跃
- 实现复杂度适中，可快速落地

**预计工作量**:
- 第一阶段(核心代理): 基础功能
- 第二阶段(桌面支持): Windows集成
- 第三阶段(移动端): 证书管理和配置向导
- 第四阶段(优化): 数据整合和UI完善

---

*文档版本: 1.0*
*创建日期: 2025-01-17*
*作者: AI Assistant*

