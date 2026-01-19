# 多平台网络请求录制系统 - 任务清单

> 基于设计文档 `multi_platform_capture_design.md` 生成
> 创建日期: 2025-01-17

---

## m1 核心代理服务模块

### m1.1 环境准备与依赖安装

- [ ] 在 `requirements.txt` 中添加 `mitmproxy>=10.0.0` 依赖
  - 说明: mitmproxy 是核心代理引擎，支持HTTP/HTTPS/WebSocket协议拦截
  - 验收标准: `pip install mitmproxy` 成功执行，版本>=10.0.0

- [ ] 在 `requirements.txt` 中添加 `qrcode[pil]>=7.4` 依赖
  - 说明: 用于生成移动端证书下载二维码
  - 验收标准: 能够成功导入 `qrcode` 模块并生成二维码图片

- [ ] 在 `requirements.txt` 中添加 `pywin32>=306` 依赖（仅Windows平台）
  - 说明: 用于操作Windows注册表设置系统代理
  - 验收标准: 能够成功导入 `winreg` 和 `ctypes` 模块

- [ ] 在前端 `package.json` 中添加 `qrcode.react: ^3.1.0` 依赖
  - 说明: React组件形式的二维码生成库
  - 验收标准: `npm install` 成功，组件可正常渲染

### m1.2 后端目录结构创建

- [ ] 创建 `backend/proxy/` 目录
  - 说明: 代理服务核心模块的根目录

- [ ] 创建 `backend/proxy/__init__.py` 文件
  - 说明: Python包初始化文件，导出主要类和函数

- [ ] 创建 `backend/proxy/proxy_server.py` 文件骨架
  - 说明: 代理服务器主类文件
  - 内容: 包含 `ProxyServer` 类的基础结构定义

- [ ] 创建 `backend/proxy/request_handler.py` 文件骨架
  - 说明: 请求处理器文件
  - 内容: 包含 `RequestInterceptor` 类的基础结构定义

- [ ] 创建 `backend/proxy/cert_manager.py` 文件骨架
  - 说明: CA证书管理文件
  - 内容: 包含 `CertManager` 类的基础结构定义

- [ ] 创建 `backend/proxy/system_proxy.py` 文件骨架
  - 说明: Windows系统代理设置文件
  - 内容: 包含 `WindowsSystemProxy` 类的基础结构定义

- [ ] 创建 `backend/proxy/filters.py` 文件骨架
  - 说明: 请求过滤规则文件
  - 内容: 包含过滤规则相关类和函数定义

### m1.3 ProxyServer 核心类实现

- [ ] 实现 `ProxyServer.__init__()` 方法
  - 参数: `host: str = "0.0.0.0"`, `port: int = 8888`, `on_request: Optional[Callable] = None`, `on_response: Optional[Callable] = None`
  - 说明: 初始化代理服务器配置，设置监听地址、端口和回调函数
  - 验收标准: 实例化时能正确保存配置参数

- [ ] 实现 `ProxyServer.start()` 方法
  - 说明: 启动代理服务器
  - 功能点:
    1. 创建 `mitmproxy.options.Options` 对象，配置 `listen_host`、`listen_port`、`ssl_insecure=True`
    2. 创建 `mitmproxy.tools.dump.DumpMaster` 实例
    3. 添加 `RequestInterceptor` 插件到 addons
    4. 在独立线程中运行代理服务
  - 验收标准: 调用后代理服务在指定端口监听

- [ ] 实现 `ProxyServer._run()` 私有方法
  - 说明: 在独立线程中运行事件循环
  - 功能点:
    1. 创建新的 asyncio 事件循环
    2. 调用 `self._master.run()` 启动服务
  - 验收标准: 代理服务能在后台线程稳定运行

- [ ] 实现 `ProxyServer.stop()` 方法
  - 说明: 停止代理服务器
  - 功能点:
    1. 调用 `self._master.shutdown()` 关闭服务
    2. 设置 `self._running = False`
  - 验收标准: 调用后代理服务完全停止，端口释放

- [ ] 实现 `ProxyServer.is_running` 属性
  - 说明: 返回代理服务器运行状态
  - 验收标准: 返回正确的布尔值

### m1.4 RequestInterceptor 请求拦截器实现

- [ ] 实现 `RequestInterceptor.__init__()` 方法
  - 参数: `on_request: Callable`, `on_response: Callable`
  - 说明: 初始化拦截器，保存回调函数引用

- [ ] 实现 `RequestInterceptor.request()` 方法
  - 参数: `flow: mitmproxy.http.HTTPFlow`
  - 说明: 拦截HTTP请求
  - 功能点:
    1. 从 flow.request 提取: method, pretty_url, headers, body(get_text), timestamp_start
    2. 构造请求数据字典
    3. 调用 `self.on_request` 回调传递数据
  - 验收标准: 每个经过代理的请求都能触发回调

- [ ] 实现 `RequestInterceptor.response()` 方法
  - 参数: `flow: mitmproxy.http.HTTPFlow`
  - 说明: 拦截HTTP响应
  - 功能点:
    1. 从 flow.response 提取: status_code, headers, body(限制10000字符), content长度, timestamp_end
    2. 同时提取请求URL用于关联
    3. 构造响应数据字典
    4. 调用 `self.on_response` 回调传递数据
  - 验收标准: 每个响应都能触发回调，大响应体被正确截断

### m1.5 代理服务与FastAPI集成

- [ ] 在 `backend/app/api/v1/` 目录下创建 `proxy.py` 路由文件
  - 说明: 代理服务的API路由定义

- [ ] 定义 `ProxyConfig` Pydantic模型
  - 字段: `host: str = "0.0.0.0"`, `port: int = 8888`, `enable_system_proxy: bool = False`, `filter_hosts: List[str] = []`
  - 说明: 代理服务配置模型，用于API请求验证

- [ ] 定义 `ProxyStatus` Pydantic模型
  - 字段: `running: bool`, `host: str`, `port: int`, `system_proxy_enabled: bool`, `connected_clients: int`, `total_requests: int`
  - 说明: 代理服务状态响应模型

- [ ] 实现 `POST /api/v1/proxy/start` 接口
  - 参数: `ProxyConfig`
  - 说明: 启动代理服务器
  - 功能点:
    1. 验证端口是否被占用
    2. 创建 ProxyServer 实例
    3. 设置请求/响应回调函数（保存到数据库、推送WebSocket）
    4. 调用 start() 方法启动服务
    5. 如果 enable_system_proxy=True，调用系统代理设置
  - 验收标准: 返回200状态码，代理服务成功启动

- [ ] 实现 `POST /api/v1/proxy/stop` 接口
  - 说明: 停止代理服务器
  - 功能点:
    1. 调用 ProxyServer.stop() 停止服务
    2. 如果启用了系统代理，恢复原始代理设置
    3. 清理资源
  - 验收标准: 返回200状态码，代理服务完全停止

- [ ] 实现 `GET /api/v1/proxy/status` 接口
  - 返回: `ProxyStatus`
  - 说明: 获取代理服务器当前状态
  - 功能点:
    1. 检查代理服务是否运行
    2. 获取配置信息（host、port）
    3. 获取系统代理状态
    4. 统计连接客户端数和总请求数
  - 验收标准: 返回准确的状态信息

- [ ] 实现 `GET /api/v1/proxy/local-ip` 接口
  - 说明: 获取本机局域网IP地址（供移动端配置使用）
  - 功能点:
    1. 使用 socket 连接外部地址获取本机IP
    2. 返回 {"ip": "192.168.x.x"} 格式
  - 验收标准: 返回正确的局域网IP地址

- [ ] 将 proxy 路由注册到主应用
  - 位置: `backend/app/main.py`
  - 说明: 在 FastAPI app 中包含 proxy 路由

### m1.6 全局代理服务管理器

- [ ] 创建 `ProxyServiceManager` 单例类
  - 位置: `backend/proxy/service_manager.py`
  - 说明: 管理代理服务实例，确保只有一个代理服务运行
  - 功能点:
    1. 单例模式实现
    2. 维护当前运行的 ProxyServer 实例
    3. 提供 get_instance() 方法获取当前实例
    4. 提供 is_running() 方法检查运行状态
    5. 防止重复启动
  - 验收标准: 无法同时启动多个代理服务

- [ ] 实现 `ProxyServiceManager.start_service()` 方法
  - 说明: 启动代理服务
  - 功能点:
    1. 检查是否已有实例运行
    2. 如果已运行，返回错误或停止旧实例
    3. 创建新的 ProxyServer 实例
    4. 保存实例引用
  - 验收标准: 启动前自动检查并处理已有实例

- [ ] 实现 `ProxyServiceManager.stop_service()` 方法
  - 说明: 停止代理服务
  - 功能点:
    1. 调用当前实例的 stop() 方法
    2. 清理实例引用
    3. 恢复系统代理设置
  - 验收标准: 服务完全停止，资源释放

- [ ] 在 API 中使用 ProxyServiceManager
  - 说明: 所有代理相关API都通过管理器操作
  - 验收标准: API调用统一通过管理器

### m1.7 请求统计功能

- [ ] 创建 `RequestStatistics` 类
  - 位置: `backend/proxy/statistics.py`
  - 说明: 统计请求相关数据
  - 功能点:
    1. 统计总请求数
    2. 统计成功/失败请求数
    3. 统计总流量大小（上传/下载）
    4. 统计平均响应时间
    5. 按来源统计（浏览器/桌面/移动端）
    6. 按域名统计
  - 验收标准: 提供完整的统计数据

- [ ] 实现 `RequestStatistics.record_request()` 方法
  - 参数: `request_data: dict`
  - 说明: 记录单个请求的统计信息
  - 验收标准: 统计数据实时更新

- [ ] 实现 `RequestStatistics.get_summary()` 方法
  - 返回: `dict` 包含所有统计数据
  - 说明: 获取统计摘要
  - 验收标准: 返回完整的统计报告

- [ ] 实现 `GET /api/v1/proxy/statistics` 接口
  - 说明: 获取请求统计数据
  - 功能点:
    1. 调用 RequestStatistics.get_summary()
    2. 支持按时间范围查询
    3. 支持按来源过滤
  - 验收标准: 返回详细的统计数据

- [ ] 在 RequestInterceptor 中集成统计
  - 说明: 每个请求都记录到统计中
  - 验收标准: 统计数据准确

### m1.8 错误处理和重试机制

- [ ] 实现代理启动失败重试逻辑
  - 位置: `ProxyServer.start()` 方法
  - 说明: 启动失败时自动重试
  - 功能点:
    1. 端口被占用时自动尝试下一个端口
    2. 最多重试3次
    3. 记录重试日志
    4. 返回详细的错误信息
  - 验收标准: 端口冲突时自动切换端口

- [ ] 实现 RequestInterceptor 异常处理
  - 说明: 处理请求/响应拦截过程中的异常
  - 功能点:
    1. 捕获所有异常
    2. 记录错误日志
    3. 不影响代理服务继续运行
    4. 统计错误次数
  - 验收标准: 单个请求异常不影响整体服务

- [ ] 实现 WebSocket 重连机制
  - 位置: 前端 WebSocket 连接代码
  - 说明: 连接断开时自动重连
  - 功能点:
    1. 检测连接断开
    2. 指数退避重连（1s, 2s, 4s, 8s...）
    3. 最多重连10次
    4. 显示连接状态
  - 验收标准: 网络波动时自动恢复连接

---

## m2 Windows桌面应用支持模块

### m2.1 WindowsSystemProxy 类实现

- [ ] 实现 `WindowsSystemProxy.__init__()` 方法
  - 说明: 初始化系统代理管理器
  - 功能点: 定义注册表路径常量 `INTERNET_SETTINGS`

- [ ] 实现 `WindowsSystemProxy.get_current_settings()` 方法
  - 返回: `dict` 包含 `enabled: bool`, `host: str`, `port: int`
  - 说明: 读取当前系统代理设置
  - 功能点:
    1. 打开注册表键 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
    2. 读取 `ProxyEnable` 值（DWORD）
    3. 读取 `ProxyServer` 值（字符串）
    4. 解析 host:port 格式
  - 验收标准: 返回当前系统代理配置

- [ ] 实现 `WindowsSystemProxy.enable_proxy()` 方法
  - 参数: `host: str = "127.0.0.1"`, `port: int = 8888`
  - 说明: 启用系统代理
  - 功能点:
    1. 保存当前代理设置到 `self._original_settings`
    2. 设置 `ProxyEnable = 1`
    3. 设置 `ProxyServer = "host:port"`
    4. 设置 `ProxyOverride` 排除本地地址（localhost、127.*、192.168.*等）
    5. 调用 `_refresh_settings()` 通知系统
  - 验收标准: 系统代理设置生效，浏览器流量经过代理

- [ ] 实现 `WindowsSystemProxy.disable_proxy()` 方法
  - 说明: 禁用系统代理
  - 功能点:
    1. 设置 `ProxyEnable = 0`
    2. 调用 `_refresh_settings()` 通知系统
  - 验收标准: 系统代理被禁用

- [ ] 实现 `WindowsSystemProxy.restore_original()` 方法
  - 说明: 恢复原始代理设置
  - 功能点:
    1. 检查 `self._original_settings` 是否存在
    2. 根据原始设置调用 enable_proxy 或 disable_proxy
  - 验收标准: 系统代理恢复到启动前的状态

- [ ] 实现 `WindowsSystemProxy._refresh_settings()` 私有方法
  - 说明: 刷新系统网络设置
  - 功能点:
    1. 使用 ctypes 调用 `Wininet.InternetSetOptionW`
    2. 发送 `INTERNET_OPTION_SETTINGS_CHANGED` (39)
    3. 发送 `INTERNET_OPTION_REFRESH` (37)
  - 验收标准: 系统立即应用代理设置变更

### m2.2 系统代理API集成

- [ ] 在 `POST /api/v1/proxy/start` 中集成系统代理设置
  - 说明: 当 `enable_system_proxy=True` 时自动设置系统代理
  - 功能点:
    1. 创建 WindowsSystemProxy 实例
    2. 调用 enable_proxy() 方法
    3. 处理可能的权限错误
  - 验收标准: 代理启动时系统代理自动配置

- [ ] 在 `POST /api/v1/proxy/stop` 中集成系统代理恢复
  - 说明: 停止代理时恢复原始系统代理设置
  - 功能点:
    1. 调用 WindowsSystemProxy.restore_original()
    2. 确保即使代理异常退出也能恢复
  - 验收标准: 代理停止后系统代理恢复原状

- [ ] 添加异常处理和清理机制
  - 说明: 确保程序异常退出时系统代理不残留
  - 功能点:
    1. 使用 atexit 注册清理函数
    2. 捕获 KeyboardInterrupt 等异常
    3. 在清理函数中恢复系统代理
  - 验收标准: 任何情况下退出都能恢复系统代理

### m2.3 Windows防火墙自动配置

- [ ] 实现 `WindowsFirewall` 类
  - 位置: `backend/proxy/windows_firewall.py`
  - 说明: 管理Windows防火墙规则，允许移动端连接
  - 功能点:
    1. 检查防火墙规则是否存在
    2. 添加防火墙规则允许代理端口
    3. 删除防火墙规则
  - 验收标准: 类实现完成

- [ ] 实现 `WindowsFirewall.check_rule_exists()` 方法
  - 参数: `rule_name: str`
  - 返回: `bool`
  - 说明: 检查指定名称的防火墙规则是否存在
  - 功能点:
    1. 使用 netsh 命令查询规则
    2. 命令: `netsh advfirewall firewall show rule name="规则名"`
    3. 解析命令输出判断规则是否存在
  - 验收标准: 正确返回规则存在状态

- [ ] 实现 `WindowsFirewall.add_rule()` 方法
  - 参数: `port: int`, `rule_name: str = "WebAnalyzer Proxy"`
  - 返回: `bool`
  - 说明: 添加防火墙规则允许指定端口的入站连接
  - 功能点:
    1. 检查规则是否已存在，存在则跳过
    2. 使用 netsh 命令添加规则
    3. 命令: `netsh advfirewall firewall add rule name="规则名" dir=in action=allow protocol=TCP localport=端口`
    4. 处理权限不足等错误
    5. 记录操作日志
  - 验收标准: 防火墙规则成功添加，移动端可以连接

- [ ] 实现 `WindowsFirewall.remove_rule()` 方法
  - 参数: `rule_name: str = "WebAnalyzer Proxy"`
  - 返回: `bool`
  - 说明: 删除指定的防火墙规则
  - 功能点:
    1. 检查规则是否存在
    2. 使用 netsh 命令删除规则
    3. 命令: `netsh advfirewall firewall delete rule name="规则名"`
    4. 处理可能的错误
  - 验收标准: 防火墙规则成功删除

- [ ] 在代理启动时自动配置防火墙
  - 位置: `ProxyServiceManager.start_service()` 方法
  - 说明: 启动代理时自动添加防火墙规则
  - 功能点:
    1. 创建 WindowsFirewall 实例
    2. 调用 add_rule() 添加规则
    3. 如果添加失败，提示用户手动配置
    4. 保存规则名称以便后续删除
  - 验收标准: 代理启动时防火墙自动配置

- [ ] 在代理停止时自动清理防火墙规则
  - 位置: `ProxyServiceManager.stop_service()` 方法
  - 说明: 停止代理时删除防火墙规则
  - 功能点:
    1. 调用 WindowsFirewall.remove_rule()
    2. 确保即使代理异常退出也能清理
    3. 使用 atexit 注册清理函数
  - 验收标准: 代理停止后防火墙规则被清理

- [ ] 添加防火墙状态检查接口
  - 说明: 实现 `GET /api/v1/proxy/firewall-status` 接口
  - 功能点:
    1. 检查防火墙规则是否存在
    2. 返回防火墙状态信息
    3. 返回格式: `{"rule_exists": bool, "rule_name": str, "port": int}`
  - 验收标准: 接口返回准确的防火墙状态

- [ ] 前端显示防火墙状态
  - 位置: `ProxyControl.tsx` 组件
  - 说明: 在控制面板显示防火墙配置状态
  - 功能点:
    1. 显示防火墙规则是否已配置
    2. 如果未配置，显示警告提示
    3. 提供手动配置指南链接
  - 验收标准: 用户可以看到防火墙状态

---

## m3 CA证书管理模块

### m3.1 CertManager 类实现

- [ ] 实现 `CertManager.__init__()` 方法
  - 参数: `cert_dir: str = None`（默认 `~/.mitmproxy`）
  - 说明: 初始化证书管理器
  - 功能点:
    1. 设置证书目录路径
    2. 定义 CA 证书文件路径（.pem 和 .cer）

- [ ] 实现 `CertManager.ensure_ca_exists()` 方法
  - 返回: `bool`
  - 说明: 确保CA证书存在
  - 功能点:
    1. 检查证书文件是否存在
    2. 不存在则创建目录（mitmproxy会自动生成证书）
  - 验收标准: 证书目录存在，首次运行后生成证书

- [ ] 实现 `CertManager.get_cert_path()` 方法
  - 返回: `str`
  - 说明: 获取CA证书文件路径
  - 验收标准: 返回正确的证书文件绝对路径

- [ ] 实现 `CertManager.get_cert_for_mobile()` 方法
  - 返回: `dict` 包含 `path`, `content_base64`, `filename`
  - 说明: 获取移动端安装所需的证书信息
  - 功能点:
    1. 读取证书文件内容
    2. Base64编码证书内容
    3. 返回证书路径、编码内容和文件名
  - 验收标准: 返回可用于下载的证书数据

- [ ] 实现 `CertManager.generate_qr_code()` 方法
  - 参数: `download_url: str`
  - 返回: `str` (Base64编码的PNG图片)
  - 说明: 生成证书下载页面的二维码
  - 功能点:
    1. 使用 qrcode 库生成二维码
    2. 将图片保存到 BytesIO
    3. Base64编码返回
  - 验收标准: 返回可直接在HTML中显示的二维码图片

- [ ] 实现 `CertManager.install_cert_windows()` 方法
  - 返回: `bool`
  - 说明: 在Windows系统中安装CA证书到受信任的根证书
  - 功能点:
    1. 使用 certutil 命令安装证书
    2. 命令: `certutil -addstore -user Root <cert_path>`
    3. 捕获并处理错误
  - 验收标准: 证书成功安装到Windows受信任根证书存储

- [ ] 实现 `CertManager.uninstall_cert_windows()` 方法
  - 返回: `bool`
  - 说明: 从Windows系统中移除CA证书
  - 功能点:
    1. 使用 certutil 命令删除证书
    2. 命令: `certutil -delstore -user Root mitmproxy`
  - 验收标准: 证书从系统中完全移除

- [ ] 实现 `CertManager.get_mobile_install_instructions()` 方法
  - 参数: `server_ip: str`, `port: int`
  - 返回: `dict` 包含 iOS 和 Android 的安装步骤
  - 说明: 获取移动端证书安装说明
  - 功能点:
    1. 返回 iOS 详细安装步骤（6步）
    2. 返回 Android 详细安装步骤（6步）
    3. 包含特殊注意事项（如Android 7.0+限制）
  - 验收标准: 返回完整的分步安装指南

### m3.2 证书相关API实现

- [ ] 实现 `GET /api/v1/proxy/cert/download` 接口
  - 说明: 下载CA证书文件
  - 功能点:
    1. 调用 CertManager.get_cert_for_mobile()
    2. 返回证书文件作为下载响应
    3. 设置正确的 Content-Type 和 Content-Disposition
  - 验收标准: 浏览器访问时自动下载证书文件

- [ ] 实现 `GET /api/v1/proxy/cert/instructions` 接口
  - 说明: 获取各平台证书安装说明
  - 功能点:
    1. 获取当前代理服务器IP和端口
    2. 调用 CertManager.get_mobile_install_instructions()
    3. 返回 JSON 格式的安装步骤
  - 验收标准: 返回iOS和Android的详细安装指南

- [ ] 实现 `GET /api/v1/proxy/cert/qrcode` 接口
  - 说明: 生成证书下载页面的二维码
  - 功能点:
    1. 构造证书下载URL（http://mitm.it 或自定义页面）
    2. 调用 CertManager.generate_qr_code()
    3. 返回 Base64 编码的二维码图片
  - 验收标准: 返回可直接显示的二维码图片数据

- [ ] 实现 `POST /api/v1/proxy/cert/install-windows` 接口
  - 说明: 在Windows系统中安装CA证书
  - 功能点:
    1. 调用 CertManager.install_cert_windows()
    2. 返回安装结果
    3. 处理权限不足等错误
  - 验收标准: 证书成功安装或返回明确错误信息

- [ ] 实现 `POST /api/v1/proxy/cert/uninstall-windows` 接口
  - 说明: 从Windows系统中卸载CA证书
  - 功能点:
    1. 调用 CertManager.uninstall_cert_windows()
    2. 返回卸载结果
  - 验收标准: 证书成功卸载

### m3.3 证书管理增强

- [ ] 实现证书过期检查
  - 位置: `CertManager` 类
  - 说明: 检查证书是否过期
  - 功能点:
    1. 读取证书有效期
    2. 检查是否即将过期（30天内）
    3. 返回过期状态
  - 验收标准: 可以检测证书过期

- [ ] 实现证书更新功能
  - 说明: 重新生成证书
  - 功能点:
    1. 删除旧证书
    2. 生成新证书
    3. 重新安装到系统
  - 验收标准: 证书成功更新

- [ ] 添加证书过期提醒
  - 说明: 证书即将过期时提醒用户
  - 功能点:
    1. 启动时检查证书
    2. 过期前30天开始提醒
    3. 前端显示提醒消息
  - 验收标准: 用户收到过期提醒

---

## m4 移动端支持模块

### m4.1 设备识别功能

- [ ] 实现设备信息提取函数
  - 位置: `backend/proxy/device_detector.py`
  - 说明: 从请求头中识别设备类型和信息
  - 功能点:
    1. 解析 User-Agent 识别 iOS/Android
    2. 提取设备型号、系统版本
    3. 识别应用名称（如果有）
  - 验收标准: 能准确识别主流移动设备

- [ ] 在 RequestInterceptor 中集成设备识别
  - 说明: 请求拦截时自动识别设备
  - 功能点:
    1. 调用设备识别函数
    2. 将设备信息添加到请求数据中
  - 验收标准: 每个请求都包含设备信息

- [ ] 实现 `GET /api/v1/proxy/devices` 接口
  - 说明: 获取当前连接的设备列表
  - 功能点:
    1. 维护活跃设备列表
    2. 记录设备首次连接时间
    3. 统计每个设备的请求数
  - 验收标准: 返回所有连接设备的详细信息

### m4.2 移动端配置页面

- [ ] 创建证书下载静态页面
  - 位置: `backend/static/mobile-setup.html`
  - 说明: 移动端访问的证书下载和配置指南页面
  - 功能点:
    1. 自动检测设备类型（iOS/Android）
    2. 显示对应平台的安装步骤
    3. 提供证书下载按钮
    4. 显示代理配置信息
  - 验收标准: 移动端浏览器访问体验良好

- [ ] 实现 `GET /api/v1/proxy/mobile-setup` 接口
  - 说明: 返回移动端配置页面
  - 功能点:
    1. 渲染 mobile-setup.html 模板
    2. 注入当前服务器IP和端口
  - 验收标准: 手机浏览器访问显示配置页面

---

## m5 请求过滤模块

### m5.1 过滤规则数据模型

- [ ] 定义 `FilterRule` Pydantic模型
  - 字段: `id: str`, `name: str`, `type: str` (include/exclude), `pattern: str`, `enabled: bool = True`
  - 说明: 请求过滤规则的数据模型

- [ ] 创建 `backend/proxy/filters.py` 文件
  - 说明: 实现请求过滤逻辑

### m5.2 过滤器实现

- [ ] 实现 `RequestFilter` 类
  - 说明: 请求过滤器核心类
  - 功能点:
    1. 加载和管理过滤规则
    2. 支持正则表达式匹配
    3. 支持通配符匹配
    4. 支持域名、路径、方法过滤

- [ ] 实现 `RequestFilter.should_capture()` 方法
  - 参数: `url: str`, `method: str`
  - 返回: `bool`
  - 说明: 判断请求是否应该被捕获
  - 功能点:
    1. 遍历所有启用的规则
    2. 先处理 exclude 规则（黑名单）
    3. 再处理 include 规则（白名单）
    4. 默认捕获所有请求
  - 验收标准: 正确应用过滤规则

- [ ] 在 RequestInterceptor 中集成过滤器
  - 说明: 请求拦截前先过滤
  - 功能点:
    1. 创建 RequestFilter 实例
    2. 在 request() 方法中调用 should_capture()
    3. 不符合规则的请求直接跳过
  - 验收标准: 过滤规则生效

### m5.3 过滤规则API实现

- [ ] 创建 `backend/app/api/v1/filters.py` 路由文件
  - 说明: 过滤规则管理API

- [ ] 实现 `GET /api/v1/filters/rules` 接口
  - 返回: `List[FilterRule]`
  - 说明: 获取所有过滤规则
  - 验收标准: 返回完整的规则列表

- [ ] 实现 `POST /api/v1/filters/rules` 接口
  - 参数: `FilterRule`
  - 说明: 添加新的过滤规则
  - 功能点:
    1. 验证规则格式
    2. 生成唯一ID
    3. 保存到数据库或配置文件
  - 验收标准: 规则成功添加并立即生效

- [ ] 实现 `PUT /api/v1/filters/rules/{rule_id}` 接口
  - 参数: `rule_id: str`, `FilterRule`
  - 说明: 更新现有过滤规则
  - 验收标准: 规则更新成功

- [ ] 实现 `DELETE /api/v1/filters/rules/{rule_id}` 接口
  - 参数: `rule_id: str`
  - 说明: 删除过滤规则
  - 验收标准: 规则删除成功

- [ ] 将 filters 路由注册到主应用
  - 位置: `backend/app/main.py`

### m5.4 过滤规则持久化

- [ ] 创建过滤规则数据库表
  - 位置: `backend/app/models/filter_rule.py`
  - 说明: 存储过滤规则
  - 字段: `id`, `name`, `type`, `pattern`, `enabled`, `created_at`, `updated_at`
  - 验收标准: 表结构创建成功

- [ ] 实现过滤规则 CRUD 操作
  - 位置: `backend/app/services/filter_service.py`
  - 说明: 过滤规则的增删改查
  - 功能点:
    1. create_rule() - 创建规则
    2. update_rule() - 更新规则
    3. delete_rule() - 删除规则
    4. get_rules() - 获取所有规则
    5. get_enabled_rules() - 获取启用的规则
  - 验收标准: 规则持久化到数据库

- [ ] 实现规则加载和缓存
  - 说明: 启动时加载规则到内存
  - 功能点:
    1. 从数据库加载所有启用的规则
    2. 缓存到 RequestFilter 实例
    3. 规则变更时刷新缓存
  - 验收标准: 规则修改后立即生效

---

## m6 数据统一管理模块

### m6.1 统一请求数据模型

- [ ] 创建 `backend/models/unified_request.py` 文件
  - 说明: 统一的请求数据模型

- [ ] 定义 `RequestSource` 枚举
  - 值: `WEB_BROWSER`, `DESKTOP_APP`, `MOBILE_IOS`, `MOBILE_ANDROID`
  - 说明: 请求来源类型

- [ ] 定义 `UnifiedRequest` 数据类
  - 字段:
    - 基础: `id`, `source`, `device_info`
    - 请求: `method`, `url`, `headers`, `body`, `timestamp`
    - 响应: `status_code`, `response_headers`, `response_body`, `response_size`, `response_time`
    - 元数据: `content_type`, `is_https`, `host`, `path`, `tags`
  - 说明: 统一的请求记录模型，兼容所有来源

- [ ] 实现 `UnifiedRequest.to_dict()` 方法
  - 说明: 转换为字典格式用于序列化
  - 验收标准: 返回完整的字典表示

- [ ] 实现 `UnifiedRequest.from_proxy_request()` 静态方法
  - 说明: 从代理请求数据创建 UnifiedRequest
  - 功能点:
    1. 提取请求和响应信息
    2. 识别来源类型
    3. 解析设备信息
  - 验收标准: 正确转换代理数据

### m6.2 数据存储层

- [ ] 扩展现有数据库模型支持多来源
  - 位置: `backend/app/models/` 或使用现有模型
  - 说明: 添加 source 和 device_info 字段

- [ ] 实现请求保存函数
  - 位置: `backend/app/services/request_storage.py`
  - 说明: 保存统一格式的请求到数据库
  - 功能点:
    1. 接收 UnifiedRequest 对象
    2. 保存到数据库
    3. 返回保存的记录ID
  - 验收标准: 请求成功保存

- [ ] 实现请求查询函数
  - 说明: 支持按来源、设备、时间范围查询
  - 功能点:
    1. 支持多条件过滤
    2. 支持分页
    3. 支持排序
  - 验收标准: 查询结果准确

### m6.3 WebSocket实时推送

- [ ] 创建 `backend/app/websocket/proxy_events.py` 文件
  - 说明: WebSocket事件广播器

- [ ] 实现 `ProxyEventBroadcaster` 类
  - 说明: 管理WebSocket连接和消息广播
  - 功能点:
    1. 维护活跃连接集合
    2. 处理连接和断开
    3. 广播消息到所有客户端

- [ ] 实现 `ProxyEventBroadcaster.connect()` 方法
  - 参数: `websocket: WebSocket`
  - 说明: 接受新的WebSocket连接
  - 验收标准: 连接成功添加到集合

- [ ] 实现 `ProxyEventBroadcaster.disconnect()` 方法
  - 参数: `websocket: WebSocket`
  - 说明: 移除断开的连接
  - 验收标准: 连接从集合中移除

- [ ] 实现 `ProxyEventBroadcaster.broadcast_request()` 方法
  - 参数: `request_data: dict`
  - 说明: 广播新请求到所有连接的客户端
  - 功能点:
    1. 构造消息格式 `{"type": "new_request", "data": ...}`
    2. 发送到所有活跃连接
    3. 处理发送失败的连接
  - 验收标准: 消息成功广播

- [ ] 实现 `ProxyEventBroadcaster.broadcast_status()` 方法
  - 参数: `status: dict`
  - 说明: 广播代理状态变化
  - 验收标准: 状态更新实时推送

- [ ] 添加 WebSocket 路由
  - 位置: `backend/app/api/v1/websocket.py`
  - 路径: `/ws/proxy-events`
  - 说明: WebSocket连接端点

- [ ] 在代理请求回调中集成WebSocket推送
  - 说明: 捕获到请求时实时推送到前端
  - 验收标准: 前端实时收到请求数据

### m6.4 导出功能支持多来源

- [ ] 实现 `GET /api/v1/requests/export` 接口
  - 说明: 导出请求数据
  - 功能点:
    1. 支持导出为 JSON 格式
    2. 支持导出为 HAR 格式
    3. 支持导出为 CSV 格式
    4. 支持按来源过滤导出
    5. 支持按时间范围过滤
    6. 支持按域名过滤
  - 验收标准: 可以导出不同格式的数据

- [ ] 实现 HAR 格式转换
  - 位置: `backend/app/services/export_service.py`
  - 说明: 将请求数据转换为 HAR 格式
  - 功能点:
    1. 符合 HAR 1.2 规范
    2. 包含请求和响应完整信息
    3. 包含时间戳和耗时
  - 验收标准: 导出的 HAR 文件可被 Charles/Fiddler 导入

- [ ] 实现 CSV 格式转换
  - 说明: 将请求数据转换为 CSV 格式
  - 功能点:
    1. 包含主要字段（URL、方法、状态码、时间等）
    2. 支持自定义导出字段
  - 验收标准: 导出的 CSV 可在 Excel 中打开

- [ ] 前端添加导出按钮和对话框
  - 位置: 请求列表组件
  - 说明: 提供导出功能入口
  - 功能点:
    1. 导出按钮
    2. 格式选择（JSON/HAR/CSV）
    3. 过滤条件设置
    4. 下载文件
  - 验收标准: 用户可以方便地导出数据

---

## m7 前端界面模块

### m7.1 前端目录结构

- [ ] 创建 `frontend/src/pages/ProxyCapture/` 目录
  - 说明: 代理录制功能页面目录

- [ ] 创建 `frontend/src/components/proxy/` 目录
  - 说明: 代理相关组件目录

### m7.2 代理控制面板组件

- [ ] 创建 `ProxyControl.tsx` 组件
  - 位置: `frontend/src/pages/ProxyCapture/ProxyControl.tsx`
  - 说明: 代理服务控制面板
  - 功能点:
    1. 代理配置表单（端口、系统代理、HTTPS捕获）
    2. 启动/停止按钮
    3. 状态显示
    4. 本机IP显示（供移动端配置）
  - 验收标准: 可以启动和停止代理服务

- [ ] 实现代理配置状态管理
  - 说明: 使用 React state 或状态管理库
  - 状态: `config`, `isRunning`, `localIP`, `status`

- [ ] 实现启动代理功能
  - 说明: 调用 `POST /api/v1/proxy/start` API
  - 功能点:
    1. 验证配置
    2. 发送启动请求
    3. 更新状态
    4. 获取本机IP
  - 验收标准: 代理成功启动，状态更新

- [ ] 实现停止代理功能
  - 说明: 调用 `POST /api/v1/proxy/stop` API
  - 验收标准: 代理成功停止

- [ ] 实现状态轮询或WebSocket监听
  - 说明: 实时更新代理状态
  - 验收标准: 状态变化实时反映在UI上

### m7.3 移动端配置向导组件

- [ ] 创建 `MobileSetup.tsx` 组件
  - 位置: `frontend/src/pages/ProxyCapture/MobileSetup.tsx`
  - 说明: 移动端配置向导
  - 功能点:
    1. 平台选择（iOS/Android）
    2. 分步安装说明
    3. 二维码显示
    4. 代理配置信息显示
  - 验收标准: 显示完整的配置指南

- [ ] 实现平台切换功能
  - 说明: 切换 iOS/Android 显示不同的安装步骤
  - 验收标准: 切换平台时内容正确更新

- [ ] 实现二维码获取和显示
  - 说明: 调用 `GET /api/v1/proxy/cert/qrcode` API
  - 功能点:
    1. 获取 Base64 编码的二维码
    2. 显示为图片
  - 验收标准: 二维码正确显示

- [ ] 实现安装说明获取
  - 说明: 调用 `GET /api/v1/proxy/cert/instructions` API
  - 验收标准: 显示详细的分步说明

### m7.4 证书管理组件

- [ ] 创建 `CertManager.tsx` 组件
  - 位置: `frontend/src/pages/ProxyCapture/CertManager.tsx`
  - 说明: 证书管理界面
  - 功能点:
    1. 证书状态显示
    2. Windows证书安装/卸载按钮
    3. 证书下载链接
    4. 安装说明
  - 验收标准: 可以管理证书

- [ ] 实现Windows证书安装功能
  - 说明: 调用 `POST /api/v1/proxy/cert/install-windows` API
  - 功能点:
    1. 显示确认对话框
    2. 调用安装API
    3. 显示安装结果
  - 验收标准: 证书成功安装

- [ ] 实现证书下载功能
  - 说明: 提供证书下载链接
  - 验收标准: 点击可下载证书文件

### m7.5 代理状态显示组件

- [ ] 创建 `ProxyStatus.tsx` 组件
  - 位置: `frontend/src/components/proxy/ProxyStatus.tsx`
  - 说明: 代理状态指示器
  - 功能点:
    1. 运行状态指示灯
    2. 连接客户端数
    3. 总请求数
    4. 系统代理状态
  - 验收标准: 实时显示准确状态

### m7.6 设备列表组件

- [ ] 创建 `DeviceList.tsx` 组件
  - 位置: `frontend/src/components/proxy/DeviceList.tsx`
  - 说明: 已连接设备列表
  - 功能点:
    1. 显示设备类型图标
    2. 显示设备信息（型号、系统版本）
    3. 显示连接时间
    4. 显示请求数统计
  - 验收标准: 列表实时更新

### m7.7 请求列表集成

- [ ] 扩展现有请求列表组件支持多来源
  - 位置: 现有的请求列表组件
  - 说明: 添加来源标识和过滤
  - 功能点:
    1. 显示请求来源图标（浏览器/桌面/iOS/Android）
    2. 添加来源过滤器
    3. 显示设备信息
  - 验收标准: 可以区分和过滤不同来源的请求

- [ ] 实现WebSocket连接
  - 说明: 连接到 `/ws/proxy-events`
  - 功能点:
    1. 建立WebSocket连接
    2. 监听 new_request 事件
    3. 实时添加到请求列表
  - 验收标准: 新请求实时显示

### m7.8 主页面整合

- [ ] 创建 `index.tsx` 主页面
  - 位置: `frontend/src/pages/ProxyCapture/index.tsx`
  - 说明: 代理录制功能主页面
  - 功能点:
    1. 整合所有子组件
    2. 布局设计（控制面板、配置向导、请求列表）
    3. 标签页或折叠面板切换
  - 验收标准: 所有功能可访问

- [ ] 添加路由配置
  - 位置: 前端路由配置文件
  - 路径: `/proxy-capture`
  - 验收标准: 可以通过路由访问页面

- [ ] 添加导航菜单项
  - 说明: 在主导航中添加"代理录制"入口
  - 验收标准: 用户可以从导航进入功能

### m7.9 QRCodeDisplay 组件

- [ ] 创建 `QRCodeDisplay.tsx` 组件
  - 位置: `frontend/src/components/proxy/QRCodeDisplay.tsx`
  - 说明: 二维码显示组件
  - 功能点:
    1. 接收 URL 或 Base64 图片数据
    2. 显示二维码
    3. 显示二维码下方的文字说明
    4. 支持自定义大小
    5. 支持下载二维码图片
  - 验收标准: 二维码清晰可扫描

- [ ] 在 MobileSetup 中使用 QRCodeDisplay
  - 说明: 替换现有的二维码显示逻辑
  - 验收标准: 组件正常工作

### m7.10 移动端配置页面响应式设计

- [ ] 优化移动端配置页面布局
  - 位置: `backend/static/mobile-setup.html`
  - 说明: 适配不同屏幕尺寸
  - 功能点:
    1. 使用响应式CSS
    2. 移动端优先设计
    3. 大按钮易于点击
    4. 字体大小适中
    5. 二维码大小自适应
  - 验收标准: 在各种设备上显示良好

- [ ] 添加设备检测和自动跳转
  - 说明: 自动检测设备类型
  - 功能点:
    1. 检测 User-Agent
    2. iOS 设备显示 iOS 说明
    3. Android 设备显示 Android 说明
    4. 桌面设备显示完整说明
  - 验收标准: 自动显示对应平台的说明

---

## m8 测试与优化模块

### m8.1 单元测试

- [ ] 编写 ProxyServer 单元测试
  - 位置: `backend/tests/test_proxy_server.py`
  - 测试点:
    1. 启动和停止
    2. 请求拦截
    3. 响应处理
  - 验收标准: 测试通过

- [ ] 编写 WindowsSystemProxy 单元测试
  - 位置: `backend/tests/test_system_proxy.py`
  - 测试点:
    1. 读取当前设置
    2. 启用/禁用代理
    3. 恢复原始设置
  - 验收标准: 测试通过

- [ ] 编写 CertManager 单元测试
  - 位置: `backend/tests/test_cert_manager.py`
  - 测试点:
    1. 证书生成
    2. 二维码生成
    3. 安装说明获取
  - 验收标准: 测试通过

- [ ] 编写 RequestFilter 单元测试
  - 位置: `backend/tests/test_filters.py`
  - 测试点:
    1. 规则匹配
    2. 黑白名单逻辑
    3. 正则表达式支持
  - 验收标准: 测试通过

### m8.2 集成测试

- [ ] 编写端到端测试
  - 说明: 测试完整的代理捕获流程
  - 测试场景:
    1. 启动代理 -> 发送HTTP请求 -> 验证捕获
    2. 启动代理 -> 发送HTTPS请求 -> 验证捕获
    3. 设置过滤规则 -> 验证过滤生效
  - 验收标准: 所有场景测试通过

- [ ] 测试系统代理设置
  - 说明: 验证系统代理正确设置和恢复
  - 测试点:
    1. 启用系统代理
    2. 验证注册表值
    3. 停止后验证恢复
  - 验收标准: 系统代理正确管理

- [ ] 测试移动端连接
  - 说明: 使用真实移动设备测试
  - 测试点:
    1. iOS设备配置代理
    2. Android设备配置代理
    3. 验证请求捕获
    4. 验证设备识别
  - 验收标准: 移动端请求成功捕获

### m8.3 性能优化

- [ ] 优化大响应体处理
  - 说明: 避免内存溢出
  - 优化点:
    1. 限制响应体大小（已实现10000字符限制）
    2. 流式处理大文件
    3. 可选的响应体压缩存储
  - 验收标准: 处理大响应不崩溃

- [ ] 优化WebSocket推送
  - 说明: 减少推送频率和数据量
  - 优化点:
    1. 批量推送（每100ms一批）
    2. 只推送必要字段
    3. 支持客户端订阅过滤
  - 验收标准: 高频请求时前端不卡顿

- [ ] 添加请求数据清理机制
  - 说明: 定期清理旧数据
  - 功能点:
    1. 配置保留天数
    2. 定时任务清理
    3. 手动清理接口
  - 验收标准: 数据库不会无限增长

### m8.4 错误处理和日志

- [ ] 添加全局异常处理
  - 说明: 捕获并记录所有异常
  - 位置: FastAPI 异常处理器
  - 验收标准: 异常不会导致服务崩溃

- [ ] 添加详细日志
  - 说明: 记录关键操作和错误
  - 日志点:
    1. 代理启动/停止
    2. 系统代理设置/恢复
    3. 证书安装/卸载
    4. 请求捕获（可配置级别）
  - 验收标准: 日志完整可追溯

- [ ] 添加用户友好的错误提示
  - 说明: 前端显示清晰的错误信息
  - 场景:
    1. 端口被占用
    2. 权限不足
    3. 证书安装失败
  - 验收标准: 用户能理解错误原因

### m8.5 配置持久化

- [ ] 实现代理配置保存功能
  - 位置: `backend/app/services/config_service.py`
  - 说明: 保存用户的代理配置
  - 功能点:
    1. 保存端口配置
    2. 保存系统代理开关状态
    3. 保存过滤规则
    4. 保存到配置文件或数据库
  - 验收标准: 配置持久化成功

- [ ] 实现配置加载功能
  - 说明: 启动时加载上次的配置
  - 功能点:
    1. 读取配置文件
    2. 应用到代理服务
    3. 处理配置不存在的情况
  - 验收标准: 重启后配置保持

- [ ] 实现 `GET /api/v1/proxy/config` 接口
  - 说明: 获取当前配置
  - 验收标准: 返回完整配置

- [ ] 实现 `PUT /api/v1/proxy/config` 接口
  - 说明: 更新配置
  - 验收标准: 配置更新并保存

- [ ] 前端加载和应用配置
  - 说明: 页面加载时获取配置
  - 验收标准: 配置自动填充到表单

### m8.6 日志系统配置

- [ ] 配置 Python logging
  - 位置: `backend/app/core/logging_config.py`
  - 说明: 统一的日志配置
  - 功能点:
    1. 配置日志级别（DEBUG/INFO/WARNING/ERROR）
    2. 配置日志格式
    3. 配置日志文件路径
    4. 配置日志轮转（按大小或时间）
    5. 配置控制台输出
  - 验收标准: 日志系统正常工作

- [ ] 添加日志级别配置接口
  - 说明: 运行时调整日志级别
  - 功能点:
    1. `GET /api/v1/system/log-level` - 获取当前日志级别
    2. `PUT /api/v1/system/log-level` - 设置日志级别
  - 验收标准: 可以动态调整日志级别

- [ ] 添加日志查看接口
  - 说明: 通过API查看日志
  - 功能点:
    1. `GET /api/v1/system/logs` - 获取最近的日志
    2. 支持分页
    3. 支持按级别过滤
    4. 支持按时间范围过滤
  - 验收标准: 可以在前端查看日志

### m8.7 性能监控

- [ ] 实现基础性能指标收集
  - 位置: `backend/proxy/statistics.py`（集成到现有统计模块）
  - 说明: 收集基本的性能数据
  - 功能点:
    1. 监控请求处理延迟
    2. 监控并发连接数
    3. 监控错误率
  - 验收标准: 性能指标准确记录

- [ ] 在统计接口中包含性能数据
  - 说明: 将性能数据集成到现有的 `GET /api/v1/proxy/statistics` 接口
  - 验收标准: 统计接口返回性能数据

### m8.8 WebSocket 心跳机制

- [ ] 实现服务端心跳
  - 位置: `ProxyEventBroadcaster` 类
  - 说明: 定期发送心跳消息
  - 功能点:
    1. 每30秒发送一次 ping 消息
    2. 检测客户端响应
    3. 超时未响应则断开连接
  - 验收标准: 可以检测死连接

- [ ] 实现客户端心跳响应
  - 位置: 前端 WebSocket 连接代码
  - 说明: 响应服务端心跳
  - 功能点:
    1. 接收 ping 消息
    2. 回复 pong 消息
    3. 超时未收到心跳则重连
  - 验收标准: 连接保持活跃

---

## m9 文档与部署

### m9.1 用户文档

- [ ] 编写功能使用文档
  - 位置: `docs/proxy_capture_guide.md`
  - 内容:
    1. 功能概述
    2. Windows桌面应用录制指南
    3. iOS移动端录制指南
    4. Android移动端录制指南
    5. 常见问题解答
  - 验收标准: 文档清晰完整

- [ ] 编写故障排查文档
  - 位置: `docs/proxy_troubleshooting.md`
  - 内容:
    1. 代理无法启动
    2. HTTPS请求无法捕获
    3. 移动端无法连接
    4. 证书安装失败
  - 验收标准: 覆盖常见问题

### m9.2 开发文档

- [ ] 编写API文档
  - 说明: 使用FastAPI自动生成的文档
  - 补充: 添加详细的接口说明和示例
  - 验收标准: API文档完整

- [ ] 编写架构文档
  - 位置: `docs/proxy_architecture.md`
  - 内容:
    1. 系统架构图
    2. 模块职责说明
    3. 数据流图
    4. 技术选型说明
  - 验收标准: 开发者能快速理解架构

### m9.3 部署配置

- [ ] 更新 requirements.txt
  - 说明: 确保所有依赖都已添加
  - 验收标准: `pip install -r requirements.txt` 成功

- [ ] 更新 package.json
  - 说明: 确保前端依赖完整
  - 验收标准: `npm install` 成功

- [ ] 添加环境变量配置
  - 说明: 代理服务相关配置
  - 配置项:
    - `PROXY_DEFAULT_PORT`: 默认代理端口
    - `PROXY_CERT_DIR`: 证书目录
    - `PROXY_MAX_RESPONSE_SIZE`: 最大响应体大小
  - 验收标准: 配置可通过环境变量覆盖

- [ ] 编写部署脚本
  - 位置: `scripts/deploy_proxy.sh` 或 `.bat`
  - 功能:
    1. 安装依赖
    2. 初始化证书
    3. 启动服务
  - 验收标准: 一键部署成功

---

## m10 安全与合规

### m10.1 安全加固

- [ ] 实现证书私钥保护
  - 说明: 确保证书私钥不泄露
  - 措施:
    1. 证书仅存储在本地
    2. 不通过API暴露私钥
    3. 文件权限限制
  - 验收标准: 私钥无法通过API获取

- [ ] 实现敏感数据脱敏
  - 说明: 自动识别和脱敏敏感字段
  - 敏感字段:
    - Authorization header
    - Cookie
    - password 字段
    - token 字段
  - 验收标准: 敏感数据被遮蔽

- [ ] 配置代理监听地址
  - 说明: 配置代理服务监听地址
  - 措施:
    1. 默认监听 0.0.0.0（允许移动端连接）
    2. 可配置为仅监听 127.0.0.1（仅本机）
  - 验收标准: 代理服务按配置监听

### m10.2 合规性

- [ ] 添加用户协议和免责声明
  - 位置: 前端首次使用时显示
  - 内容:
    1. 工具用途说明
    2. 合法使用要求
    3. 隐私保护说明
  - 验收标准: 用户必须同意才能使用

- [ ] 添加数据保留策略配置
  - 说明: 允许用户配置数据保留时间
  - 验收标准: 可配置自动删除旧数据

### m10.3 数据备份和恢复

- [ ] 实现数据备份功能
  - 位置: `backend/app/services/backup_service.py`
  - 说明: 备份请求数据和配置
  - 功能点:
    1. 导出所有请求数据
    2. 导出所有配置
    3. 导出过滤规则
    4. 打包为 ZIP 文件
  - 验收标准: 可以完整备份数据

- [ ] 实现数据恢复功能
  - 说明: 从备份恢复数据
  - 功能点:
    1. 解析备份文件
    2. 恢复请求数据
    3. 恢复配置
    4. 恢复过滤规则
  - 验收标准: 可以从备份恢复

- [ ] 添加备份/恢复 API
  - 说明: 提供备份和恢复接口
  - 功能点:
    1. `POST /api/v1/system/backup` - 创建备份
    2. `POST /api/v1/system/restore` - 恢复备份
    3. `GET /api/v1/system/backups` - 列出备份
  - 验收标准: API 正常工作

- [ ] 前端备份管理界面
  - 位置: 系统设置页面
  - 说明: 备份和恢复操作界面
  - 验收标准: 用户可以方便地备份和恢复

---

## m11 高级功能模块

### m11.1 请求重放功能

- [ ] 创建请求重放数据模型
  - 位置: `backend/app/models/replay_request.py`
  - 说明: 存储重放请求的配置
  - 字段:
    - `id`: 重放ID
    - `original_request_id`: 原始请求ID
    - `target_url`: 目标URL（可修改）
    - `method`: 请求方法
    - `headers`: 请求头（可修改）
    - `body`: 请求体（可修改）
    - `created_at`: 创建时间
  - 验收标准: 数据模型创建成功

- [ ] 实现请求重放服务
  - 位置: `backend/app/services/replay_service.py`
  - 说明: 重放捕获的请求
  - 功能点:
    1. `replay_request()` - 重放单个请求
    2. `batch_replay()` - 批量重放请求
    3. 支持修改URL、headers、body
    4. 记录重放结果
    5. 支持重放到不同环境
  - 验收标准: 服务正常工作

- [ ] 实现 `POST /api/v1/requests/{request_id}/replay` 接口
  - 说明: 重放指定的请求
  - 功能点:
    1. 获取原始请求数据
    2. 允许修改目标URL、headers、body
    3. 发送HTTP请求
    4. 返回响应结果
    5. 记录重放历史
  - 验收标准: 请求成功重放

- [ ] 实现 `POST /api/v1/requests/batch-replay` 接口
  - 说明: 批量重放多个请求
  - 参数: `request_ids: List[str]`, `modifications: dict`
  - 功能点:
    1. 支持批量重放
    2. 支持统一修改配置
    3. 支持并发控制
    4. 返回批量结果
  - 验收标准: 批量重放成功

- [ ] 实现 `GET /api/v1/requests/{request_id}/replay-history` 接口
  - 说明: 获取请求的重放历史
  - 功能点:
    1. 查询重放记录
    2. 显示重放时间、结果、响应
    3. 支持分页
  - 验收标准: 返回完整的重放历史

- [ ] 前端请求重放界面
  - 位置: 请求详情页面
  - 说明: 请求重放操作界面
  - 功能点:
    1. 重放按钮
    2. 修改URL对话框
    3. 修改headers对话框
    4. 修改body对话框
    5. 显示重放结果
    6. 查看重放历史
  - 验收标准: 用户可以方便地重放请求

- [ ] 实现请求对比功能
  - 位置: `frontend/src/components/RequestCompare.tsx`
  - 说明: 对比原始请求和重放结果
  - 功能点:
    1. 并排显示原始和重放的请求/响应
    2. 高亮差异部分
    3. 支持JSON格式化对比
    4. 支持响应时间对比
  - 验收标准: 差异清晰可见

### m11.2 环境管理功能（可选功能）

> **说明**: 此功能为可选的高级功能，适用于需要在多个环境间切换测试的场景。对于基础的请求录制和重放，可以跳过此模块。

- [ ] 创建环境配置数据模型
  - 位置: `backend/app/models/environment.py`
  - 说明: 管理不同的测试环境
  - 字段:
    - `id`: 环境ID
    - `name`: 环境名称（开发、测试、生产等）
    - `base_url`: 基础URL
    - `headers`: 默认headers
  - 验收标准: 数据模型创建成功

- [ ] 实现环境管理API
  - 说明: 环境的增删改查
  - 接口:
    1. `GET /api/v1/environments` - 获取所有环境
    2. `POST /api/v1/environments` - 创建环境
    3. `PUT /api/v1/environments/{env_id}` - 更新环境
    4. `DELETE /api/v1/environments/{env_id}` - 删除环境
  - 验收标准: API正常工作

- [ ] 在请求重放中集成环境选择
  - 说明: 重放时可以选择目标环境
  - 功能点:
    1. 环境选择下拉框
    2. 自动替换base_url
    3. 应用环境默认headers
  - 验收标准: 可以重放到不同环境

---

## 总结

本任务清单共包含 **11个大模块 (m1-m11)**，涵盖：
- m1: 核心代理服务模块（环境准备、ProxyServer、RequestInterceptor）
- m2: Windows桌面应用支持模块（系统代理设置、防火墙配置）
- m3: CA证书管理模块（证书生成、安装、管理）
- m4: 移动端支持模块（设备识别、配置页面）
- m5: 请求过滤模块（过滤规则、API）
- m6: 数据统一管理模块（统一模型、存储、WebSocket推送）
- m7: 前端界面模块（控制面板、配置向导、组件）
- m8: 测试与优化模块（单元测试、集成测试、性能优化）
- m9: 文档与部署（用户文档、开发文档、部署配置）
- m10: 安全与合规（安全加固、合规性、数据备份）
- m11: 高级功能模块（请求重放、环境管理）

**预计任务数量**: 约 **230+ 个详细任务**

**原有补充模块**:
- m1.6: 全局代理服务管理器
- m1.7: 请求统计功能
- m1.8: 错误处理和重试机制
- m3.3: 证书管理增强
- m5.4: 过滤规则持久化
- m6.4: 导出功能支持多来源
- m7.9: QRCodeDisplay 组件
- m7.10: 移动端配置页面响应式设计
- m8.5: 配置持久化
- m8.6: 日志系统配置
- m8.7: 性能监控
- m8.8: WebSocket 心跳机制
- m10.3: 数据备份和恢复

**新增实用模块（Windows平台）**:
- m2.3: Windows防火墙自动配置（8个任务）- 移动端连接必需
- m11.1: 请求重放功能（7个任务）- 调试测试必备
- m11.2: 环境管理功能（4个任务）- 多环境切换

**新增任务总计**: 19个实用任务

**说明**:
- 本地运行场景，已移除过度设计的安全功能（API限流、令牌认证、审计日志等）
- 保留实用功能：防火墙配置（移动端连接）、请求重放（调试）、环境管理（多环境测试）
- 保留基础安全：敏感数据脱敏、证书私钥保护

**实施建议**:
1. 按模块顺序实施：m1 → m2 → m3 → m4 → m5 → m6 → m7 → m8 → m9 → m10
2. 每个模块完成后进行测试验证
3. 优先实现核心功能（m1-m4），再完善辅助功能
4. 持续集成测试（m8）贯穿整个开发过程

---

*任务清单版本: 1.0*
*创建日期: 2025-01-17*
*基于设计文档: multi_platform_capture_design.md*
