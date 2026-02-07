# Windows 应用端抓包/数据抓取补齐任务清单

> 目标：把 Windows 桌面应用的网络数据“尽可能完整、可复现、可定位来源”地采集下来。
> 现状：代理抓包（mitmproxy）为主，Native Hook（Frida）为增强；仍存在 WinHTTP/SSL pinning/WS/HTTP3/二进制持久化等缺口。

---

## 后端（Backend）

### P0（强烈建议优先补齐：直接影响“能不能抓到”）

- [x] 系统代理增加 **WinHTTP** 覆盖：封装 `netsh winhttp set proxy` / `reset` / `import proxy source=ie`，并支持读取当前 WinHTTP 代理状态（便于回滚与冲突提示）。
- [x] `/api/v1/proxy/start` 增加开关：`enable_winhttp_proxy`（与现有 `enable_system_proxy` 区分 WinINet/IE vs WinHTTP），`/stop` 时分别恢复。
- [x] 启动代理时增加“冲突自检”：若 WinHTTP/WinINet 已被其它软件占用或设置为 PAC/无效地址，返回明确诊断与修复建议。
- [x] 增加“HTTP3/QUIC 风险提示与一键指导”：检测/提示常见 Chromium 系应用走 QUIC 导致抓不到（给出禁用方式/启动参数/策略说明）。
- [x] mitmproxy 插件补齐 **WebSocket 消息**采集：记录 `connect/open/message/close` 事件（含方向、长度、前 N 字节预览、可选落盘）。

### P1（提高完整性：抓到之后“不丢关键字段/不丢大包”）

- [x] 请求/响应体改为“可配置落盘”：对二进制/大包保存到文件，内存只留摘要与路径（避免 `MAX_BODY_LENGTH` 截断导致关键字段缺失）。
- [x] 响应体处理增强：自动识别并解码 gzip/br/deflate（若 mitmproxy 未解码则补齐），并记录 `content-encoding` 及解码结果。
- [x] 统一结构补齐：为代理抓包的 `UnifiedRequest` 增加 `http_version`、`remote_ip/port`、`tls`（SNI/ALPN/证书摘要）等字段（能显著提升排障效率）。
- [x] WebSocket 消息与 HTTP 请求建立关联：按连接 URL、会话、时间窗口进行关联，便于前端按“某个业务操作”查看整套链路。
- [x] 敏感字段策略：本地自用场景默认“完整保存”（Cookie/Authorization/Set-Cookie 等），仍保留导出/详情的“包含敏感字段”开关以便按需脱敏或分享。

### P2（Native Hook：用于“代理失效/证书固定/直连”场景）

- [x] 增加 Frida 模板：**SSL Unpinning（Windows）**（SChannel/WinVerifyTrust/CertVerifyCertificateChainPolicy 等），用于绕过证书固定让流量回到代理解密。
- [x] 现有 `windows_api_hooks.js` 做成“可配置模块化”：按需启用 WinHTTP/WinINet/Winsock/Crypto，降低注入风险与噪音。
- [x] WinHTTP Hook 增强：补齐 `WinHttpOpenRequest/WinHttpConnect/WinHttpAddRequestHeaders/WinHttpSendRequest/WinHttpReadData` 等，尽可能还原 URL、method、headers、body（至少做到“能定位到请求对象”）。
- [x] Winsock Hook 增强：增加 `WSASend/WSARecv/sendto/recvfrom` 支持，并提供可选 hexdump（仅前 N 字节）与按 socket 维度聚合。
- [x] Hook 记录持久化：当前 `hook_records` 为内存列表，补齐落库/落盘（分页、检索、导出）与 session 生命周期管理。
- [x] 修复 `GET /native-hook/records` 的会话过滤逻辑（当前按 `process_name` 过滤且对象/字典混用，容易失效）。

### P3（工程化与可运维）

- [x] 增加“环境诊断”接口：一键输出 WinINet/WinHTTP 代理状态、证书安装状态、端口占用、防火墙规则、mitmproxy CA 是否有效等。
- [x] 增加“抓包失败分类”与建议码：例如 `CERT_NOT_TRUSTED / SSL_PINNING / HTTP3_QUIC / BYPASS_PROXY / NO_TRAFFIC`，前端直接展示可执行建议。
- [x] 增加回归用样例：用已知站点（HTTP/HTTPS/WS）跑通采集 + 导出，保证每次改动不退化。

---

## 前端（Frontend）

### P0（强烈建议优先补齐：把关键开关“放到可用的 UI”）

- [x] 代理控制台增加 **WinINet 代理 / WinHTTP 代理** 两套开关与当前状态展示（并提示它们覆盖范围不同）。
- [x] 新增“Windows 桌面应用抓包向导”页面：按步骤引导（安装证书 → 开启代理 → 开启 WinHTTP → 处理 QUIC → 必要时启用 Hook）。
- [x] 抓包列表支持 WebSocket 消息视图：连接列表、按连接筛选、消息方向/大小/预览、可下载原始数据。

### P1（提高可分析性：抓到之后“看得懂/找得到/导得出”）

- [x] 请求详情补齐：展示 `http_version`、TLS/证书摘要、远端地址、是否来自 WinHTTP/WinINet（若后端提供）。
- [x] 大包/二进制展示：支持“摘要 + 下载文件 +（可选）hex/文本切换”，并在 UI 明确标识“已截断/已落盘”。
- [x] 过滤器增强：按来源（WinINet/WinHTTP/Hook）、协议（HTTP/WS）、状态（仅失败/仅 4xx/5xx）、内容类型筛选。
- [x] 导出开关与提示：导出前明确提示敏感字段处理方式，并支持单次导出覆盖默认设置（本地默认包含敏感字段）。

### P2（Native Hook：降低使用门槛）

- [x] Native Hook 页面模板按“用途”分组：网络监控/SSL unpin/WinHTTP 还原/Socket 聚合，并提供风险提示（稳定性/隐私/性能）。
- [x] Hook 记录表格增强：按 `session/api/type` 聚合、关键字段快捷展开、支持导出（JSON/CSV）。
- [x] Hook 与请求联动：点击 Hook 事件可跳转/高亮对应时间段的请求/WS 消息（后端完成关联后启用）。

### P3（体验与稳定性）

- [x] 为“抓不到流量”的场景增加统一错误页：展示诊断码 + 一键复制命令/建议（例如 WinHTTP 代理设置、QUIC 禁用方式）。
- [x] 增加“性能保护”提示：当实时列表过大时自动降采样/分页，并提示用户如何开启落盘与缩小过滤范围。
