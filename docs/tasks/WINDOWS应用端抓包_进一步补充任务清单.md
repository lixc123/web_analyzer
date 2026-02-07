# Windows 应用端抓包/数据抓取：进一步补充任务清单（建议项）

> 目标：在现有“mitmproxy 代理抓包 + WinINet/WinHTTP 双栈代理 + Windows 向导诊断 + Frida Native Hook/SSL Unpin”的基础上，把 **抓不到/抓到了但看不懂/抓到了但不可复现** 这些尾部场景补齐。
>
> 说明：本清单为“进一步增强项”，不否定当前实现；是否做取决于你的目标应用类型（WinHTTP/WinINet/直连/QUIC/WebView2/Electron/CEF）与验收标准（只要能抓到 vs 还要可复现可定位）。

---

## 后端（Backend）

### P0（命中率/可回滚：直接影响“能不能抓到”）

[x] WinINet（系统代理）备份/恢复增强：完整保存并恢复 `ProxyEnable/ProxyServer/ProxyOverride/AutoConfigURL/AutoDetect`，避免 PAC/按协议代理被覆盖后无法回滚  
[x] WinINet 解析增强：支持 `http=...;https=...` 这类按协议 ProxyServer 字符串的展示与诊断（目前仅按 `host:port` 简化）  
[x] WinHTTP 备份/恢复增强：解析并保留更多原始信息（包含 bypass list / 多代理输出），`import_from_ie` 前也要先备份并可一键恢复  
[x] “无流量”诊断细分：区分 `BYPASS_PROXY / HTTP3_QUIC / CERT_PINNING / TLS_HANDSHAKE_FAIL / APP_LAYER_ENCRYPTION`，并基于 mitmproxy flow error/握手失败统计给出更具体建议  
[x] HTTP/3(QUIC) 处理升级：在诊断中加入“近期 UDP 443 连接/Chrome(Edge) QUIC 策略状态”的 best-effort 检测（仍然无法真正抓 QUIC，但能更快定位原因）  
[x] 进程归因稳健化：优化 `psutil.net_connections` 的匹配逻辑与缓存策略（减少误判/性能开销），并把 `client_process` 作为一等字段用于筛选与导出  
[x] Source 判定改进：不只依赖 User-Agent，结合 `client_process/exe`、目标端口、SNI 等把 `web_browser/desktop_app` 分类更准确  

### P1（可分析/可复现：抓到了要“看得懂”）

[x] Proxy 抓包“会话化”：增加 `proxy_session_id`（start/stop）并将 HTTP/WS/诊断快照/artifacts 索引写入 `data/sessions/<id>/...`，重启后可回放/复盘  
[x] WebSocket 数据持久化：当前 WS 主要为内存缓存；补齐落盘（文本/二进制引用 artifacts）+ 导出（json/csv）+ 按会话清理  
[x] 大包/二进制治理：artifacts 增加容量上限与清理策略（LRU/按天/按会话），避免长期运行磁盘膨胀  
[x] 结构化导出增强：HAR/CSV/JSON 导出补齐 `http_version/tls/client_process/artifact_id` 关联信息；WS 导出提供连接摘要与消息引用  
[x] gRPC/Protobuf best-effort 识别：至少标注 `content-type=application/grpc`、method path、message length（不强行解码），提升可读性  
[x] Streaming/SSE 处理：对长连接响应记录首包/尾包/片段统计，避免“响应体为空/不完整”导致误判  

### P2（高级场景：代理无效/证书固定/应用层加密）

[x] Native Hook 模板扩展：检测进程加载模块（如 OpenSSL/BoringSSL/mbedTLS）后提示对应 unpin/hook 模板（现有主要覆盖 Windows API 链路）  
[x] 应用层加密定位增强：在 Hook 中增加更贴近业务的数据点（序列化/压缩/签名函数）采样能力（可配置、默认关闭）  
[x] QUIC/自研 UDP 场景策略：给出“禁用 QUIC/降级到 TCP”的一键脚本/指导（尽量只做指导或可选执行，避免默认修改系统策略）  

### P3（工程化）

[x] 回归脚本补齐：HTTP/HTTPS/WS + WinINet/WinHTTP 开关回滚 + 导出 + artifacts 清理的自动化验证  

---

## 前端（Frontend）

### P0（可用性：少走弯路）

[x] Windows 向导补齐“恢复原始代理/一键清理”操作，并展示“原始配置快照”（PAC/按协议代理/绕过列表）  
[x] 抓不到流量“分诊 UI”：按诊断码给出可执行步骤（启用 WinHTTP、处理 QUIC、安装证书、启用 SSL Unpin、检查代理冲突）  
[x] 进程维度筛选：按 `client_process.name/exe/pid` 快速筛选（定位“到底是谁在发请求”）  
[x] WebSocket 页面增强：导出（json/csv）、artifact 批量下载、按连接/方向/大小过滤  
[x] 请求详情增强：大包/二进制的下载入口更显眼，支持文本/hex 预览切换并标记“已截断/已落盘”  

### P1（可分析：把链路串起来）

[x] Proxy 会话视图：按 `proxy_session_id` 组织请求/WS/诊断快照，支持导出/删除/备注  
[x] 联动视图：HTTP 请求 ↔ WS 连接/消息 ↔ Native Hook 事件互相跳转（已有弱关联基础，补齐 UI）  
[x] 元数据展示：TLS(SNI/ALPN)、HTTP 版本、远端地址、WinINet/WinHTTP 状态等统一呈现并可筛选  

### P2（性能/可运维）

[x] 大列表优化：虚拟滚动/分页与降采样提示，避免长时间抓包导致页面卡顿  
[x] 存储占用/清理页：展示 artifacts/session 占用、保留策略、清理预览与执行结果  

---

## JS 注入（可选，仅在 WebView2/Electron/CEF 需要）

[x] 增加“JS 注入采集”模式：通过 CDP/remote debugging（或 Hook 注入到渲染进程）注入脚本，采集 `fetch/XHR/WebSocket` 的调用栈与业务语义（默认关闭）  
[x] JS 注入与代理请求关联：将 JS 层事件与 proxy request_id/WS connection_id 关联，解决“抓到了但不知道哪段代码触发”  
[x] 注入脚本开关与采样：可配置采样比例与最大预览，避免对页面/渲染进程造成明显性能影响  
