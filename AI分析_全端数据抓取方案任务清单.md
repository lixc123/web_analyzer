# AI 分析用：全端数据抓取方案（推荐 B）任务清单

## 我建议选 A 还是 B？

结论：**推荐 B（可复现/可定位/可关联）作为目标**，因为你后续要给 AI 做分析，AI 最需要的是：
- 同一业务操作的 **HTTP + WS + 进程/调用栈/脚本来源** 能串起来
- 关键请求/响应的 **完整 body（或落盘引用）** 可回放、可对比
- 出问题时能解释“为什么抓不到/为什么是密文”（证书固定/HTTP3/应用层加密）

同时建议用“**A → B 的分阶段落地**”：先保证能稳定抓到流量（A），再把采集质量升级到 AI 友好的结构（B）。

---

## Phase 0：定义“给 AI 的输入包”（先定标准，后补功能）

- [x] 定义 `analysis_bundle` 目录结构（Web/Windows/手机统一），明确必须包含：请求列表、响应/产物引用、会话元信息、关联索引、摘要统计  
- [x] 生成 `bundle_manifest.json`：包含所有文件路径、计数、时间范围、会话来源（proxy/crawler/hook/js_injection）  
- [x] 生成 `bundle_summary.md`：人类可读摘要（域名Top、API Top、WS Top、失败原因统计、疑似应用层加密比例）  
- [x] 统一“关联键”规范：`analysis_session_id`（总会话） ↔ `proxy_session_id` / `crawler_session_id` / `hook_session_id` / `js_injection_session_id` 的映射文件  
- [x] 约定大包/二进制一律“落盘引用”：记录 `artifact_id/path/size/sha256/content-type`，避免内存截断影响 AI 判断  

---

## Phase 1：Web（Playwright 录制 / Crawler）补齐到 B

- [x] 明确 `max_depth` / `follow_redirects` 的真实语义：要么实现“自动爬链路”，要么在 UI/文档标注为“预留不生效”，避免误导  
- [x] 补齐 Playwright `requestfailed` 采集：把失败原因/错误文本落到会话记录里（否则 AI 无法解释“为什么没响应”）  
- [x] 修正截图落盘到 session 目录：保证下载的 session zip 自包含（不要把截图写到工作目录 `screenshots/`）  
- [x] 请求体补齐：对 `multipart/binary/大 body` 增加落盘（类似 proxy 的 artifacts），并在记录里保存引用  
- [x] Hook 选项对齐能力：在 crawler 的 HookOptions/前端 UI 中补齐可选项（如 websocket/crypto/storageExport/stateManagement），默认关闭即可  
- [x] JS 资源补齐策略记录：`save_js_resources` 的跨域/CORS 失败要落日志与计数（否则“脚本缺失”AI 会误判）  

---

## Phase 2：Windows（代理抓包 + 内存 Hook）补齐到 B

- [x] WinHTTP：补齐分块发送路径（例如 `WinHttpWriteData`）以提高请求体完整性（目前更多是预览/片段）  
- [x] WinINet：补齐分块发送路径（例如 `HttpSendRequestEx/InternetWriteFile`）以提高请求体完整性  
- [x] WinHTTP/WinINet：补齐响应元信息采集（例如 `WinHttpQueryHeaders/HttpQueryInfo`），让 Hook 侧也能还原 status/headers（不仅是读到的数据片段）  
- [x] Winsock：把“仅预览”明确标注为兜底层；必要时增加按 socket 聚合/重组开关（默认关闭，避免噪音）  
- [x] Hook 事件与 proxy 请求做更稳关联：从“URL+method+时间窗”升级为“句柄/连接信息+时间窗+目标域名”多因子匹配，并把关联结果写入记录  
- [x] Hook 原始 buffer 可选落盘（受限于 max_preview/采样/总量上限）：让 AI 可以对比“网络前最后一次明文/压缩/加密”的字节特征  

---

## Phase 3：手机（iOS/Android）补齐到 B

- [x] 在前端“移动端配置”页增加抓不到时的分诊：证书未信任/证书固定/HTTP3/走直连等（给出可执行排查步骤）  
- [x] 在后端 diagnostics 增加“移动端抓不到”可解释信号：TLS 握手失败统计、最近 NO_TRAFFIC、疑似 pinning 的特征计数  
- [x] 设备识别增强：移动端设备列表里展示更稳定的标识（IP/UA/平台/系统版本/首次出现时间/请求数），便于 AI 过滤来源  
- [x] 若目标 App 经常 pinning：明确是否要引入移动端 Hook 方案（不做安全设计也要做可操作路径的文档化）  

---

## Phase 4：后端功能是否都有前端入口（UI 对齐）

- [x] 给 `/api/v1/migration/*` 增加 Settings 中的“迁移工具”UI（查看状态 + 一键迁移）  
- [x] 核对 proxy 相关：requests / sessions / websockets / artifacts / js_injection / storage-cleanup 全部可在前端访问与下载  
- [x] 核对 crawler 相关：sessions / status / requests 分页 / export(json/csv/har) / download(zip) 全部可在前端访问  
- [x] 核对 native-hook 相关：进程列表/attach/detach/templates/records/导出/推荐模板（按模块检测）全部可在前端访问  
- [x] 明确 `request-analysis` 页的定位：若要用于 AI 训练/分析，需替换 mock callstack 与“录制”占位实现；否则在 UI 标注为“演示/实验功能”  

---

## Phase 5：一键导出“AI 分析包”（把多会话数据串成 1 个 zip）

- [x] 后端增加 `GET /export/analysis-bundle?analysis_session_id=...`：将 proxy/crawler/hook/js 注入产物打包为 zip  
- [x] 前端增加“下载 AI 分析包”按钮：支持选择 proxy_session/crawler_session/hook_session 或自动关联当前会话  
- [x] zip 内增加 `index.json`：为 AI/脚本提供机器可读入口（按 request_id/connection_id/事件类型快速定位）  

---

## Phase 6：本地验证（不做安全，只做完整性回归）

- [x] 增加一个本地 smoke 脚本：启动 proxy → 产生 HTTP/HTTPS/WS 示例流量 → 停止 → 校验 sessions/artifacts/导出文件齐全  
- [x] 增加一个 crawler smoke：录制一个站点 → 停止 → 校验 requests.json/trace.har/metadata/browser_data/脚本目录/zip 自包含  
- [x] 增加一个 hook smoke（可选）：附加一个可控进程/注入模板 → 产生网络调用 → 校验 records 落库与可导出  
