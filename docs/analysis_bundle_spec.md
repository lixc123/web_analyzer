# AI 分析包（analysis_bundle）规范

本项目的目标是给 AI / 自动化脚本提供 **可复现、可定位、可关联** 的输入包：把来自不同采集链路（proxy / crawler / native-hook）的数据统一打包为一个 zip，目录结构固定、元信息齐全、二进制/大包以落盘引用方式提供。

---

## 1. 目录结构（zip 内）

zip 根目录固定为：

`analysis_bundle/<analysis_session_id>/`

其中 `<analysis_session_id>` 由前端传入或后端自动生成（例如 `analysis_20260126_120000`）。

### 1.1 元信息文件（meta_files）

- `bundle_manifest.json`：全量元信息（来源/计数/时间范围/产物引用/文件清单）
- `bundle_summary.md`：人类可读摘要（Top 域名/路径/WS、失败原因统计、疑似应用层加密比例等）
- `index.json`：机器可读索引（按 request_id/connection_id/关联ID 快速定位）
- `session_mapping.json`：关联键映射（analysis_session_id ↔ proxy/crawler/hook/js_injection 会话）

### 1.2 数据来源（sources）

- `sources/proxy/<proxy_session_id>/`：代理抓包会话目录（requests/websockets/js_events/errors 等）
- `sources/crawler/<crawler_session_id>/`：Playwright 录制会话目录（requests.json/trace.har/metadata.json/响应落盘目录等）
- `sources/native_hook/<hook_session_id>/`：Native Hook 会话导出（hook_session.json/hook_records.json 等）

### 1.3 产物目录（artifacts）

所有“大包/二进制”统一 **落盘引用**，避免内存截断影响 AI 判断：

- `artifacts/proxy/<artifact_id>`：proxy 侧请求/响应体、WS 二进制等落盘文件
- `artifacts/hook/<artifact_id>`：native-hook 侧 raw buffer（可选）落盘文件

---

## 2. 关联键（mapping）

统一以一个 `analysis_session_id` 作为“总会话”，并通过 `session_mapping.json` 建立映射：

- `analysis_session_id` ↔ `proxy_session_id[]`
- `analysis_session_id` ↔ `crawler_session_id[]`
- `analysis_session_id` ↔ `hook_session_id[]`
- `analysis_session_id` ↔ `js_injection_session_id[]`（当前与 proxy 会话绑定，事件存于 proxy 会话内）

用于 AI/脚本将同一次业务操作的“网络流量 + 调用栈/Hook事件 + 产物引用”串联起来。

---

## 3. bundle_manifest.json（全量元信息）

`bundle_manifest.json` 是分析包的“总索引”，包含：

- `analysis_session_id` / `generated_at`
- `directory_structure`：目录结构声明（用于外部脚本无需猜测路径）
- `sources[]`：每个来源会话（kind/session_id/root）
- `time_range`：合并后的时间范围（best-effort）
- `counts`：核心计数（proxy/crawler/hook/ws/js/artifacts 等）
- `top`：Top Domains / Top Paths / Top WS（best-effort）
- `failures`：失败原因统计（proxy error types、crawler failure reasons）
- `proxy_artifacts[]` / `hook_artifacts[]`：产物引用清单（artifact_id/size/sha256/content_type 等）
- `files[]`：文件清单（path/size/sha256/generated；`bundle_manifest.json` 本身会列出 path/size）

---

## 4. index.json（机器可读入口）

`index.json` 目标是让 AI/脚本能快速定位数据：

- `sources.proxy[].requests_index`：按 `request_id` 定位请求在 `proxy_requests.json` 中的序号与关键字段
- `sources.proxy[].ws_messages_index`：按 `connection_id` 定位 WS 消息范围
- `sources.proxy[].js_events_by_request_id`：按 `request_id` 聚合 JS 注入事件
- `sources.crawler[].requests_index`：按 `request_id` 定位 crawler 请求记录
- `sources.native_hook[].records_by_correlated_request_id`：按 `request_id` 聚合 hook 事件

---

## 5. 大包/二进制落盘引用约定

当内容体积过大、为 multipart、或为二进制时，记录里应 **保留预览 + artifact 引用**：

- proxy：`body_artifact` / `response_body_artifact`
- crawler：`request_body_artifact` / `response_body_path`
- native-hook：`args._raw_buffer_artifact`（仅当启用 raw buffer 落盘）

artifact 引用建议包含：

- `artifact_id` / `relative_path`（或 bundle 内路径）
- `size` / `sha256`
- `content_type`
- `is_binary` / `truncated`（可选）

---

## 6. 兼容性说明

- 该规范以 **可读性 + 可关联性** 为优先，字段均为 best-effort。
- 不同来源会话可能缺少部分文件（例如未启用 screenshots/js_resources/raw buffers）。
- `bundle_summary.md` 与统计字段用于快速排查抓不到/抓不全/密文等问题，但不承诺严格准确。

