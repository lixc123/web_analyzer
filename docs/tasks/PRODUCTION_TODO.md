# 上线前待办清单（Production Readiness）

> 说明：如果你只在本机单人使用（服务仅绑定 `127.0.0.1/localhost`，不对局域网/公网开放），下面标注为“本机单人可忽略”的安全项可以去除。
> 如果你需要手机/其他设备连进来抓包（通常会绑定 `0.0.0.0`、开放端口到局域网），这些安全项就不建议去掉。

## 前端（frontend）
[]（本机单人可忽略）`npm audit --omit=dev` 目前存在高危漏洞（`@remix-run/router` Open Redirect XSS）：升级 `react-router-dom` 到已修复版本并做回归测试。
[]（本机单人可忽略）`lodash`/`lodash-es` 原型污染告警：确认是否真实可利用；若有对不可信输入使用 `_.unset/_.omit` 等，增加输入校验/替代实现；同时尝试通过依赖升级消除告警。
[] 确认生产环境 API/WS 地址策略：`VITE_API_BASE_URL`、`VITE_WS_BASE_URL`（或同域反代）配置正确；验证代理页能实时收到 `/ws/proxy-events` 推送。
[] 产物体积告警（chunk > 500KB）：按路由/页面做动态拆分，验证首屏与交互性能。

## 后端（backend）
[]（本机单人可忽略）生产环境收紧 CORS：移除 `*`，与 `allow_credentials` 保持一致，仅允许实际前端域名。
[]（本机单人可忽略）设置并校验 `SECRET_KEY`（禁止使用默认值 `your-secret-key-here-change-in-production`），确认 JWT 过期策略符合生产需求。
[] `/api/v1/health` 返回的 `timestamp` 目前为硬编码：改为实时生成时间。
[]（本机单人可忽略）为敏感接口加保护/隔离：`/api/v1/proxy/*`（启动/停止/证书安装/防火墙）、`/api/v1/terminal/*`、`/api/v1/native_hook/*` 等至少限制为内网/localhost 或增加鉴权与权限控制。
[] 运行方式确认：`RecorderService`/`ProxyServiceManager` 为进程内单例；生产不要多 worker（或改为共享存储/队列/分布式锁）。
[] `HybridStorage`（JSON 文件）并发写入存在损坏风险：增加文件锁/原子写/迁移到 DB，避免多请求/崩溃导致数据损坏。
[] Playwright 依赖：生产机预装并执行 `playwright install`（或配置 `use_system_chrome/chrome_path`）；验证录制链路可用。
[] 依赖锁定与兼容性：已添加 `bcrypt<4`（用于 passlib/mitmproxy 兼容），建议补充 constraints/锁文件并在干净环境全量安装验证。

## 冒烟/回归（建议上线前必做）
[] 前端：`npm run lint`、`npm run type-check`、`npm run build` 全部通过（最好放进 CI）。
[] 后端：启动后验证 `/health`、`/api/v1/proxy/status`、`/api/v1/crawler/sessions`；WebSocket（`/ws/{client_id}` 与 `/ws/proxy-events`）连通；代理抓包与导出（HAR/CSV）做一次真实流量验证。
