# 下一阶段开发任务清单

> 基于已完成的8项核心功能，规划下一阶段的开发任务

## 已完成功能回顾 ✅

### 第一优先级（核心功能）- 5项
1. ✅ WebSocket Hook - 实时通信拦截
2. ✅ Crypto API Hook - 加密操作拦截
3. ✅ 存储数据完整导出 - localStorage/sessionStorage/Cookie/IndexedDB
4. ✅ 参数签名分析工具 - 自动识别签名算法
5. ✅ 应用状态捕获 - Redux/Vuex/Pinia状态管理

### 第二优先级（效率提升）- 3项
6. ✅ JavaScript代码美化器 - jsbeautifier集成
7. ✅ 请求依赖关系图 - 数据流分析
8. ✅ 自动重放验证工具 - 批量验证和失败诊断

---

## 第一优先级：前端集成（最重要！）🔥

**问题：** 已实现的后端API缺少对应的前端界面，用户无法使用这些强大功能。

### 1. 代码美化器UI集成 ✅
**重要性：高**

**已实现：**
- ✅ 在代码查看器中添加"美化代码"按钮
- ✅ 调用 `/api/v1/analysis/beautify-js` 接口
- ✅ 显示美化前后的代码对比
- ✅ 支持一键复制美化后的代码

**实现位置：**
- `frontend/src/components/RequestAnalysis/EnhancedRequestAnalysisPanel.tsx:248-272` - beautifyCode函数
- `frontend/src/components/RequestAnalysis/EnhancedRequestAnalysisPanel.tsx:741-760` - UI按钮和显示

**实现效果：**
- JavaScript代码查看器中添加了"美化代码"按钮
- 点击后调用后端API进行代码美化
- 美化后的代码自动显示在代码区域
- 支持loading状态显示

---

### 2. 依赖关系图可视化 ✅
**重要性：高**

**已实现：**
- ✅ 创建依赖关系图可视化组件
- ✅ 使用Cytoscape.js渲染图形
- ✅ 调用 `/api/v1/analysis/dependency-graph` 接口
- ✅ 支持节点点击查看请求详情
- ✅ 支持缩放和拖拽
- ✅ 添加重置视图功能

**实现位置：**
- `frontend/src/components/DependencyGraph/DependencyGraph.tsx` - 完整组件实现
- 使用Cytoscape.js进行图形渲染
- 支持节点选中和详情展示

**实现效果：**
- 使用breadthfirst布局算法展示依赖关系
- 节点点击弹出详情模态框
- 支持适应窗口、重置视图等操作
- 节点选中时高亮显示

---

### 3. 重放验证结果展示 ✅
**重要性：高**

**已实现：**
- ✅ 创建重放验证结果面板
- ✅ 调用 `/api/v1/analysis/replay-validate` 接口
- ✅ 显示验证统计（成功/失败数量）
- ✅ 展示每个请求的验证结果
- ✅ 高亮显示失败原因（token过期、签名错误等）
- ✅ 支持响应差异对比（原始 vs 重放）

**实现位置：**
- `frontend/src/components/ReplayValidator/ReplayValidator.tsx` - 完整组件实现
- 使用Ant Design的Statistic和Table组件展示验证结果

**实现效果：**
- 统计卡片显示总计、成功、失败数量
- 表格展示每个请求的验证详情
- 支持查看响应差异对比
- 失败原因标签高亮显示

---

### 4. 签名分析面板 ✅
**重要性：高**

**已实现：**
- ✅ 创建签名分析结果展示组件
- ✅ 集成 `SignatureAnalyzer` 到分析服务
- ✅ 显示识别的签名参数（sign、signature、token等）
- ✅ 展示算法提示（MD5、SHA256、HMAC等）
- ✅ 显示参数组合模式
- ✅ 添加API接口 `/api/v1/analysis/signature-analysis`

**实现位置：**
- `frontend/src/components/SignatureAnalysis/SignatureAnalysis.tsx` - 完整组件实现
- `backend/app/api/v1/analysis.py:297-307` - API接口
- `backend/utils/signature_analyzer.py` - 签名分析器

**实现效果：**
- 统计信息展示（分析请求数、识别参数数量）
- 签名参数表格（参数名、置信度、示例值）
- 时间戳参数表格
- 算法提示表格（算法类型、置信度、特征指标）
  • sign (置信度: 100%)
  • timestamp (置信度: 95%)
  • nonce (置信度: 90%)

算法提示:
  • sign: MD5 (长度32, 十六进制)

参数组合:
  • sign = MD5(timestamp + nonce + secret)
```

---

### 5. 状态管理数据查看器 ✅
**重要性：中高**

**已实现：**
- ✅ 创建状态数据查看器组件
- ✅ 展示Redux/Vuex/Pinia捕获的状态数据
- ✅ 支持状态树展开/折叠
- ✅ 支持导出状态数据

**实现位置：**
- `frontend/src/components/StateViewer/StateViewer.tsx` - 完整组件实现
- 使用Ant Design Tree组件展示状态树结构

**实现效果：**
- 递归转换状态对象为树形结构
- 支持展开/折叠节点
- 显示对象、数组、基本类型
- 一键导出JSON格式状态数据

---

### 6. WebSocket消息查看器 ✅
**重要性：中高**

**已实现：**
- ✅ 创建WebSocket消息流查看器
- ✅ 实时展示WebSocket消息
- ✅ 区分发送/接收消息
- ✅ 支持消息过滤（按方向）
- ✅ 支持消息搜索
- ✅ 支持消息导出

**实现位置：**
- `frontend/src/components/WebSocketViewer/WebSocketViewer.tsx` - 完整组件实现

**实现效果：**
- 表格展示消息列表（方向、时间、连接、内容）
- 发送/接收消息图标区分
- 搜索框过滤消息内容
- 下拉框过滤消息方向

---

### 7. Crypto操作日志查看器 ✅
**重要性：中**

**已实现：**
- ✅ 创建加密操作日志组件
- ✅ 展示所有crypto.subtle操作
- ✅ 显示算法、数据大小、结果预览
- ✅ 支持按操作类型过滤（encrypt/decrypt/sign/verify/digest）
- ✅ 支持导出加密日志

**实现位置：**
- `frontend/src/components/CryptoLogger/CryptoLogger.tsx` - 完整组件实现

**实现效果：**
- 表格展示加密操作（操作类型、时间、算法、数据大小、结果预览）
- 操作类型图标标识（加密/解密/签名等）
- 下拉框过滤操作类型
- 分页展示操作记录

---

## 第二优先级：高级过滤和搜索 🟡

**问题：** 当请求数量达到数百上千时，需要强大的过滤和搜索功能。

### 8. 高级过滤器 ✅
**重要性：中高**

**已实现：**
- ✅ 多条件组合过滤
- ✅ 按URL模式过滤（支持通配符和正则）
- ✅ 按请求方法过滤（GET/POST/PUT/DELETE等）
- ✅ 按响应状态码过滤（2xx/3xx/4xx/5xx）
- ✅ 按时间范围过滤
- ✅ 按请求大小过滤
- ✅ 按响应时间过滤
- ✅ 保存过滤条件为预设

**实现位置：**
- `frontend/src/components/AdvancedFilter/AdvancedFilter.tsx` - 完整组件实现

**实现效果：**
- 表单式多条件过滤界面
- 支持URL模式匹配（包含/通配符/正则）
- 时间范围选择器
- 请求大小和响应时间范围输入
- 预设保存和加载功能

---

### 9. 全文搜索 ✅
**重要性：中高**

**已实现：**
- ✅ 搜索请求URL
- ✅ 搜索请求/响应Headers
- ✅ 搜索请求/响应Body
- ✅ 搜索Cookie
- ✅ 支持正则表达式搜索
- ✅ 高亮搜索结果
- ✅ 显示匹配数量

**实现位置：**
- `frontend/src/components/EnhancedSearch/EnhancedSearch.tsx` - 完整组件实现

**实现效果：**
- 统一搜索输入框
- 文本/正则模式切换
- 多范围搜索（URL/Headers/Body/Cookie）
- 搜索结果高亮显示
- 匹配计数显示

---

## 第三优先级：请求编辑和重发 🟢

**问题：** 需要手动测试API的能力，类似Burp Suite的Repeater功能。

### 10. 请求编辑器 ✅
**重要性：中**

**已实现：**
- ✅ 编辑请求URL
- ✅ 编辑请求Headers
- ✅ 编辑请求Body
- ✅ 编辑请求参数
- ✅ 一键重发请求
- ✅ 显示重发结果
- ✅ 支持多次重发对比

**实现位置：**
- `frontend/src/components/RequestEditor/RequestEditor.tsx` - 完整组件实现

**实现效果：**
- 类似Burp Suite的Repeater功能
- 方法选择器（GET/POST/PUT/DELETE/PATCH）
- Headers和Body编辑器（JSON格式）
- 发送按钮和响应展示
- 复制为cURL命令功能

---

### 11. 批量参数替换 ✅
**重要性：中**

**已实现：**
- ✅ 批量替换token
- ✅ 批量替换签名参数
- ✅ 批量替换时间戳
- ✅ 支持正则表达式替换
- ✅ 预览替换结果

**实现位置：**
- `frontend/src/components/BatchReplace/BatchReplace.tsx` - 完整组件实现

**实现效果：**
- 添加替换规则（字段名、匹配模式、替换值）
- 正则表达式开关
- 规则启用/禁用切换
- 替换预览功能
- 规则列表管理

---

### 12. 请求模板 🟢
**重要性：中低**

**需要实现：**
- 保存请求为模板
- 管理模板库
- 从模板创建请求
- 模板参数化

**实现位置：**
- `frontend/src/components/RequestTemplate/` - 新建组件
- `backend/app/models/template.py` - 模板数据模型

---

## 第四优先级：完整报告导出 🟢

### 13. PDF报告生成 🟢
**重要性：中**

**需要实现：**
- 生成包含所有分析结果的PDF报告
- 包含请求统计、签名分析、依赖关系图等
- 支持自定义报告模板
- 支持添加注释和标记

**实现位置：**
- `backend/utils/report_generator.py` - 新建报告生成器
- 使用库：reportlab 或 weasyprint

---

### 14. HTML报告 🟢
**重要性：中低**

**需要实现：**
- 生成可分享的HTML报告
- 包含交互式图表
- 支持离线查看

**实现位置：**
- `backend/utils/html_report_generator.py` - 新建HTML报告生成器

---

### 15. Markdown报告 🟢
**重要性：中低**

**需要实现：**
- 生成Markdown格式报告
- 便于文档化和版本控制
- 支持导入到文档系统

**实现位置：**
- `backend/utils/markdown_report_generator.py` - 新建Markdown报告生成器

---

## 第五优先级：性能优化 🟢

### 16. 虚拟滚动 🟢
**重要性：中**

**需要实现：**
- 请求列表虚拟滚动
- 只渲染可见区域的请求
- 提升大数据量时的性能

**实现位置：**
- `frontend/src/components/RequestList/` - 使用react-window或react-virtualized

---

### 17. 数据分页 🟢
**重要性：中**

**需要实现：**
- 后端分页API
- 前端分页组件
- 按需加载数据

**实现位置：**
- `backend/app/api/v1/` - 添加分页参数
- `frontend/src/components/Pagination/` - 分页组件

---

### 18. 数据库索引优化 🟢
**重要性：中**

**需要实现：**
- 为常用查询字段添加索引
- 优化查询性能
- 分析慢查询

**实现位置：**
- `backend/app/models/` - 数据模型添加索引
- `backend/alembic/versions/` - 数据库迁移

---

## 实施建议

### 第一阶段（最优先）
专注于**前端集成**（功能1-7），让已实现的后端功能可用：
1. 代码美化器UI
2. 依赖关系图可视化
3. 重放验证结果展示
4. 签名分析面板

### 第二阶段
实现**高级过滤和搜索**（功能8-9），提升大数据量场景的可用性。

### 第三阶段
实现**请求编辑和重发**（功能10-12），增强手动测试能力。

### 第四阶段
根据实际需求选择性实现报告导出和性能优化功能。

---

## 技术栈建议

### 前端
- **图形可视化：** Cytoscape.js（依赖关系图）
- **代码编辑器：** Monaco Editor（请求编辑器）
- **虚拟滚动：** react-window
- **状态管理：** 已有的状态管理方案

### 后端
- **PDF生成：** reportlab 或 weasyprint
- **数据分页：** SQLAlchemy分页支持
- **全文搜索：** 可考虑集成Elasticsearch（可选）

---

*文档创建时间: 2026-01-20*
*基于已完成的8项核心功能规划*
