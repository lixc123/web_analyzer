# Web分析工具 API文档

## 📚 目录

- [代理抓包API](#代理抓包api)
- [爬虫录制API](#爬虫录制api)
- [数据分析API](#数据分析api)
- [代码生成API](#代码生成api)
- [请求录制API](#请求录制api)
- [Native Hook API](#native-hook-api)
- [任务队列API](#任务队列api)

---

## 代理抓包API

### 启动代理服务
```http
POST /api/v1/proxy/start
Content-Type: application/json

{
  "port": 8080,
  "enable_https": true
}
```

**响应：**
```json
{
  "status": "started",
  "port": 8080,
  "local_ip": "192.168.1.100"
}
```

### 停止代理服务
```http
POST /api/v1/proxy/stop
```

### 获取代理状态
```http
GET /api/v1/proxy/status
```

**响应：**
```json
{
  "running": true,
  "port": 8080,
  "requests_captured": 1234,
  "uptime_seconds": 3600
}
```

### 获取请求列表
```http
GET /api/v1/proxy/requests?limit=100&offset=0
```

**响应：**
```json
{
  "requests": [
    {
      "id": "req_123",
      "method": "GET",
      "url": "https://api.example.com/data",
      "status_code": 200,
      "timestamp": 1234567890
    }
  ],
  "total": 1234
}
```

### 下载CA证书
```http
GET /api/v1/proxy/cert/download
```

---

## 爬虫录制API

### 启动爬虫会话
```http
POST /api/v1/crawler/start
Content-Type: application/json

{
  "url": "https://example.com",
  "browser": "chromium",
  "headless": false,
  "record_requests": true
}
```

**响应：**
```json
{
  "session_id": "session_abc123",
  "status": "started",
  "browser_url": "https://example.com"
}
```

### 停止爬虫会话
```http
POST /api/v1/crawler/stop/{session_id}
```

### 获取会话请求
```http
GET /api/v1/crawler/requests/{session_id}?limit=100
```

**响应：**
```json
{
  "session_id": "session_abc123",
  "requests": [
    {
      "id": "req_456",
      "method": "POST",
      "url": "https://api.example.com/login",
      "headers": {...},
      "body": "...",
      "response": {...},
      "call_stack": [...]
    }
  ]
}
```

### 导出会话数据
```http
POST /api/v1/crawler/export/{session_id}
Content-Type: application/json

{
  "format": "json",
  "include_responses": true
}
```

---

## 数据分析API

### 分析网络请求
```http
POST /api/v1/analysis/analyze
Content-Type: application/json

{
  "session_id": "session_abc123",
  "analysis_types": ["entropy", "sensitive_params", "encryption_keywords"],
  "min_entropy": 4.5
}
```

**响应：**
```json
{
  "analysis_id": "analysis_789",
  "suspicious_requests": [...],
  "high_entropy_fields": [...],
  "sensitive_params": [...],
  "summary": {
    "total_analyzed": 100,
    "suspicious_count": 5
  }
}
```

### 熵值分析
```http
GET /api/v1/analysis/entropy/{session_id}?min_entropy=4.5
```

### 敏感参数分析
```http
GET /api/v1/analysis/sensitive-params/{session_id}
```

### 比较分析结果
```http
POST /api/v1/analysis/compare
Content-Type: application/json

["analysis_id1", "analysis_id2", "analysis_id3"]
```

**响应：**
```json
{
  "comparison": {
    "common_suspicious": [...],
    "unique_suspicious": {...},
    "summary": {
      "total_analyses": 3,
      "common_issues": 2
    }
  }
}
```

---

## 代码生成API

### 生成会话代码
```http
POST /api/v1/code-generator/generate
Content-Type: application/json

{
  "session_path": "/path/to/session",
  "include_js_analysis": true,
  "output_format": "python"
}
```

**响应：**
```json
{
  "success": true,
  "message": "成功生成代码，包含 25 个API请求",
  "code_preview": "import requests...",
  "file_path": "/path/to/generated_code.py",
  "stats": {
    "total_requests": 100,
    "api_requests": 25
  }
}
```

### 预览生成代码
```http
GET /api/v1/code-generator/preview/{session_name}
```

**响应：** 纯文本Python代码

### 下载生成代码
```http
GET /api/v1/code-generator/download/{session_name}
```

**响应：** 文件下载

### 获取会话统计
```http
GET /api/v1/code-generator/stats/{session_name}
```

**响应：**
```json
{
  "session_name": "example_session",
  "total_requests": 100,
  "api_requests_count": 25,
  "domains_count": 3,
  "methods": {
    "GET": 60,
    "POST": 40
  }
}
```

### 批量生成代码
```http
POST /api/v1/code-generator/batch-generate
Content-Type: application/json

["session1", "session2", "session3"]
```

**响应：**
```json
{
  "total_sessions": 3,
  "successful": ["session1", "session2"],
  "failed": [],
  "summary": {
    "success_count": 2,
    "failed_count": 0,
    "status": "批量任务已启动"
  }
}
```

---

## 请求录制API

### 开始录制
```http
POST /api/v1/request-analysis/start-recording
```

### 停止录制
```http
POST /api/v1/request-analysis/stop-recording
```

### 获取录制的请求
```http
GET /api/v1/request-analysis/requests?limit=100
```

### 重放请求
```http
POST /api/v1/request-analysis/replay-request
Content-Type: application/json

{
  "request_id": "req_123",
  "modify_headers": {
    "Authorization": "Bearer new_token"
  },
  "modify_body": null,
  "follow_redirects": true,
  "verify_ssl": true
}
```

**响应：**
```json
{
  "success": true,
  "status_code": 200,
  "response_body": "...",
  "duration_ms": 234
}
```

### 清空请求记录
```http
DELETE /api/v1/request-analysis/requests
```

---

## Native Hook API

### 获取进程列表
```http
GET /api/v1/native-hook/processes
```

**响应：**
```json
{
  "processes": [
    {
      "pid": 1234,
      "name": "example.exe",
      "path": "C:\\Program Files\\Example\\example.exe"
    }
  ]
}
```

### 附加到进程
```http
POST /api/v1/native-hook/attach
Content-Type: application/json

{
  "pid": 1234,
  "process_name": "example.exe"
}
```

**响应：**
```json
{
  "session_id": "hook_session_xyz",
  "pid": 1234,
  "status": "attached"
}
```

### 注入Frida脚本
```http
POST /api/v1/native-hook/inject-script/{session_id}
Content-Type: application/json

{
  "script": "console.log('Hello from Frida!');",
  "template_name": null
}
```

### 获取Hook记录
```http
GET /api/v1/native-hook/records?session_id=hook_session_xyz&limit=100
```

### 分离进程
```http
POST /api/v1/native-hook/detach/{session_id}
```

---

## 任务队列API

### 提交后台任务
```http
POST /api/v1/tasks/submit
Content-Type: application/json

{
  "task_type": "code_generation",
  "params": {
    "session_name": "example_session"
  }
}
```

**响应：**
```json
{
  "task_id": "task_abc123",
  "status": "pending",
  "created_at": "2024-01-20T10:00:00Z"
}
```

### 获取任务状态
```http
GET /api/v1/tasks/status/{task_id}
```

**响应：**
```json
{
  "task_id": "task_abc123",
  "status": "completed",
  "progress": 100,
  "result": {...},
  "error": null
}
```

### 取消任务
```http
DELETE /api/v1/tasks/cancel/{task_id}
```

### 列出所有任务
```http
GET /api/v1/tasks/list?status=running&limit=50
```

---

## 通用响应格式

### 成功响应
```json
{
  "success": true,
  "data": {...},
  "message": "操作成功"
}
```

### 错误响应
```json
{
  "detail": "错误描述信息",
  "status_code": 400
}
```

## HTTP状态码

- `200 OK` - 请求成功
- `201 Created` - 资源创建成功
- `400 Bad Request` - 请求参数错误
- `401 Unauthorized` - 未授权
- `404 Not Found` - 资源不存在
- `500 Internal Server Error` - 服务器内部错误

## 认证

部分API需要认证，在请求头中添加：
```http
Authorization: Bearer <your_token>
```

## 速率限制

- 普通API：100请求/分钟
- 分析API：20请求/分钟
- 批量操作：10请求/分钟

## WebSocket接口

### 代理请求实时推送
```
ws://localhost:8000/api/v1/proxy/ws
```

### 爬虫进度推送
```
ws://localhost:8000/api/v1/crawler/progress/{session_id}
```

---

## 示例代码

### Python示例
```python
import requests

# 启动代理
response = requests.post('http://localhost:8000/api/v1/proxy/start', json={
    'port': 8080,
    'enable_https': True
})
print(response.json())

# 获取请求列表
response = requests.get('http://localhost:8000/api/v1/proxy/requests?limit=10')
requests_data = response.json()
print(f"捕获了 {len(requests_data['requests'])} 个请求")
```

### JavaScript示例
```javascript
// 启动爬虫会话
const response = await fetch('http://localhost:8000/api/v1/crawler/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://example.com',
    browser: 'chromium',
    headless: false
  })
});

const data = await response.json();
console.log('会话ID:', data.session_id);
```

---

**版本：** v2.0
**更新时间：** 2024-01-20
**联系方式：** support@example.com
