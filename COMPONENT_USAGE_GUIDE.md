# 组件使用指南

**更新时间**: 2026-01-21  
**适用组件**: EnhancedRequestAnalysisPanel, DependencyGraph

---

## 📦 EnhancedRequestAnalysisPanel

### Props接口

```typescript
interface EnhancedRequestAnalysisPanelProps {
  sessionId?: string;        // 会话ID（推荐）
  sessionPath?: string;      // 会话路径（可选，优先使用）
  sessionName?: string;      // 会话名称（用于下载文件名）
}
```

### 使用方式

#### 方式1：只传sessionId（推荐）
```typescript
<EnhancedRequestAnalysisPanel sessionId="session_20240121_143000" />
```
**自动行为**:
- sessionPath自动构建为: `data/sessions/session_20240121_143000`
- sessionName使用sessionId: `session_20240121_143000`

#### 方式2：传完整信息（最佳）
```typescript
<EnhancedRequestAnalysisPanel 
  sessionId="session_20240121_143000"
  sessionPath="data/sessions/session_20240121_143000"
  sessionName="我的测试会话"
/>
```

#### 方式3：不传props（会提示）
```typescript
<EnhancedRequestAnalysisPanel />
```
**行为**: 点击生成/下载按钮时会提示"请确保已选择会话"

---

## 📊 DependencyGraph

### Props接口

```typescript
interface DependencyGraphProps {
  sessionId?: string;    // 会话ID（优先使用）
  requests?: any[];      // 请求数组（备选）
}
```

### 使用方式

#### 方式1：使用sessionId（推荐）
```typescript
<DependencyGraph sessionId="session_20240121_143000" />
```
**行为**: 从后端加载该会话的所有请求并生成依赖图

#### 方式2：直接传requests数组
```typescript
const requests = [
  { id: '1', method: 'GET', url: 'https://api.example.com/users' },
  { id: '2', method: 'POST', url: 'https://api.example.com/login' }
];

<DependencyGraph requests={requests} />
```
**行为**: 使用传入的请求数组生成依赖图

#### 方式3：同时传两个（sessionId优先）
```typescript
<DependencyGraph 
  sessionId="session_20240121_143000"
  requests={localRequests}
/>
```
**行为**: 优先使用sessionId，忽略requests

#### 方式4：不传props（显示提示）
```typescript
<DependencyGraph />
```
**行为**: 显示提示信息，按钮禁用

---

## 🎯 完整示例

### 示例1：Analysis页面

```typescript
import React, { useState } from 'react';
import EnhancedRequestAnalysisPanel from '@components/RequestAnalysis/EnhancedRequestAnalysisPanel';
import DependencyGraph from '@components/DependencyGraph';

const AnalysisPage: React.FC = () => {
  const [selectedSession, setSelectedSession] = useState<string>('session_20240121_143000');

  return (
    <div>
      <h1>数据分析</h1>
      
      {/* 请求分析面板 */}
      <EnhancedRequestAnalysisPanel 
        sessionId={selectedSession}
        sessionName={`分析会话-${selectedSession.slice(-8)}`}
      />
      
      {/* 依赖关系图 */}
      <DependencyGraph sessionId={selectedSession} />
    </div>
  );
};
```

### 示例2：AnalysisWorkbench页面

```typescript
import React, { useState, useEffect } from 'react';
import { Layout } from 'antd';
import SessionSelector from './components/SessionSelector';
import EnhancedRequestAnalysisPanel from '@components/RequestAnalysis/EnhancedRequestAnalysisPanel';
import DependencyGraph from '@components/DependencyGraph';

interface CrawlerSession {
  session_id: string;
  session_name: string;
  // ...
}

const AnalysisWorkbench: React.FC = () => {
  const [selectedSession, setSelectedSession] = useState<CrawlerSession | null>(null);
  const [requests, setRequests] = useState<any[]>([]);

  // 加载会话请求
  useEffect(() => {
    if (selectedSession) {
      loadSessionRequests(selectedSession.session_id);
    }
  }, [selectedSession]);

  const loadSessionRequests = async (sessionId: string) => {
    const response = await fetch(`/api/v1/crawler/session/${sessionId}/requests`);
    const data = await response.json();
    setRequests(data.requests || []);
  };

  return (
    <Layout>
      <Layout.Sider>
        <SessionSelector onSessionChange={setSelectedSession} />
      </Layout.Sider>
      
      <Layout.Content>
        {selectedSession ? (
          <>
            {/* 请求分析 - 使用完整信息 */}
            <EnhancedRequestAnalysisPanel
              sessionId={selectedSession.session_id}
              sessionPath={`data/sessions/${selectedSession.session_id}`}
              sessionName={selectedSession.session_name}
            />
            
            {/* 依赖图 - 可以用sessionId或requests */}
            <DependencyGraph 
              sessionId={selectedSession.session_id}
              // requests={requests}  // 也可以直接传requests
            />
          </>
        ) : (
          <div>请选择会话</div>
        )}
      </Layout.Content>
    </Layout>
  );
};
```

### 示例3：使用Context（推荐）

```typescript
// SessionContext.tsx
import React, { createContext, useContext, useState } from 'react';

interface SessionContextType {
  currentSession: {
    sessionId: string;
    sessionPath: string;
    sessionName: string;
  } | null;
  setCurrentSession: (session: any) => void;
}

const SessionContext = createContext<SessionContextType>({
  currentSession: null,
  setCurrentSession: () => {}
});

export const SessionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentSession, setCurrentSession] = useState(null);

  return (
    <SessionContext.Provider value={{ currentSession, setCurrentSession }}>
      {children}
    </SessionContext.Provider>
  );
};

export const useSession = () => useContext(SessionContext);

// 使用
import { useSession } from './SessionContext';

const MyComponent: React.FC = () => {
  const { currentSession } = useSession();

  return (
    <>
      {currentSession && (
        <>
          <EnhancedRequestAnalysisPanel 
            sessionId={currentSession.sessionId}
            sessionPath={currentSession.sessionPath}
            sessionName={currentSession.sessionName}
          />
          
          <DependencyGraph sessionId={currentSession.sessionId} />
        </>
      )}
    </>
  );
};
```

---

## ⚠️ 注意事项

### EnhancedRequestAnalysisPanel

1. **至少提供sessionId**
   ```typescript
   // ✅ 推荐
   <EnhancedRequestAnalysisPanel sessionId="xxx" />
   
   // ⚠️ 不推荐（会提示错误）
   <EnhancedRequestAnalysisPanel />
   ```

2. **sessionPath格式**
   ```typescript
   // ✅ 正确
   sessionPath="data/sessions/session_20240121"
   
   // ❌ 错误（缺少data/sessions前缀）
   sessionPath="session_20240121"
   ```

3. **sessionName用途**
   - 仅用于下载文件名
   - 不影响代码生成功能
   - 可以使用中文

### DependencyGraph

1. **优先级**
   ```typescript
   // sessionId优先于requests
   <DependencyGraph sessionId="xxx" requests={[...]} />
   // 实际使用sessionId，忽略requests
   ```

2. **requests格式**
   ```typescript
   // 至少需要这些字段
   const requests = [
     {
       id: string,
       method: string,
       url: string,
       // ... 其他字段
     }
   ];
   ```

3. **空数据处理**
   - 如果sessionId对应的会话没有请求，会显示提示
   - 如果requests数组为空，会显示提示
   - 不会报错，只是显示空图

---

## 🔍 调试技巧

### 检查Props是否正确传递

```typescript
const MyComponent: React.FC = () => {
  const sessionId = "session_20240121";
  
  console.log('传递给组件的sessionId:', sessionId);
  
  return (
    <EnhancedRequestAnalysisPanel 
      sessionId={sessionId}
      sessionPath={`data/sessions/${sessionId}`}
      sessionName={`会话-${sessionId}`}
    />
  );
};
```

### 检查API响应

```typescript
// 在浏览器控制台
fetch('/api/v1/code/generate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_path: 'data/sessions/session_20240121'
  })
})
.then(r => r.json())
.then(console.log);
```

### 检查依赖图数据

```typescript
// 在浏览器控制台
fetch('/api/v1/analysis/dependency-graph', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_id: 'session_20240121'
  })
})
.then(r => r.json())
.then(console.log);
```

---

## ✅ 快速检查清单

### 使用EnhancedRequestAnalysisPanel前

- [ ] 确认有sessionId或sessionPath
- [ ] 确认会话目录存在（`data/sessions/{sessionId}/`）
- [ ] 确认会话有requests.json文件
- [ ] 确认后端API `/api/v1/code/generate` 可访问

### 使用DependencyGraph前

- [ ] 确认有sessionId或requests数组
- [ ] 如果用sessionId，确认会话有足够的请求数据
- [ ] 如果用requests，确认数组不为空
- [ ] 确认后端API `/api/v1/analysis/dependency-graph` 可访问

---

## 📚 相关文档

- [HARDCODE_FIX_REPORT.md](./HARDCODE_FIX_REPORT.md) - 详细的修复报告
- [HARDCODE_ANALYSIS.md](./HARDCODE_ANALYSIS.md) - 问题分析文档
- [代码完整性分析报告.md](./代码完整性分析报告.md) - 完整的代码分析

---

**使用愉快！** 🎉
