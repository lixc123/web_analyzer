# Qwen Code Web Terminal

实时将Qwen Code CLI界面流式传输到web浏览器，保持原始界面完全不变。

## 技术方案

- **xterm.js**: 浏览器端终端模拟器
- **node-pty**: 后端伪终端，运行真实的qwen CLI
- **Socket.IO**: WebSocket实时双向通信
- **Express**: Web服务器

## 安装运行

1. 安装Node.js依赖:
```bash
npm install
```

2. 下载xterm.js文件:
```bash
node setup.js
```

3. 启动服务器:
```bash
npm start
```

4. 访问: http://localhost:3000

## 工作原理

1. 浏览器连接到Node.js服务器
2. 服务器使用node-pty创建真实的终端进程
3. 自动运行`qwen`命令
4. 所有终端输出通过WebSocket实时传输到浏览器
5. 用户输入通过WebSocket发送回终端进程
6. xterm.js在浏览器中完美渲染原始CLI界面

## 特点

- 🎯 **完全原生**: 直接运行真实的qwen CLI，不修改任何原有逻辑  
- ⚡ **实时同步**: WebSocket确保输入输出实时传输
- 🎨 **原样呈现**: ASCII艺术、颜色、格式完全保持
- 📱 **响应式**: 支持终端窗口大小调整
