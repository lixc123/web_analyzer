import React, { useRef, useEffect, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { Button, Space, Tooltip } from 'antd';
import { 
  PlayCircleOutlined, 
  PauseCircleOutlined, 
  ClearOutlined, 
  FullscreenOutlined,
  SyncOutlined
} from '@ant-design/icons';

interface QwenTerminalProps {
  // 简化接口，不再需要会话相关的props
}

const QwenTerminal: React.FC<QwenTerminalProps> = () => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const websocket = useRef<WebSocket | null>(null);
  
  const [isConnected, setIsConnected] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // 初始化终端
  useEffect(() => {
    if (!terminalRef.current) return;

    // 创建终端实例
    terminal.current = new Terminal({
      rows: 30,
      cols: 120,
      theme: {
        background: '#1e1e1e',
        foreground: '#d4d4d4',
        cursor: '#ffffff',
        selectionBackground: '#264f78'
      },
      fontFamily: 'Consolas, "Courier New", monospace',
      fontSize: 14,
      cursorBlink: true,
      scrollback: 10000
    });

    // 添加插件
    fitAddon.current = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    
    terminal.current.loadAddon(fitAddon.current);
    terminal.current.loadAddon(webLinksAddon);

    // 打开终端
    terminal.current.open(terminalRef.current);
    
    // 适应容器大小
    fitAddon.current.fit();

    // 监听输入
    terminal.current.onData((data) => {
      if (websocket.current && websocket.current.readyState === WebSocket.OPEN) {
        websocket.current.send(data);
      }
    });

    // 窗口大小改变时重新适应
    const handleResize = () => {
      setTimeout(() => {
        fitAddon.current?.fit();
      }, 100);
    };
    
    window.addEventListener('resize', handleResize);
    
    // 显示欢迎消息
    terminal.current.writeln('\x1b[36m=== Qwen Code 终端 ===\x1b[0m');
    terminal.current.writeln('\x1b[33m正在连接到 CLI...\x1b[0m');
    
    return () => {
      window.removeEventListener('resize', handleResize);
      websocket.current?.close();
      terminal.current?.dispose();
    };
  }, []);

  // 建立 WebSocket 连接
  const connectToQwen = () => {
    if (websocket.current?.readyState === WebSocket.OPEN) {
      return;
    }

    // 简化 WebSocket URL，不依赖会话
    const wsUrl = 'ws://localhost:8000/ws/qwen-cli';
    
    websocket.current = new WebSocket(wsUrl);
    
    websocket.current.onopen = () => {
      setIsConnected(true);
      terminal.current?.writeln('\r\n\x1b[32m✓ 已连接到 Qwen CLI\x1b[0m\r\n');
    };
    
    websocket.current.onmessage = (event) => {
      try {
        // 尝试解析 JSON 消息
        const data = JSON.parse(event.data);
        if (data.type === 'output' && data.data) {
          terminal.current?.write(data.data);
        } else if (data.type === 'error') {
          terminal.current?.writeln(`\r\n\x1b[31m错误: ${data.message}\x1b[0m\r\n`);
        } else if (data.type === 'connected') {
          terminal.current?.writeln(`\r\n\x1b[32m✓ CLI 已启动 (${data.cli_path})\x1b[0m\r\n`);
        } else if (data.type === 'disconnected') {
          terminal.current?.writeln(`\r\n\x1b[33m✗ ${data.message}\x1b[0m\r\n`);
        }
      } catch (error) {
        // 如果不是 JSON，直接显示
        terminal.current?.write(event.data);
      }
    };
    
    websocket.current.onerror = (error) => {
      console.error('WebSocket 错误:', error);
      terminal.current?.writeln('\r\n\x1b[31m✗ 连接失败\x1b[0m\r\n');
    };
    
    websocket.current.onclose = () => {
      setIsConnected(false);
      terminal.current?.writeln('\r\n\x1b[33m✗ 连接已断开\x1b[0m\r\n');
    };
  };

  // 断开连接
  const disconnect = () => {
    if (websocket.current) {
      websocket.current.close();
      setIsConnected(false);
    }
  };

  // 清空终端
  const clearTerminal = () => {
    terminal.current?.clear();
    terminal.current?.writeln('\x1b[36m=== Qwen Code 终端 ===\x1b[0m');
  };

  // 发送命令
  const sendCommand = (command: string) => {
    if (websocket.current && websocket.current.readyState === WebSocket.OPEN) {
      websocket.current.send(command + '\r');
    }
  };

  // 全屏切换
  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
    setTimeout(() => {
      fitAddon.current?.fit();
    }, 100);
  };

  // 初始连接
  useEffect(() => {
    const timer = setTimeout(() => {
      connectToQwen();
    }, 500);

    return () => clearTimeout(timer);
  }, []);

  return (
    <div className={`qwen-terminal ${isFullscreen ? 'fullscreen' : ''}`}>
      <div className="terminal-header">
        <div className="terminal-info">
          <span className="connection-status">
            {isConnected ? (
              <><span className="status-dot connected"></span> 已连接</>
            ) : (
              <><span className="status-dot disconnected"></span> 未连接</>
            )}
          </span>
        </div>
        
        <Space className="terminal-controls">
          <Tooltip title="连接/断开">
            <Button
              icon={isConnected ? <PauseCircleOutlined /> : <PlayCircleOutlined />}
              onClick={isConnected ? disconnect : connectToQwen}
              type={isConnected ? "default" : "primary"}
              size="small"
            />
          </Tooltip>
          
          <Tooltip title="清空终端">
            <Button
              icon={<ClearOutlined />}
              onClick={clearTerminal}
              size="small"
            />
          </Tooltip>
          
          <Tooltip title="刷新连接">
            <Button
              icon={<SyncOutlined />}
              onClick={() => {
                disconnect();
                setTimeout(connectToQwen, 500);
              }}
              size="small"
            />
          </Tooltip>
          
          <Tooltip title="全屏">
            <Button
              icon={<FullscreenOutlined />}
              onClick={toggleFullscreen}
              size="small"
            />
          </Tooltip>
        </Space>
      </div>
      
      <div 
        ref={terminalRef} 
        className="terminal-container"
        style={{ 
          height: isFullscreen ? 'calc(100vh - 60px)' : 'calc(100% - 50px)',
          width: '100%'
        }}
      />
      
      <div className="terminal-footer">
        <div className="quick-commands">
          <Space wrap>
            <Button 
              size="small" 
              onClick={() => sendCommand('help')}
              disabled={!isConnected}
            >
              帮助
            </Button>
            <Button 
              size="small" 
              onClick={() => sendCommand('ls')}
              disabled={!isConnected}
            >
              列表
            </Button>
            <Button 
              size="small" 
              onClick={() => sendCommand('pwd')}
              disabled={!isConnected}
            >
              路径
            </Button>
          </Space>
        </div>
        <div className="terminal-tips">
          <span>提示: 直接输入命令，Ctrl+C 中断</span>
        </div>
      </div>
    </div>
  );
};

export default QwenTerminal;
