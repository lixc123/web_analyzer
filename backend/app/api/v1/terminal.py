from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from typing import List, Dict, Any
import os
import json
from pathlib import Path

router = APIRouter()

@router.get("/sessions")
async def get_crawler_sessions() -> List[Dict[str, Any]]:
    """获取所有爬虫会话目录"""
    sessions = []
    
    # 获取项目根目录
    project_root = Path(__file__).parent.parent.parent.parent.parent
    
    # 直接扫描 data/sessions 目录下的会话文件夹
    sessions_dir = project_root / "data" / "sessions"
    
    if sessions_dir.exists():
        try:
            for item in sessions_dir.iterdir():
                if item.is_dir():
                    # 获取会话创建时间和文件数量
                    try:
                        # 从文件夹名称解析时间戳
                        if item.name.startswith("session_"):
                            timestamp_str = item.name.replace("session_", "")
                            # 尝试解析时间戳格式 YYYYMMDD_HHMMSS
                            if len(timestamp_str) >= 15:
                                date_part = timestamp_str[:8]  # YYYYMMDD
                                time_part = timestamp_str[9:15] if len(timestamp_str) > 8 else "000000"  # HHMMSS
                                formatted_time = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]} {time_part[:2]}:{time_part[2:4]}:{time_part[4:6]}"
                            else:
                                formatted_time = "未知时间"
                        else:
                            formatted_time = "未知时间"

                        sessions.append({
                            "name": item.name,
                            "description": f"会话时间: {formatted_time}",
                            "path": str(item.absolute()),
                            "type": "crawler_session",
                        })
                    except Exception:
                        # 如果解析失败，使用基本信息
                        sessions.append({
                            "name": item.name,
                            "description": "爬虫会话目录",
                            "path": str(item.absolute()),
                            "type": "crawler_session",
                        })
        except (PermissionError, OSError) as e:
            print(f"扫描会话目录失败: {e}")
    
    # 如果没有找到会话，添加一些默认目录
    if not sessions:
        default_dirs = [
            (project_root, "🏠 项目根目录", "当前web_analyzer_v2项目"),
            (Path.home() / "Desktop", "🖥️ 桌面目录", "用户桌面"),
        ]
        
        for dir_path, name, desc in default_dirs:
            if dir_path.exists():
                sessions.append({
                    "name": name,
                    "description": desc,
                    "path": str(dir_path.absolute()),
                    "type": "default_directory",
                })
    
    # 按时间倒序排列（最新的在前面）
    sessions.sort(key=lambda x: (
        0 if x["type"] == "crawler_session" else 1,  # 爬虫会话优先
        x["name"]  # 按名称排序，session_开头的自然按时间排序
    ), reverse=True)
    
    return sessions

@router.get("/page")
async def terminal_page() -> HTMLResponse:
    """返回终端页面"""
    html_content = """
    <!DOCTYPE html>
    <html lang="zh">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Qwen Code 终端</title>
        <style>
            body {
                margin: 0;
                padding: 0;
                background-color: #1a1a1a;
                overflow: hidden;
                font-family: 'Courier New', monospace;
            }
            
            .control-panel {
                background: #2a2a2a;
                color: white;
                padding: 10px 20px;
                display: flex;
                align-items: center;
                gap: 15px;
                border-bottom: 1px solid #444;
                height: 60px;
                box-sizing: border-box;
            }
            
            .control-panel label {
                font-size: 14px;
                color: #ccc;
                min-width: 80px;
            }
            
            .control-panel select {
                background: #1a1a1a;
                border: 1px solid #555;
                color: white;
                padding: 8px 12px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                min-width: 300px;
            }
            
            .control-panel select option {
                background: #1a1a1a;
                color: white;
            }
            
            .control-panel button {
                background: #4a9eff;
                border: none;
                color: white;
                padding: 8px 16px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 12px;
                transition: background-color 0.2s;
            }
            
            .control-panel button:hover {
                background: #357abd;
            }
            
            .control-panel button:disabled {
                background: #555;
                cursor: not-allowed;
            }
            
            .terminal-container {
                width: 100vw;
                height: calc(100vh - 60px);
                position: relative;
            }
            
            .terminal-frame {
                width: 100%;
                height: 100%;
                border: none;
                background-color: #1a1a1a;
            }
            
            .loading {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                color: #4a9eff;
                text-align: center;
                z-index: 1000;
            }
            
            .error {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                color: #e74c3c;
                text-align: center;
                z-index: 1000;
                display: none;
            }
            
            .status {
                font-size: 12px;
                color: #888;
                margin-left: auto;
            }
        </style>
    </head>
    <body>
        <div class="control-panel">
            <label>选择会话:</label>
            <select id="session-select">
                <option value="">正在加载会话...</option>
            </select>
            <button id="switch-btn" onclick="switchToSession()" disabled>切换到此会话</button>
            <div class="status" id="status">正在连接...</div>
        </div>
        
        <div class="terminal-container">
            <div id="loading" class="loading">
                <div>正在连接终端服务...</div>
                <div style="margin-top: 10px; font-size: 12px; opacity: 0.7;">
                    Node.js 终端服务: localhost:3001
                </div>
            </div>
            
            <div id="error" class="error">
                <div>❌ 无法连接到终端服务</div>
                <div style="margin: 10px 0; font-size: 14px;">
                    请确保 Node.js 终端服务正在端口 3001 运行
                </div>
                <button onclick="retryConnection()" style="background: #4a9eff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">重试连接</button>
            </div>
            
            <iframe id="terminal-frame" class="terminal-frame" src="http://localhost:3001" style="display: none;"></iframe>
        </div>

        <script>
            let loadTimeout;
            let terminalReady = false;
            let sessions = [];
            
            // 页面加载完成后初始化
            window.addEventListener('load', async function() {
                await loadSessions();
                setTimeout(loadTerminal, 1000);
            });
            
            async function loadSessions() {
                try {
                    const response = await fetch('/api/v1/terminal/sessions');
                    sessions = await response.json();
                    
                    const select = document.getElementById('session-select');
                    select.innerHTML = '<option value="">请选择一个会话...</option>';
                    
                    sessions.forEach(session => {
                        const option = document.createElement('option');
                        option.value = session.path;
                        option.textContent = `${session.name} - ${session.description}`;
                        select.appendChild(option);
                    });
                    
                    updateButtons();
                } catch (error) {
                    console.error('加载会话失败:', error);
                    document.getElementById('session-select').innerHTML = '<option value="">加载会话失败</option>';
                }
            }
            
            function updateButtons() {
                const sessionPath = document.getElementById('session-select').value;
                const switchBtn = document.getElementById('switch-btn');
                switchBtn.disabled = !terminalReady || !sessionPath;
            }
            
            function switchToSession() {
                const sessionPath = document.getElementById('session-select').value;
                if (!sessionPath || !terminalReady) return;
                
                updateStatus('正在切换会话...');

                const frame = document.getElementById('terminal-frame');
                if (frame && frame.contentWindow) {
                    try {
                        frame.contentWindow.postMessage({
                            type: 'switch-session',
                            path: sessionPath
                        }, '*');
                    } catch (e) {
                        console.log('无法发送切换会话到终端:', e);
                    }
                }

                setTimeout(() => {
                    updateStatus(`已切换到: ${sessionPath}`);
                }, 2000);
            }
            
            function sendCommandToTerminal(command) {
                const frame = document.getElementById('terminal-frame');
                if (frame && frame.contentWindow) {
                    try {
                        frame.contentWindow.postMessage({
                            type: 'command',
                            data: command === '\\x03' ? command : command + '\\r'
                        }, '*');
                    } catch (e) {
                        console.log('无法发送命令到终端:', e);
                    }
                }
            }
            
            function updateStatus(message) {
                document.getElementById('status').textContent = message;
            }
            
            function showLoading() {
                document.getElementById('loading').style.display = 'block';
                document.getElementById('error').style.display = 'none';
                document.getElementById('terminal-frame').style.display = 'none';
            }
            
            function showError() {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error').style.display = 'block';
                document.getElementById('terminal-frame').style.display = 'none';
            }
            
            function showTerminal() {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error').style.display = 'none';
                document.getElementById('terminal-frame').style.display = 'block';
                terminalReady = true;
                updateButtons();
                updateStatus('终端已连接');
            }
            
            function loadTerminal() {
                showLoading();
                
                const frame = document.getElementById('terminal-frame');
                
                if (loadTimeout) {
                    clearTimeout(loadTimeout);
                }
                
                frame.onload = function() {
                    console.log('Terminal iframe loaded successfully');
                    clearTimeout(loadTimeout);
                    showTerminal();
                };
                
                frame.onerror = function() {
                    console.log('Terminal iframe load error');
                    clearTimeout(loadTimeout);
                    showError();
                };
                
                loadTimeout = setTimeout(() => {
                    console.log('Terminal load timeout');
                    showError();
                }, 5000);
                
                frame.src = frame.src;
            }
            
            function retryConnection() {
                loadTerminal();
            }
            
            // 监听下拉框变化
            document.getElementById('session-select').addEventListener('change', updateButtons);
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@router.post("/switch-session")
async def switch_session(session_path: str):
    """切换到指定会话目录"""
    if not os.path.exists(session_path):
        raise HTTPException(status_code=404, detail="会话目录不存在")
    
    return {
        "success": True,
        "message": f"准备切换到会话: {session_path}",
        "path": session_path
    }
