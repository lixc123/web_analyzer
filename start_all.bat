@echo off
chcp 65001 >nul
title Web Analyzer V2 - 一键启动

echo ========================================
echo   Web Analyzer V2 - 启动所有服务
echo ========================================
echo.

REM 检查后端虚拟环境
if not exist "backend\venv\Scripts\python.exe" (
    echo [错误] 未找到后端虚拟环境，请先运行 scripts\setup_and_start.bat
    pause
    exit /b 1
)

REM 检查前端依赖
if not exist "frontend\node_modules" (
    echo [错误] 未找到前端依赖，请先在 frontend 目录运行 npm install
    pause
    exit /b 1
)

echo [1/3] 启动后端服务 (端口 8000)...
start "Backend Server" cmd /k "cd /d %~dp0backend && venv\Scripts\python.exe -m app.main"
timeout /t 2 /nobreak >nul

echo [2/3] 启动前端服务 (端口 3000)...
start "Frontend Dev Server" cmd /k "cd /d %~dp0frontend && npm run dev"
timeout /t 2 /nobreak >nul

echo [3/3] 检查 Qwen-Code 服务 (端口 3001)...
if exist "qwen-code\server.py" (
    start "Qwen-Code Server" cmd /k "cd /d %~dp0qwen-code && python server.py"
) else (
    echo [提示] 未找到 Qwen-Code 服务，跳过
)

echo.
echo ========================================
echo   所有服务已启动
echo ========================================
echo.
echo 后端服务: http://localhost:8000
echo 前端服务: http://localhost:3000
echo API文档: http://localhost:8000/docs
echo.
echo 按任意键关闭此窗口...
pause >nul
