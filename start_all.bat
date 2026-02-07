@echo off
chcp 65001 >nul
title Web Analyzer V2 - 一键启动

echo ========================================
echo   Web Analyzer V2 - 启动所有服务
echo ========================================
echo.

REM 加载 .env 变量
if exist ".env" (
    for /f "tokens=1,2 delims==" %%a in ('type .env ^| findstr /v "^#" ^| findstr "="') do (
        set "%%a=%%b"
    )
)
if "%BACKEND_PORT%"=="" set BACKEND_PORT=8000
if "%FRONTEND_PORT%"=="" set FRONTEND_PORT=3000
if "%TERMINAL_SERVICE_PORT%"=="" set TERMINAL_SERVICE_PORT=3001

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

echo [1/3] 启动后端服务 (端口 %BACKEND_PORT%)...
start "Backend Server" cmd /k "cd /d %~dp0backend && venv\Scripts\python.exe -m app.main"
timeout /t 2 /nobreak >nul

echo [2/3] 启动前端服务 (端口 %FRONTEND_PORT%)...
start "Frontend Dev Server" cmd /k "cd /d %~dp0frontend && npx vite --host 0.0.0.0 --port %FRONTEND_PORT%"
timeout /t 2 /nobreak >nul

echo [3/3] 启动 AI 终端服务 (端口 %TERMINAL_SERVICE_PORT%)...
if exist "backend\terminal_service\package.json" (
    start "Terminal-Service" cmd /k "cd /d %~dp0backend\terminal_service && set PORT=%TERMINAL_SERVICE_PORT%&& npm start"
) else (
    echo [提示] 未找到 backend\terminal_service，跳过
)

REM 获取本机IP地址
set "LOCAL_IP="
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /c:"IPv4"') do (
    for /f "tokens=1" %%j in ("%%i") do (
        if not defined LOCAL_IP set "LOCAL_IP=%%j"
    )
)
if not defined LOCAL_IP set "LOCAL_IP=127.0.0.1"

echo.
echo ========================================
echo   所有服务已启动
echo ========================================
echo.
echo 前端服务:
echo   - localhost: http://localhost:%FRONTEND_PORT%
echo   - 127.0.0.1: http://127.0.0.1:%FRONTEND_PORT%
echo   - 局域网:     http://%LOCAL_IP%:%FRONTEND_PORT%
echo.
echo 后端服务:
echo   - localhost: http://localhost:%BACKEND_PORT%
echo   - 127.0.0.1: http://127.0.0.1:%BACKEND_PORT%
echo   - 局域网:     http://%LOCAL_IP%:%BACKEND_PORT%
echo.
echo AI终端服务:
echo   - localhost: http://localhost:%TERMINAL_SERVICE_PORT%
echo   - 127.0.0.1: http://127.0.0.1:%TERMINAL_SERVICE_PORT%
echo   - 局域网:     http://%LOCAL_IP%:%TERMINAL_SERVICE_PORT%
echo.
echo API文档:
echo   - localhost: http://localhost:%BACKEND_PORT%/docs
echo   - 127.0.0.1: http://127.0.0.1:%BACKEND_PORT%/docs
echo   - 局域网:     http://%LOCAL_IP%:%BACKEND_PORT%/docs
echo.
echo 按任意键关闭此窗口...
pause >nul
