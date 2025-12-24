@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================
echo    Web Analyzer V2 - 停止服务脚本
echo ========================================
echo.

:: 停止后端FastAPI服务
echo [信息] 正在停止后端服务...
for /f "tokens=2" %%i in ('tasklist /fi "WindowTitle eq Backend-FastAPI" /fo table /nh 2^>nul') do (
    if not "%%i"=="" (
        taskkill /f /pid %%i >nul 2>&1
        echo [信息] 后端服务已停止 (PID: %%i)
    )
)

:: 停止前端React服务
echo [信息] 正在停止前端服务...
for /f "tokens=2" %%i in ('tasklist /fi "WindowTitle eq Frontend-React" /fo table /nh 2^>nul') do (
    if not "%%i"=="" (
        taskkill /f /pid %%i >nul 2>&1
        echo [信息] 前端服务已停止 (PID: %%i)
    )
)

:: 停止Qwen-Code服务
echo [信息] 正在停止Qwen-Code服务...
for /f "tokens=2" %%i in ('tasklist /fi "WindowTitle eq Qwen-Code-Service" /fo table /nh 2^>nul') do (
    if not "%%i"=="" (
        taskkill /f /pid %%i >nul 2>&1
        echo [信息] Qwen-Code服务已停止 (PID: %%i)
    )
)

:: 停止所有相关的Node.js进程 (如果有遗漏)
for /f "tokens=2" %%i in ('tasklist /fi "imagename eq node.exe" /fo table /nh 2^>nul') do (
    if not "%%i"=="" (
        :: 检查是否是我们的服务端口
        netstat -ano | findstr :3000 | findstr %%i >nul 2>&1
        if !errorlevel! == 0 (
            taskkill /f /pid %%i >nul 2>&1
            echo [信息] Node.js服务已停止 (PID: %%i, Port: 3000)
        )
        netstat -ano | findstr :3001 | findstr %%i >nul 2>&1
        if !errorlevel! == 0 (
            taskkill /f /pid %%i >nul 2>&1
            echo [信息] Node.js服务已停止 (PID: %%i, Port: 3001)
        )
    )
)

:: 停止Python uvicorn进程
for /f "tokens=2" %%i in ('tasklist /fi "imagename eq python.exe" /fo table /nh 2^>nul') do (
    if not "%%i"=="" (
        netstat -ano | findstr :8000 | findstr %%i >nul 2>&1
        if !errorlevel! == 0 (
            taskkill /f /pid %%i >nul 2>&1
            echo [信息] Python/FastAPI服务已停止 (PID: %%i, Port: 8000)
        )
    )
)

:: 清理临时文件
echo [信息] 清理临时文件...
cd /d "%~dp0.."
if exist "logs\*.tmp" del /q "logs\*.tmp" >nul 2>&1
if exist "temp\*.*" del /q "temp\*.*" >nul 2>&1

echo.
echo ========================================
echo         所有服务已停止
echo ========================================
echo.
echo 如需重新启动服务，请运行 setup_and_start.bat
pause
