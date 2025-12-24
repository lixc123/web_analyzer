@echo off

:: 如果是通过双击等方式以 cmd /c 启动，则自动切换到 cmd /k，避免窗口一闪而过
echo %cmdcmdline% | find /i "/c" >nul
if %errorlevel%==0 if /i "%~1" neq "__keep" (
    start "Web Analyzer V2 Starter" cmd /k ""%~f0" __keep"
    exit /b
)

chcp 65001 >nul
echo ========================================
echo       Web Analyzer V2 - 简化启动
echo ========================================
echo.

:: 设置项目根目录
cd /d "%~dp0.."

:: 检查.env文件
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo [信息] 已创建.env文件，请根据需要修改配置
        echo [警告] 请在.env文件中设置您的API密钥
    ) else (
        echo [错误] .env.example文件不存在，无法创建配置文件
        pause
        exit /b 1
    )
)

:: 加载环境变量（简化版）
set BACKEND_PORT=8000
set FRONTEND_PORT=3000

:: 创建必要目录
if not exist "data" mkdir data
if not exist "logs" mkdir logs

:: 快速检查Playwright浏览器（简化版）
echo [INFO] Quick browser check starting...
python check_browsers.py --auto-install --quiet >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Browser check failed. Run scripts\check_and_install_browsers.bat for full check
)

:: 启动Node.js终端服务
echo [信息] 检查Node.js终端服务...
cd backend\terminal_service
if exist "package.json" (
    if not exist "node_modules" (
        echo [信息] 安装Node.js终端服务依赖...
        call npm install --silent >nul 2>&1
    )
    echo [信息] 启动Node.js终端服务 (端口 3001)...
    start "Terminal-Service" cmd /k "npm start"
) else (
    echo [警告] 未发现terminal_service，跳过终端服务启动
)
cd ..\..

echo [信息] 启动后端服务 - Windows优化版本...
echo [信息] 使用Windows ProactorEventLoop解决Playwright异步子进程问题...
cd backend
start "Backend-FastAPI-Windows" cmd /k "call venv\Scripts\activate.bat && python ..\start_backend_windows.py"
cd ..

echo [信息] 等待后端启动...
timeout /t 5 /nobreak >nul

echo [信息] 检查前端构建状态...
cd frontend

:: 检查是否存在构建文件
if not exist "dist\index.html" (
    echo [信息] 未发现构建文件，正在构建前端项目...
    echo ========================================
    echo         构建前端项目
    echo ========================================
    call npm run build
    if %errorlevel% neq 0 (
        echo.
        echo [错误] 前端构建失败！请检查代码并重试
        cd ..
        pause
        exit /b 1
    )
    echo [信息] 前端构建完成！
) else (
    echo [信息] 发现已存在构建文件，跳过构建步骤
)

echo [信息] 启动前端服务...  
start "Frontend-React" cmd /k "npx vite --host 0.0.0.0 --port %FRONTEND_PORT%"
cd ..

:: Qwen-Code服务已移除，跳过启动

:: 获取本机IP地址
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /c:"IPv4"') do set LOCAL_IP=%%i
for /f "tokens=1" %%i in ("%LOCAL_IP%") do set LOCAL_IP=%%i

echo.
echo ========================================
echo          所有服务已启动！
echo ========================================
echo.
echo 前端访问地址:
echo   - 本地访问: http://localhost:%FRONTEND_PORT%
echo   - IP访问:   http://%LOCAL_IP%:%FRONTEND_PORT%
echo.
echo 后端: http://localhost:%BACKEND_PORT%
echo 文档: http://localhost:%BACKEND_PORT%/docs
echo.

:: 等待3秒后打开浏览器 (优先使用IP地址)
timeout /t 3 /nobreak >nul
start http://%LOCAL_IP%:%FRONTEND_PORT%

echo.
echo ========================================
echo          启动完成总结
echo ========================================
echo [✓] Backend service started (FastAPI + Uvicorn)
echo [✓] Frontend service started (Vite dev server)
echo [✓] Node.js Terminal service started (Qwen integration)
echo [✓] Browser opened automatically
echo.
echo Service Management:
echo - Stop services: Close each service terminal window
echo - Restart: Run this script again  
echo - View logs: Check service terminal windows
echo - Full setup: Use setup_and_start.bat
echo.
echo ========================================
echo Press any key to exit startup program (services will continue running)
echo ========================================
pause
