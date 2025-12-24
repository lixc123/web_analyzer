@echo off

echo %cmdcmdline% | find /i "/c" >nul
if %errorlevel%==0 if /i "%~1" neq "__keep" (
    cmd /k ""%~f0" __keep"
    exit /b
)

chcp 65001 >nul
setlocal enabledelayedexpansion

set "AUTO_MODE=0"
if /i "%~2"=="--auto" set "AUTO_MODE=1"

echo ========================================
echo    Web Analyzer V2 - 一键启动脚本
echo ========================================
echo.

:: 检查Python版本
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] Python 未安装或未添加到PATH
    echo 请安装 Python 3.11+ 并添加到环境变量
    pause
    exit /b 1
)

:: 检查Node.js版本
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] Node.js 未安装或未添加到PATH
    echo 请安装 Node.js 20+ 并添加到环境变量
    pause
    exit /b 1
)

for /f %%v in ('node -p "process.versions.node"') do set "NODE_VER=%%v"
for /f "tokens=1 delims=." %%m in ("%NODE_VER%") do set "NODE_MAJOR=%%m"
if %NODE_MAJOR% lss 20 (
    echo [错误] Node.js 版本过低: %NODE_VER%
    echo Qwen-Code 需要 Node.js 20+
    pause
    exit /b 1
)

:: 设置项目根目录
pushd "%~dp0.."

:: 检查并创建.env文件
if not exist ".env" (
    if exist ".env.example" (
        echo [信息] 正在从 .env.example 创建 .env 文件...
        copy ".env.example" ".env" >nul
        echo [警告] 请编辑 .env 文件并填写您的 API Key
        echo.
        echo 主要配置项:
        echo   OPENAI_API_KEY=sk-xxxx  ^(硅基流动API密钥^)
        echo   OPENAI_BASE_URL=https://api.siliconflow.cn/v1
        echo.
        if "!AUTO_MODE!"=="1" (
            echo [信息] 自动模式已开启，跳过打开编辑器步骤
        ) else (
            set /p "continue=是否现在编辑 .env 文件? ^(y/n^): "
            if /i "!continue!"=="y" (
                notepad ".env"
            )
        )
    ) else (
        echo [错误] .env.example 文件不存在
        pause
        exit /b 1
    )
)

:: 加载环境变量
for /f "tokens=1,2 delims==" %%a in ('type .env ^| findstr /v "^#" ^| findstr "="') do (
    set "%%a=%%b"
)

if "%BACKEND_PORT%"=="" set BACKEND_PORT=8000
if "%FRONTEND_PORT%"=="" set FRONTEND_PORT=3000

:: 创建必要的目录
if not exist "data" mkdir data
if not exist "logs" mkdir logs

echo [信息] 正在安装后端依赖...
cd backend
if not exist "requirements.txt" (
    echo [错误] backend/requirements.txt 不存在
    cd ..
    pause
    exit /b 1
)

:: 创建虚拟环境（如果不存在）
if not exist "venv" (
    echo [信息] 创建 Python 虚拟环境...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [错误] Python虚拟环境创建失败
        cd ..
        pause
        exit /b 1
    )
    echo [信息] Python虚拟环境创建成功
)

:: 激活虚拟环境并安装依赖
echo [信息] 激活Python虚拟环境...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [错误] 无法激活Python虚拟环境，请检查venv\Scripts\activate.bat是否存在
    cd ..
    pause
    exit /b 1
)
echo [信息] 正在安装后端Python包（使用清华源加速）...
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
if %errorlevel% neq 0 (
    echo [错误] 后端依赖安装失败
    deactivate
    cd ..
    pause
    exit /b 1
)

echo [信息] 后端依赖安装完成

:: 回到项目根目录准备后续操作
cd ..

:: 检查和安装Playwright浏览器
echo [INFO] Checking Playwright browser installation...
python check_browsers.py --auto-install >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Browser check failed, but continuing with startup
    echo [TIP] If browser errors occur, run: scripts\check_and_install_browsers.bat
)
echo [INFO] Browser check completed

echo [信息] 正在安装前端依赖...
cd frontend
if not exist "package.json" (
    echo [错误] frontend/package.json 不存在
    cd ..
    pause
    exit /b 1
)

echo [信息] 正在安装前端Node.js包...
call npm install
if %errorlevel% neq 0 (
    echo.
    echo ============================================
    echo [错误] 前端依赖安装失败！
    echo ============================================
    echo 可能的解决方案：
    echo 1. 检查网络连接
    echo 2. 尝试使用国内镜像：npm config set registry https://registry.npmmirror.com
    echo 3. 清理npm缓存：npm cache clean --force
    echo 4. 手动进入frontend目录运行：npm install
    echo ============================================
    cd ..
    echo 按任意键退出...
    pause
    exit /b 1
)

echo [信息] 前端依赖安装完成

echo.
echo ========================================
echo         正在构建前端项目
echo ========================================
echo [信息] 开始编译TypeScript并构建前端项目...
call npm run build
if %errorlevel% neq 0 (
    echo.
    echo ============================================
    echo [错误] 前端项目构建失败！
    echo ============================================
    echo 可能的解决方案：
    echo 1. 检查TypeScript编译错误
    echo 2. 运行 npm run type-check 检查类型错误
    echo 3. 检查src目录下的代码语法
    echo 4. 清理依赖重新安装：rmdir /s /q node_modules ^& del /f /q package-lock.json ^& npm install
    echo ============================================
    cd ..
    echo.
    echo 按任意键退出...
    pause
    exit /b 1
)

echo [信息] 前端项目构建成功！
echo [INFO] Frontend dist folder: frontend\dist\

cd ..

:: Qwen-Code功能已移除，跳过相关安装

:: 启动服务
echo.
echo ========================================
echo           启动所有服务
echo ========================================
echo.

:: 启动Node.js终端服务
echo [信息] 正在安装和启动Node.js终端服务...
cd backend\terminal_service
if not exist "node_modules" (
    echo [信息] 安装Node.js终端服务依赖...
    call npm install
    if %errorlevel% neq 0 (
        echo [警告] Node.js终端服务依赖安装失败，跳过终端服务
        cd ..\..
        goto skip_terminal
    )
)
echo [信息] 启动Node.js终端服务 (端口 3001)...
start "Terminal-Service" cmd /k "npm start"
cd ..\..

:skip_terminal
:: 启动后端服务 (Windows ProactorEventLoop 优化版)
echo [信息] 正在启动后端服务 (端口 %BACKEND_PORT%) - Windows优化版本...
echo [信息] 使用Windows ProactorEventLoop解决Playwright异步子进程问题...
cd backend
start "Backend-FastAPI-Windows" cmd /k "call venv\Scripts\activate.bat && python ..\start_backend_windows.py"
cd ..

:: 等待后端启动
timeout /t 5 /nobreak >nul

:: 启动前端服务
echo [信息] 正在启动前端服务 (端口 %FRONTEND_PORT%)...
cd frontend
start "Frontend-React" cmd /k "npx vite --host 0.0.0.0 --port %FRONTEND_PORT%"
cd ..

:: Qwen-Code服务已移除，跳过启动

:: 获取本机IP地址
set "LOCAL_IP="
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /c:"IPv4"') do (
    for /f "tokens=1" %%j in ("%%i") do (
        if not defined LOCAL_IP set "LOCAL_IP=%%j"
    )
)
if not defined LOCAL_IP set "LOCAL_IP=localhost"

echo.
echo ========================================
echo          服务启动完成!
echo ========================================
echo.
echo 前端地址: 
echo   - 本地访问: http://localhost:%FRONTEND_PORT%
echo   - IP访问:   http://%LOCAL_IP%:%FRONTEND_PORT%
echo.
echo 后端API:  http://localhost:%BACKEND_PORT%
echo API文档:  http://localhost:%BACKEND_PORT%/docs
echo.
echo 按任意键打开浏览器...
if "%AUTO_MODE%"=="1" (
    timeout /t 1 /nobreak >nul
) else (
    pause >nul
)

:: 打开浏览器 (优先使用IP地址)
start http://%LOCAL_IP%:%FRONTEND_PORT%

echo.
echo ========================================
echo          启动完成总结
echo ========================================
echo [OK] 后端服务已启动 (FastAPI + Uvicorn)
echo [OK] 前端服务已启动 (Vite开发服务器)
echo [OK] Node.js终端服务已启动 (Qwen助手集成)
echo [OK] 浏览器已自动打开应用
echo.
echo Service management:
echo - Stop services: stop_services.bat
echo - Restart: run this script again
echo - Logs: check the service windows
echo.
echo ========================================
echo 按任意键退出安装程序 (服务将继续运行)
echo ========================================
if "%AUTO_MODE%"=="1" (
    timeout /t 3 /nobreak >nul
) else (
    pause
)
popd
