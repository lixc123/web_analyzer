@echo off
chcp 65001 >nul
echo ========================================
echo   Web Analyzer V2 - 生产环境清理脚本
echo   方案A：保守清理（安全快速）
echo ========================================
echo.

echo 本脚本将执行以下操作：
echo [1] 清空历史数据 (290MB)
echo [2] 删除Python缓存 (2288个文件)
echo [3] 删除测试文件
echo [4] 删除IDE配置
echo [5] 清空日志文件
echo.
echo 不会删除：依赖包、Git仓库、开发文档
echo.

set /p confirm="确认执行清理？(Y/N): "
if /i not "%confirm%"=="Y" (
    echo 已取消清理操作
    pause
    exit /b
)

echo.
echo ========================================
echo   开始清理...
echo ========================================
echo.

:: 1. 清空历史数据
echo [1/5] 清空历史数据...
if exist "data\sessions" (
    rmdir /s /q "data\sessions" 2>nul
    mkdir "data\sessions"
    echo   ✓ 已清空 data\sessions\
)
if exist "data\requests.json" (
    del /q "data\requests.json" 2>nul
    echo   ✓ 已删除 data\requests.json
)
if exist "data\sessions.json" (
    del /q "data\sessions.json" 2>nul
    echo   ✓ 已删除 data\sessions.json
)
echo   完成！预计节省 290MB
echo.

:: 2. 删除Python缓存
echo [2/5] 删除Python缓存...
set count=0
for /d /r . %%d in (__pycache__) do (
    if exist "%%d" (
        rmdir /s /q "%%d" 2>nul
        set /a count+=1
    )
)
del /s /q *.pyc 2>nul
echo   ✓ 已删除 %count% 个 __pycache__ 目录
echo   ✓ 已删除所有 .pyc 文件
echo.

:: 3. 删除测试文件
echo [3/5] 删除测试文件...
if exist "backend\tests" (
    rmdir /s /q "backend\tests" 2>nul
    echo   ✓ 已删除 backend\tests\
)
echo.

:: 4. 删除IDE配置
echo [4/5] 删除IDE配置...
if exist ".vscode" (
    rmdir /s /q ".vscode" 2>nul
    echo   ✓ 已删除 .vscode\
)
if exist ".claude" (
    rmdir /s /q ".claude" 2>nul
    echo   ✓ 已删除 .claude\
)
if exist ".idea" (
    rmdir /s /q ".idea" 2>nul
    echo   ✓ 已删除 .idea\
)
echo.

:: 5. 清空日志文件
echo [5/5] 清空日志文件...
if exist "logs" (
    del /q "logs\*" 2>nul
    echo   ✓ 已清空 logs\
)
if exist "backend\logs" (
    del /q "backend\logs\*" 2>nul
    echo   ✓ 已清空 backend\logs\
)
echo.

echo ========================================
echo   清理完成！
echo ========================================
echo.
echo 已完成：
echo   ✓ 历史数据已清空
echo   ✓ Python缓存已删除
echo   ✓ 测试文件已删除
echo   ✓ IDE配置已删除
echo   ✓ 日志文件已清空
echo.
echo ⚠️  重要：请手动完成以下配置修改
echo ========================================
echo.
echo 1. 修改 .env 文件：
echo    - DEBUG=false
echo    - LOG_LEVEL=WARNING
echo    - SECRET_KEY=^<生成新密钥^>
echo.
echo 2. 修改 backend\app\config.py：
echo    - 删除 CORS 中的 "*"
echo    - 更换 SECRET_KEY
echo.
echo 3. 修改 frontend\vite.config.ts：
echo    - sourcemap: false
echo.
echo 详细说明请查看：PRODUCTION_CONFIG_GUIDE.md
echo.
echo ========================================
pause
