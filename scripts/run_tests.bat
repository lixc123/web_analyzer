@echo off
chcp 65001 >nul
echo ========================================
echo 运行测试套件
echo ========================================
echo.

cd /d "%~dp0.."

echo [1/3] 运行单元测试...
echo.
cd backend
python -m pytest tests/test_filters.py -v
if errorlevel 1 (
    echo.
    echo ❌ 单元测试失败
    pause
    exit /b 1
)

echo.
echo [2/3] 运行API测试...
echo.
python -m pytest tests/test_proxy_api.py -v
if errorlevel 1 (
    echo.
    echo ❌ API测试失败
    pause
    exit /b 1
)

echo.
echo [3/3] 运行集成测试...
echo.
python -m pytest tests/test_integration.py -v -s
if errorlevel 1 (
    echo.
    echo ❌ 集成测试失败
    pause
    exit /b 1
)

cd ..

echo.
echo ========================================
echo ✅ 所有测试通过！
echo ========================================
echo.
pause
