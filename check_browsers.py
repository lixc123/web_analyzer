#!/usr/bin/env python3
"""
Playwright 浏览器检查和安装脚本
自动检查所需浏览器是否已安装，如未安装则自动下载安装
"""
import sys
import os
import subprocess
import platform
from pathlib import Path

def print_status(message, status="INFO"):
    """打印带状态标识的消息"""
    status_icons = {
        "INFO": "🔍",
        "SUCCESS": "✅", 
        "ERROR": "❌",
        "WARNING": "⚠️",
        "INSTALL": "📦"
    }
    icon = status_icons.get(status, "ℹ️")
    print(f"{icon} {message}")

def check_python_version():
    """检查Python版本"""
    print_status("检查Python版本...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_status(f"Python版本过低: {version.major}.{version.minor}", "ERROR")
        print_status("需要Python 3.8或更高版本", "ERROR")
        return False
    print_status(f"Python版本: {version.major}.{version.minor}.{version.micro}", "SUCCESS")
    return True

def check_playwright_installed():
    """检查Playwright是否已安装"""
    print_status("检查Playwright包是否已安装...")
    try:
        import playwright
        # 尝试获取版本信息
        try:
            version = playwright.__version__
        except AttributeError:
            # 如果__version__不存在，尝试其他方式获取版本
            try:
                import pkg_resources
                version = pkg_resources.get_distribution("playwright").version
            except:
                version = "未知版本"
        print_status(f"Playwright已安装 - 版本: {version}", "SUCCESS")
        return True
    except ImportError:
        print_status("Playwright未安装", "ERROR")
        return False

def get_playwright_browsers_dir():
    """获取Playwright浏览器安装目录"""
    system = platform.system().lower()
    if system == "windows":
        return os.path.join(os.path.expanduser("~"), "AppData", "Local", "ms-playwright")
    elif system == "darwin":  # macOS
        return os.path.join(os.path.expanduser("~"), "Library", "Caches", "ms-playwright")
    else:  # Linux
        return os.path.join(os.path.expanduser("~"), ".cache", "ms-playwright")

def check_chromium_installed():
    """检查Chromium浏览器是否已安装"""
    print_status("检查Chromium浏览器安装状态...")
    
    browsers_dir = get_playwright_browsers_dir()
    print_status(f"浏览器目录: {browsers_dir}")
    
    if not os.path.exists(browsers_dir):
        print_status("Playwright浏览器目录不存在", "WARNING")
        return False
    
    # 查找Chromium相关目录
    chromium_dirs = []
    for item in os.listdir(browsers_dir):
        if "chromium" in item.lower():
            chromium_dirs.append(item)
    
    if not chromium_dirs:
        print_status("未找到Chromium浏览器", "WARNING")
        return False
    
    print_status(f"找到Chromium目录: {', '.join(chromium_dirs)}", "SUCCESS")
    
    # 检查可执行文件是否存在
    for chromium_dir in chromium_dirs:
        full_path = os.path.join(browsers_dir, chromium_dir)
        if os.path.isdir(full_path):
            # 查找可执行文件
            exe_found = False
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    if file.endswith('.exe') or 'chrome' in file.lower():
                        print_status(f"找到Chromium可执行文件: {file}", "SUCCESS")
                        exe_found = True
                        break
                if exe_found:
                    break
            
            if exe_found:
                return True
    
    print_status("Chromium目录存在但缺少可执行文件", "WARNING")
    return False

def install_playwright_browsers():
    """安装Playwright浏览器"""
    print_status("开始安装Playwright浏览器...", "INSTALL")
    
    # 尝试多种安装方式
    install_commands = [
        ["playwright", "install", "chromium"],
        ["python", "-m", "playwright", "install", "chromium"],
        [sys.executable, "-m", "playwright", "install", "chromium"]
    ]
    
    for cmd in install_commands:
        try:
            print_status(f"尝试安装命令: {' '.join(cmd)}", "INSTALL")
            
            # 运行安装命令
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5分钟超时
            )
            
            if result.returncode == 0:
                print_status("Chromium浏览器安装成功!", "SUCCESS")
                print("安装输出:")
                print(result.stdout)
                return True
            else:
                print_status(f"安装命令失败 (退出码: {result.returncode})", "WARNING")
                if result.stderr:
                    print(f"错误信息: {result.stderr}")
                    
        except subprocess.TimeoutExpired:
            print_status("安装超时", "ERROR")
        except FileNotFoundError:
            print_status(f"命令未找到: {cmd[0]}", "WARNING")
        except Exception as e:
            print_status(f"安装出现异常: {e}", "ERROR")
    
    print_status("所有安装尝试都失败了", "ERROR")
    return False

def test_playwright_functionality():
    """测试Playwright功能"""
    print_status("测试Playwright浏览器功能...")
    
    try:
        # 创建简单的测试脚本
        test_code = """
import asyncio
from playwright.async_api import async_playwright

async def test_browser():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto('about:blank')
        title = await page.title()
        await browser.close()
        return True

if __name__ == "__main__":
    try:
        result = asyncio.run(test_browser())
        if result:
            print("PLAYWRIGHT_TEST_SUCCESS")
    except Exception as e:
        print(f"PLAYWRIGHT_TEST_FAILED: {e}")
"""
        
        # 写入临时测试文件
        test_file = "temp_playwright_test.py"
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_code)
        
        try:
            # 运行测试
            result = subprocess.run(
                [sys.executable, test_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "PLAYWRIGHT_TEST_SUCCESS" in result.stdout:
                print_status("Playwright功能测试成功!", "SUCCESS")
                return True
            else:
                print_status("Playwright功能测试失败", "ERROR")
                if result.stderr:
                    print(f"测试错误: {result.stderr}")
                return False
                
        finally:
            # 清理测试文件
            if os.path.exists(test_file):
                os.remove(test_file)
                
    except Exception as e:
        print_status(f"测试过程出现异常: {e}", "ERROR")
        return False

def main():
    """主函数"""
    import argparse
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Playwright浏览器检查和安装工具")
    parser.add_argument("--auto-install", action="store_true", 
                        help="自动安装缺失的浏览器，不需要用户确认")
    parser.add_argument("--quiet", action="store_true", 
                        help="静默模式，减少输出信息")
    args = parser.parse_args()
    
    if not args.quiet:
        print("=" * 60)
        print("🚀 Playwright浏览器检查和安装工具")
        print("=" * 60)
        print()
    
    # 检查Python版本
    if not check_python_version():
        return 1
    
    # 检查Playwright是否安装
    if not check_playwright_installed():
        print_status("请先安装Playwright: pip install playwright", "ERROR")
        return 1
    
    # 检查Chromium是否已安装
    chromium_installed = check_chromium_installed()
    
    if not chromium_installed:
        if not args.quiet:
            print()
        print_status("需要安装Chromium浏览器", "WARNING")
        
        should_install = False
        if args.auto_install:
            should_install = True
            print_status("自动安装模式：开始安装Chromium浏览器", "INSTALL")
        else:
            response = input("是否现在安装Chromium浏览器? (y/n): ").strip().lower()
            should_install = response in ['y', 'yes', '是', 'Y']
        
        if should_install:
            if install_playwright_browsers():
                if not args.quiet:
                    print()
                print_status("重新检查Chromium安装状态...")
                chromium_installed = check_chromium_installed()
            else:
                print_status("浏览器安装失败", "ERROR")
                return 1
        else:
            print_status("用户选择不安装浏览器", "WARNING")
            return 1
    
    if chromium_installed:
        if not args.quiet:
            print()
        print_status("进行Playwright功能测试...")
        if test_playwright_functionality():
            if not args.quiet:
                print()
                print("=" * 60)
            print_status("🎉 所有检查通过！Playwright浏览器已就绪", "SUCCESS")
            if not args.quiet:
                print("=" * 60)
            return 0
        else:
            print_status("功能测试失败，可能需要重新安装浏览器", "ERROR")
            return 1
    else:
        print_status("Chromium浏览器仍未正确安装", "ERROR")
        return 1

if __name__ == "__main__":
    exit_code = main()
    print()
    input("按任意键退出...")
    sys.exit(exit_code)
