from pathlib import Path
from typing import Optional
import asyncio
import concurrent.futures
import sys

try:
    from playwright.async_api import async_playwright, Browser, Page
except ImportError:
    async_playwright = None
    Browser = Page = None

try:
    from playwright_stealth import Stealth
    HAS_STEALTH = True
except ImportError:
    Stealth = None
    HAS_STEALTH = False


class ThreadSafeContextWrapper:
    """线程安全的Playwright上下文包装器，用于Windows ProactorEventLoop"""
    
    def __init__(self, async_context, async_page, executor):
        self.async_context = async_context
        self.async_page = async_page
        self.executor = executor
    
    @property 
    def pages(self):
        """返回页面列表"""
        return [ThreadSafePageWrapper(self.async_page, self.executor)]
    
    async def new_page(self):
        """在原线程中创建新页面"""
        import asyncio
        
        def _create_in_thread():
            # 在Playwright线程中运行异步操作
            async def _create():
                return await self.async_context.new_page()
            
            # 创建新的事件循环来运行
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_create())
            finally:
                loop.close()
        
        future = self.executor.submit(_create_in_thread)
        new_page = await asyncio.wrap_future(future)
        return ThreadSafePageWrapper(new_page, self.executor)

class ThreadSafePageWrapper:
    """线程安全的Playwright页面包装器"""
    
    def __init__(self, async_page, executor):
        self.async_page = async_page
        self.executor = executor
    
    async def goto(self, url: str, wait_until: str = None, timeout: float = None):
        """在原线程中导航到URL"""
        import asyncio
        
        def _goto_in_thread():
            # 在Playwright线程中运行异步导航
            async def _goto():
                print(f"[INFO] 线程安全导航到: {url}")
                kwargs = {}
                if wait_until is not None:
                    kwargs["wait_until"] = wait_until
                if timeout is not None:
                    kwargs["timeout"] = timeout
                result = await self.async_page.goto(url, **kwargs)
                print(f"[OK] 线程安全导航完成: {url}")
                return result
            
            # 在现有事件循环中运行
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_goto())
            finally:
                loop.close()
        
        future = self.executor.submit(_goto_in_thread)
        return await asyncio.wrap_future(future)


class BrowserManager:
    def __init__(self) -> None:
        self._playwright = None
        self._browser: Optional["Browser"] = None
        self._page: Optional["Page"] = None
        self._screenshot_dir: Optional[Path] = None

    async def launch(self, headless: bool = False) -> None:
        if async_playwright is None:
            raise RuntimeError(
                "playwright is not available. Install dependencies with "
                "`pip install -r web_recorder/requirements.txt` and run "
                "`playwright install chromium`."
            )

        if self._browser is not None:
            return

        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=headless)
        page = await browser.new_page()

        self._playwright = pw
        self._browser = browser
        self._page = page

    async def goto(self, url: str) -> None:
        if self._page is None:
            raise RuntimeError("browser is not running")
        await self._page.goto(url)

    async def export_storage_state(self, path: Path) -> None:
        if self._page is None:
            raise RuntimeError("browser is not running")
        context = self._page.context
        await context.storage_state(path=str(path))

    async def launch_with_storage_state(self, storage_state_path: Path, headless: bool = False) -> None:
        if async_playwright is None:
            raise RuntimeError(
                "playwright is not available. Install dependencies with "
                "`pip install -r web_recorder/requirements.txt` and run "
                "`playwright install chromium`."
            )

        if self._browser is not None:
            await self.close()

        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(storage_state=str(storage_state_path))
        page = await context.new_page()

        self._playwright = pw
        self._browser = browser
        self._page = page

    async def close(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None

        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

        self._page = None

    @property
    def page(self) -> Optional["Page"]:
        return self._page

    def is_running(self) -> bool:
        return self._browser is not None

    async def create_browser_context(self, headless: bool = True, user_agent: str = None, timeout: int = 30, use_system_chrome: bool = False, chrome_path: str = None):
        """创建浏览器上下文 - 使用 playwright-stealth 反检测"""
        import sys
        import random
        import os
        
        if self._browser is not None:
            await self.close()

        print(f"[INFO] 启动 Playwright... (use_system_chrome={use_system_chrome}, headless={headless})")
        
        if async_playwright is None:
            raise RuntimeError("playwright is not available.")
            
        try:
            pw = await async_playwright().start()
            print("[OK] Playwright实例已启动")
            
            # 启动参数
            launch_args = [
                '--disable-blink-features=AutomationControlled',
                '--disable-infobars',
                '--disable-dev-shm-usage',
                '--no-first-run',
                '--no-default-browser-check',
            ]
            
            if sys.platform != 'win32':
                launch_args.append('--no-sandbox')
            
            # 确定 Chrome 路径
            final_chrome_path = None
            
            # 优先使用用户指定的路径
            if chrome_path and os.path.exists(chrome_path):
                final_chrome_path = chrome_path
                print(f"[OK] 使用用户配置的 Chrome: {final_chrome_path}")
            elif use_system_chrome:
                # 自动查找系统 Chrome
                print("[INFO] 正在查找系统 Chrome...")
                
                # 常见安装路径
                possible_paths = [
                    # Windows 常见路径
                    "C:/Program Files/Google/Chrome/Application/chrome.exe",
                    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
                    os.path.expanduser("~/AppData/Local/Google/Chrome/Application/chrome.exe"),
                    # macOS
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    # Linux
                    "/usr/bin/google-chrome",
                    "/usr/bin/google-chrome-stable",
                    "/usr/bin/chromium-browser",
                    "/usr/bin/chromium",
                ]
                
                # Windows: 尝试从注册表获取 Chrome 路径
                if sys.platform == 'win32':
                    try:
                        import winreg
                        for reg_path in [
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                        ]:
                            try:
                                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                                chrome_from_reg, _ = winreg.QueryValueEx(key, "")
                                winreg.CloseKey(key)
                                if chrome_from_reg and os.path.exists(chrome_from_reg):
                                    possible_paths.insert(0, chrome_from_reg)
                                    print(f"[DEBUG] 从注册表找到: {chrome_from_reg}")
                                    break
                            except WindowsError:
                                continue
                    except Exception as e:
                        print(f"[DEBUG] 注册表查找失败: {e}")
                
                # macOS/Linux: 尝试用 which 命令
                elif sys.platform in ['darwin', 'linux']:
                    try:
                        import subprocess
                        result = subprocess.run(['which', 'google-chrome'], capture_output=True, text=True)
                        if result.returncode == 0 and result.stdout.strip():
                            possible_paths.insert(0, result.stdout.strip())
                    except Exception:
                        pass
                
                # 遍历查找
                for path in possible_paths:
                    if os.path.exists(path):
                        final_chrome_path = path
                        print(f"[OK] 找到系统 Chrome: {final_chrome_path}")
                        break
                
                if not final_chrome_path:
                    print("[WARN] 未找到系统 Chrome，使用 Playwright 内置 Chromium")
            
            # 启动浏览器
            if final_chrome_path:
                print(f"[INFO] 使用 Chrome 启动: {final_chrome_path}")
                browser = await pw.chromium.launch(
                    executable_path=final_chrome_path,
                    headless=headless,
                    args=launch_args,
                )
            else:
                print("[INFO] 使用 Playwright 内置 Chromium 启动")
                browser = await pw.chromium.launch(
                    headless=headless,
                    args=launch_args,
                )
            print("[OK] 浏览器已启动")
            
            # 随机 User-Agent
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            ]
            final_user_agent = user_agent or random.choice(user_agents)
            
            # 随机屏幕分辨率
            screen_sizes = [
                {"width": 1920, "height": 1080},
                {"width": 1366, "height": 768},
                {"width": 1536, "height": 864},
            ]
            screen_size = random.choice(screen_sizes)
            
            context_options = {
                "viewport": screen_size,
                "user_agent": final_user_agent,
                "locale": "zh-CN",
                "timezone_id": "Asia/Shanghai",
                "ignore_https_errors": True,
            }
                
            context = await browser.new_context(**context_options)
            context.set_default_timeout(timeout * 1000)
            print(f"[OK] 浏览器上下文已创建")
            
            page = await context.new_page()
            print("[OK] 新页面已创建")
            
            # 使用 playwright-stealth 注入反检测
            if HAS_STEALTH and Stealth:
                try:
                    stealth = Stealth()
                    await stealth.apply_stealth_async(page)
                    print("[OK] playwright-stealth 反检测已启用")
                except Exception as e:
                    print(f"[WARN] playwright-stealth 应用失败: {e}")
            else:
                print("[WARN] playwright-stealth 未安装，跳过反检测")
                
            self._playwright = pw
            self._browser = browser
            self._page = page
            
            print("[OK] Playwright启动完成")
            return context
            
        except Exception as e:
            msg = str(e)
            low = msg.lower()
            hints = []

            # Browser binary missing / not installed
            if "executable doesn't exist" in low or "playwright install" in low or "chromium" in low and "download" in low:
                hints.append("提示：Playwright 浏览器未安装/路径不可用。可运行：`python -m playwright install chromium`。")

            # Linux shared library deps missing
            if ("error while loading shared libraries" in low) or ("host system is missing dependencies" in low) or ("libnspr" in low) or ("libnss" in low):
                hints.append("提示(Linux)：系统依赖缺失。可运行：`python -m playwright install-deps chromium`，或安装缺失库（如 libnspr4/libnss3 等）。")

            # Permission denied creating default cache path
            if ("permission denied" in low or "eacces" in low) and "ms-playwright" in low:
                hints.append("提示：浏览器缓存目录无权限。可设置 `PLAYWRIGHT_BROWSERS_PATH` 到可写目录后再安装浏览器。")

            hint_text = ("\n" + "\n".join(hints)) if hints else ""
            print(f"[FAIL] Playwright启动失败: {msg}{hint_text}")
            raise RuntimeError(f"Playwright启动失败: {msg}{hint_text}")

    async def take_screenshot(self, reason: str = "general", full_page: bool = True) -> Optional[str]:
        """截取页面截图"""
        try:
            if not self._page:
                print("[FAIL] 截图失败: 页面未初始化")
                return None
            
            # 生成截图文件名
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            filename = f"screenshot_{timestamp}_{reason}.png"
            
            # 确定截图保存路径
            screenshots_dir = self._screenshot_dir or Path("screenshots")
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshots_dir / filename
            
            # 根据页面类型执行截图
            if hasattr(self._page, 'screenshot'):
                # 标准异步页面
                await self._page.screenshot(
                    path=str(screenshot_path),
                    full_page=full_page,
                    type="png"
                )
            elif hasattr(self._page, 'sync_screenshot'):
                # 同步包装器页面
                self._page.sync_screenshot(
                    path=str(screenshot_path),
                    full_page=full_page,
                    type="png"
                )
            else:
                print(f"[FAIL] 截图失败: 未知页面类型 {type(self._page)}")
                return None
            
            print(f"[OK] 截图已保存: {screenshot_path} (原因: {reason})")
            return str(screenshot_path)
            
        except Exception as e:
            print(f"[FAIL] 截图失败 ({reason}): {e}")
            return None

    def set_screenshot_directory(self, directory: str) -> None:
        """设置截图保存目录"""
        try:
            self._screenshot_dir = Path(directory)
            self._screenshot_dir.mkdir(parents=True, exist_ok=True)
            print(f"[OK] 截图目录已设置: {self._screenshot_dir}")
        except Exception as e:
            print(f"[FAIL] 设置截图目录失败: {e}")

    async def take_element_screenshot(self, selector: str, reason: str = "element") -> Optional[str]:
        """截取特定元素的截图"""
        try:
            if not self._page:
                print("[FAIL] 元素截图失败: 页面未初始化")
                return None
            
            # 生成截图文件名
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            filename = f"element_{timestamp}_{reason}.png"
            
            # 确定截图保存路径  
            screenshots_dir = self._screenshot_dir or Path("screenshots")
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshots_dir / filename
            
            # 查找元素并截图
            if hasattr(self._page, 'locator'):
                # 标准异步页面
                element = self._page.locator(selector)
                await element.screenshot(path=str(screenshot_path))
            else:
                print("[FAIL] 元素截图失败: 页面不支持元素定位")
                return None
            
            print(f"[OK] 元素截图已保存: {screenshot_path} (选择器: {selector})")
            return str(screenshot_path)
            
        except Exception as e:
            print(f"[FAIL] 元素截图失败 ({selector}): {e}")
            return None

    def get_page_info(self) -> dict:
        """获取当前页面信息"""
        try:
            if not self._page:
                return {"error": "页面未初始化"}
            
            info = {
                "url": self._page.url if hasattr(self._page, 'url') else "未知",
                "title": "未获取",
                "viewport": "未获取",
                "user_agent": "未获取"
            }
            
            # 尝试获取更多信息
            try:
                if hasattr(self._page, 'title'):
                    info["title"] = self._page.title()
                if hasattr(self._page, 'viewport_size'):
                    info["viewport"] = self._page.viewport_size
                if hasattr(self._page, 'evaluate'):
                    info["user_agent"] = self._page.evaluate("navigator.userAgent")
            except:
                pass
            
            return info
            
        except Exception as e:
            return {"error": f"获取页面信息失败: {e}"}
