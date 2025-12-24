from pathlib import Path
from typing import Optional
import asyncio
import concurrent.futures
import sys

try:
    from playwright.async_api import async_playwright, Browser, Page
except ImportError:  # playwright is optional until the user installs it
    async_playwright = None  # type: ignore[assignment]
    Browser = Page = None  # type: ignore[assignment]

from .js_hooks import JS_HOOK_SCRIPT


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
                print(f"🔄 线程安全导航到: {url}")
                kwargs = {}
                if wait_until is not None:
                    kwargs["wait_until"] = wait_until
                if timeout is not None:
                    kwargs["timeout"] = timeout
                result = await self.async_page.goto(url, **kwargs)
                print(f"✅ 线程安全导航完成: {url}")
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

        # 注入 JS Hook，用于拦截 fetch / XHR 调用栈
        try:
            await page.add_init_script(JS_HOOK_SCRIPT)
        except Exception:
            # Hook 注入失败不影响主流程
            pass

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

        try:
            await page.add_init_script(JS_HOOK_SCRIPT)
        except Exception:
            pass

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

    async def create_browser_context(self, headless: bool = True, user_agent: str = None, timeout: int = 30):
        """创建浏览器上下文 - Windows兼容版本"""
        import sys
        import asyncio
        import concurrent.futures
        
        if self._browser is not None:
            await self.close()

        # Windows和其他系统统一使用异步Playwright
        print("🔄 启动异步Playwright (支持所有平台)...")
        
        if sys.platform == 'win32':
            print("🔧 Windows系统 - 使用应用级ProactorEventLoop")
        
        if async_playwright is None:
            raise RuntimeError("playwright is not available.")
            
        try:
            # 非Windows系统使用异步playwright
            if async_playwright is None:
                raise RuntimeError("playwright is not available.")
                
            pw = await async_playwright().start()
            print("✅ Playwright实例已启动")
            
            browser = await pw.chromium.launch(
                headless=headless,
                args=['--no-sandbox', '--disable-web-security'] if sys.platform != 'win32' else []
            )
            print("✅ Chromium浏览器已启动")
            
            context_options = {"viewport": {"width": 1280, "height": 720}}
            if user_agent:
                context_options["user_agent"] = user_agent
                
            context = await browser.new_context(**context_options)
            context.set_default_timeout(timeout * 1000)
            print("✅ 浏览器上下文已创建")

            try:
                await context.add_init_script(JS_HOOK_SCRIPT)
            except Exception as e:
                print(f"⚠️ JS Hook注入失败: {e}")
            
            page = await context.new_page()
            print("✅ 新页面已创建")
            
            try:
                await page.add_init_script(JS_HOOK_SCRIPT)
                print("✅ JS Hook脚本已注入")
            except Exception as e:
                print(f"⚠️ JS Hook注入失败: {e}")
                
            self._playwright = pw
            self._browser = browser
            self._page = page
            
            print("✅ 统一异步Playwright启动完成")
            return context
            
        except Exception as e:
            print(f"❌ Playwright启动失败: {e}")
            raise RuntimeError(f"Playwright启动失败: {e}")

    async def take_screenshot(self, reason: str = "general", full_page: bool = True) -> Optional[str]:
        """截取页面截图"""
        try:
            if not self._page:
                print("❌ 截图失败: 页面未初始化")
                return None
            
            # 生成截图文件名
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            filename = f"screenshot_{timestamp}_{reason}.png"
            
            # 确定截图保存路径
            from pathlib import Path
            screenshots_dir = Path("screenshots")
            screenshots_dir.mkdir(exist_ok=True)
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
                print(f"❌ 截图失败: 未知页面类型 {type(self._page)}")
                return None
            
            print(f"✅ 截图已保存: {screenshot_path} (原因: {reason})")
            return str(screenshot_path)
            
        except Exception as e:
            print(f"❌ 截图失败 ({reason}): {e}")
            return None

    def set_screenshot_directory(self, directory: str) -> None:
        """设置截图保存目录"""
        try:
            self._screenshot_dir = Path(directory)
            self._screenshot_dir.mkdir(parents=True, exist_ok=True)
            print(f"✅ 截图目录已设置: {self._screenshot_dir}")
        except Exception as e:
            print(f"❌ 设置截图目录失败: {e}")

    async def take_element_screenshot(self, selector: str, reason: str = "element") -> Optional[str]:
        """截取特定元素的截图"""
        try:
            if not self._page:
                print("❌ 元素截图失败: 页面未初始化")
                return None
            
            # 生成截图文件名
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            filename = f"element_{timestamp}_{reason}.png"
            
            # 确定截图保存路径  
            from pathlib import Path
            screenshots_dir = Path("screenshots")
            screenshots_dir.mkdir(exist_ok=True)
            screenshot_path = screenshots_dir / filename
            
            # 查找元素并截图
            if hasattr(self._page, 'locator'):
                # 标准异步页面
                element = self._page.locator(selector)
                await element.screenshot(path=str(screenshot_path))
            else:
                print(f"❌ 元素截图失败: 页面不支持元素定位")
                return None
            
            print(f"✅ 元素截图已保存: {screenshot_path} (选择器: {selector})")
            return str(screenshot_path)
            
        except Exception as e:
            print(f"❌ 元素截图失败 ({selector}): {e}")
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
