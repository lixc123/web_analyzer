import pytest
import platform
from backend.proxy.system_proxy import WindowsSystemProxy


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
class TestWindowsSystemProxy:
    def test_get_current_settings(self):
        proxy = WindowsSystemProxy()
        settings = proxy.get_current_settings()
        assert isinstance(settings, dict)
        assert "enabled" in settings

    def test_enable_disable(self):
        proxy = WindowsSystemProxy()
        original = proxy.get_current_settings()

        proxy.enable("127.0.0.1:8888")
        enabled_settings = proxy.get_current_settings()
        assert enabled_settings["enabled"]

        proxy.disable()
        disabled_settings = proxy.get_current_settings()
        assert not disabled_settings["enabled"]
