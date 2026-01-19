import pytest
from backend.proxy.cert_manager import CertManager


class TestCertManager:
    def test_cert_exists(self):
        manager = CertManager()
        exists = manager.cert_exists()
        assert isinstance(exists, bool)

    def test_get_qrcode(self):
        manager = CertManager()
        qr = manager.get_cert_qrcode("http://example.com/cert")
        assert qr.startswith("data:image/png;base64,")

    def test_get_instructions(self):
        manager = CertManager()
        ios_inst = manager.get_install_instructions("ios")
        android_inst = manager.get_install_instructions("android")
        assert "iOS" in ios_inst or "设置" in ios_inst
        assert "Android" in android_inst or "设置" in android_inst
