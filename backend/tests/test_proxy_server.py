import pytest
from backend.proxy.proxy_server import ProxyServer


class TestProxyServer:
    def test_init(self):
        server = ProxyServer(port=8888)
        assert server.port == 8888
        assert not server.is_running()

    def test_start_stop(self):
        server = ProxyServer(port=8889)
        server.start()
        assert server.is_running()
        server.stop()
        assert not server.is_running()

    def test_port_conflict(self):
        server1 = ProxyServer(port=8890)
        server1.start()
        server2 = ProxyServer(port=8890)
        with pytest.raises(Exception):
            server2.start()
        server1.stop()
