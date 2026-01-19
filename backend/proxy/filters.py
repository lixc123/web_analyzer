"""
请求过滤规则
"""


class RequestFilter:
    """请求过滤器"""

    def __init__(self):
        """初始化过滤器"""
        self.rules = []

    def should_capture(self, url: str, method: str) -> bool:
        """判断请求是否应该被捕获"""
        pass
