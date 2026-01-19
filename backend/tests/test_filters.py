import pytest
from backend.proxy.filters import FilterRule, RequestFilter


class TestRequestFilter:
    def test_add_rule(self):
        filter = RequestFilter()
        rule = FilterRule(pattern="*.example.com", type="blacklist")
        filter.add_rule(rule)
        assert len(filter.rules) == 1

    def test_blacklist_match(self):
        filter = RequestFilter()
        filter.add_rule(FilterRule(pattern="*.ads.com", type="blacklist"))
        assert not filter.should_capture("http://tracker.ads.com/pixel")
        assert filter.should_capture("http://example.com/page")

    def test_whitelist_match(self):
        filter = RequestFilter()
        filter.add_rule(FilterRule(pattern="api.example.com", type="whitelist"))
        assert filter.should_capture("http://api.example.com/data")
        assert not filter.should_capture("http://other.com/data")

    def test_regex_pattern(self):
        filter = RequestFilter()
        filter.add_rule(FilterRule(pattern=r".*\.jpg$", type="blacklist", use_regex=True))
        assert not filter.should_capture("http://example.com/image.jpg")
        assert filter.should_capture("http://example.com/page.html")
