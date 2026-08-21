"""Tests for the exfiltration prevention module."""

import pytest

from nagapasha.security.exfil import HostAllowlist


class TestHostAllowlist:
    """Tests for HostAllowlist."""

    def setup_method(self):
        """Create an allowlist with example.com."""
        self.allowlist = HostAllowlist(
            allowed=["example.com", "api.example.com"],
            allow_subdomains=True,
        )

    def test_allows_exact_match(self):
        """Should allow URLs matching an allowed host exactly."""
        assert self.allowlist.is_allowed("https://example.com/api") is True

    def test_allows_subdomain(self):
        """Should allow subdomains of allowed hosts."""
        assert self.allowlist.is_allowed("https://sub.example.com/api") is True

    def test_allows_nested_subdomain(self):
        """Should allow nested subdomains."""
        assert self.allowlist.is_allowed("https://a.b.example.com/api") is True

    def test_allows_different_allowed_host(self):
        """Should allow URLs matching other allowed hosts."""
        assert self.allowlist.is_allowed("https://api.example.com/v1") is True

    def test_blocks_unauthorized_host(self):
        """Should block URLs to unauthorized hosts."""
        assert self.allowlist.is_allowed("https://evil.com/api") is False

    def test_blocks_different_domain(self):
        """Should block URLs to different domains."""
        assert self.allowlist.is_allowed("https://example.org/api") is False

    def test_blocks_empty_url(self):
        """Should block empty URLs."""
        assert self.allowlist.is_allowed("") is False

    def test_blocks_null_url(self):
        """Should block None URLs."""
        assert self.allowlist.is_allowed(None) is False

    def test_blocks_suspicious_characters(self):
        """Should block URLs with suspicious characters in hostname."""
        assert self.allowlist.is_allowed("https://evil.com;exec.com/api") is False
        assert self.allowlist.is_allowed("https://evil\\x00.com/api") is False

    def test_records_blocked_events(self):
        """Should record blocked events."""
        self.allowlist.is_allowed("https://evil.com/api")
        events = self.allowlist.get_blocked_events()
        assert len(events) == 1
        assert events[0].blocked_url == "https://evil.com/api"
        assert events[0].reason == "host_not_in_allowlist"

    def test_clear_blocked(self):
        """Should clear blocked events log."""
        self.allowlist.is_allowed("https://evil.com/api")
        self.allowlist.clear_blocked()
        assert len(self.allowlist.get_blocked_events()) == 0

    def test_add_allowed(self):
        """Should add hosts to allowlist."""
        self.allowlist.add_allowed("newhost.com")
        assert self.allowlist.is_allowed("https://newhost.com/api") is True

    def test_remove_allowed(self):
        """Should remove hosts from allowlist."""
        self.allowlist.remove_allowed("example.com")
        assert self.allowlist.is_allowed("https://example.com/api") is False

    def test_allow_localhost(self):
        """Should allow localhost when configured."""
        allowlist = HostAllowlist(
            allowed=["example.com"],
            allow_localhost=True,
        )
        assert allowlist.is_allowed("http://localhost:8080/api") is True

    def test_blocks_localhost_without_flag(self):
        """Should block localhost when not explicitly allowed."""
        allowlist = HostAllowlist(
            allowed=["example.com"],
            allow_localhost=False,
        )
        assert allowlist.is_allowed("http://localhost:8080/api") is False

    def test_ip_range_match(self):
        """Should match IPs in allowed CIDR ranges."""
        allowlist = HostAllowlist(
            allowed=[],
            allow_ip_ranges=["192.168.1.0/24"],
        )
        assert allowlist.is_allowed("http://192.168.1.50/api") is True
        assert allowlist.is_allowed("http://192.168.1.254/api") is True

    def test_ip_range_no_match(self):
        """Should not match IPs outside allowed CIDR ranges."""
        allowlist = HostAllowlist(
            allowed=[],
            allow_ip_ranges=["192.168.1.0/24"],
        )
        assert allowlist.is_allowed("http://192.168.2.1/api") is False
