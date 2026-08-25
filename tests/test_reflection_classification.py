"""A2a tests: context-aware reflection classification in diff.py

Verifies:
- _classify_reflection returns "unescaped" when payload appears literally
- _classify_reflection returns "html_escaped" when payload is HTML-entity-encoded
- _classify_reflection returns "not_reflected" when payload is absent
- ResponseDelta.reflection_context is correctly populated by compute_delta()
- html_escaped does NOT set is_confirmed_hit = True (regression test)
"""

import pytest
from nagapasha.engine.diff import (
    _classify_reflection,
    ResponseDelta,
    BaselineFingerprint,
    compute_delta,
)


class TestClassifyReflection:
    """Unit tests for the _classify_reflection function."""

    def test_unescaped_reflection(self):
        """Payload reflected literally → 'unescaped'."""
        payload = "<script>alert(1)</script>"
        body = "<html>Search results for: <script>alert(1)</script></html>"
        assert _classify_reflection(payload, body) == "unescaped"

    def test_html_escaped_reflection(self):
        """Payload reflected as HTML entities → 'html_escaped'."""
        payload = "<script>alert(1)</script>"
        body = "<html>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</html>"
        assert _classify_reflection(payload, body) == "html_escaped"

    def test_not_reflected(self):
        """Payload absent from body → 'not_reflected'."""
        payload = "<script>alert(1)</script>"
        body = "<html>Search results for: safe query</html>"
        assert _classify_reflection(payload, body) == "not_reflected"

    def test_empty_payload(self):
        """Empty payload → 'not_reflected'."""
        assert _classify_reflection("", "<html>body</html>") == "not_reflected"

    def test_empty_body(self):
        """Empty body → 'not_reflected'."""
        assert _classify_reflection("<script>alert(1)</script>", "") == "not_reflected"

    def test_special_chars_escaped(self):
        """Payload with special chars reflected as HTML entities."""
        payload = '" autofocus onfocus=alert(1) x="'
        body = f'<input value="&#34; autofocus onfocus=alert(1) x=&#34;">'
        assert _classify_reflection(payload, body) == "html_escaped"

    def test_lt_gt_escaped(self):
        """Payload with < and > reflected as &lt; and &gt;."""
        payload = "<img src=x onerror=alert(1)>"
        body = "<html>Result: &lt;img src=x onerror=alert(1)&gt;</html>"
        assert _classify_reflection(payload, body) == "html_escaped"

    def test_ampersand_escaped(self):
        """Payload with & reflected as &amp;."""
        payload = "a & b"
        body = "Result: a &amp; b"
        assert _classify_reflection(payload, body) == "html_escaped"

    def test_mixed_escaping(self):
        """If ANY part of payload is unescaped, return 'unescaped' (not 'html_escaped')."""
        payload = "<script>alert(1)</script>"
        # Partially escaped — but the raw payload is NOT in body,
        # so it falls through to the escaped check
        body = "<html><script>alert('not the same');</html>"
        assert _classify_reflection(payload, body) == "not_reflected"

    def test_full_escape_match(self):
        """All special chars escaped → 'html_escaped'."""
        payload = "<img src='x' onerror='alert(1)'>"
        escaped = "&lt;img src=&#39;x&#39; onerror=&#39;alert(1)&#39;&gt;"
        body = f"<html>{escaped}</html>"
        assert _classify_reflection(payload, body) == "html_escaped"


class TestComputeDeltaReflectionContext:
    """Integration tests: compute_delta populates reflection_context correctly."""

    def _make_baseline(self, status_code=200, body="<html>default</html>"):
        import hashlib
        return BaselineFingerprint(
            status_code=status_code,
            content_length=len(body),
            body_hash=hashlib.sha256(body.encode()).hexdigest(),
            avg_response_time=0.1,
            header_names=frozenset(["content-type"]),
        )

    def test_unescaped_reflection_sets_context(self):
        """Payload reflected literally → delta.reflection_context = 'unescaped'."""
        baseline = self._make_baseline()
        body = "<html>Result: <script>alert(1)</script></html>"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/html"},
            response_time=0.1,
            payload="<script>alert(1)</script>",
        )
        assert delta.has_reflected_payload
        assert delta.reflection_context == "unescaped"
        assert delta.is_confirmed_hit

    def test_html_escaped_does_not_set_confirmed_hit(self):
        """A2a regression: html_escaped must NOT set is_confirmed_hit = True."""
        baseline = self._make_baseline()
        body = "<html>Result: &lt;script&gt;alert(1)&lt;/script&gt;</html>"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/html"},
            response_time=0.1,
            payload="<script>alert(1)</script>",
        )
        assert delta.has_reflected_payload
        assert delta.reflection_context == "html_escaped"
        assert not delta.is_confirmed_hit, \
            "html_escaped reflection should NOT be a confirmed hit"

    def test_no_reflection_no_hit(self):
        """Payload not reflected → no confirmed hit from reflection alone."""
        baseline = self._make_baseline()
        body = "<html>Result: normal query</html>"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/html"},
            response_time=0.1,
            payload="<script>alert(1)</script>",
        )
        assert not delta.has_reflected_payload
        assert delta.reflection_context == "not_reflected"
        assert not delta.is_confirmed_hit

    def test_reflection_context_in_to_dict(self):
        """reflection_context must appear in delta.to_dict()."""
        baseline = self._make_baseline()
        body = "<html>Result: <script>alert(1)</script></html>"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/html"},
            response_time=0.1,
            payload="<script>alert(1)</script>",
        )
        d = delta.to_dict()
        assert "reflection_context" in d
        assert d["reflection_context"] == "unescaped"

    def test_to_dict_includes_file_disclosure_field(self):
        """A4 forward-compat: has_file_disclosure field must be in to_dict."""
        baseline = self._make_baseline()
        body = "<html>default</html>"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/html"},
            response_time=0.1,
            payload="test",
        )
        d = delta.to_dict()
        assert "has_file_disclosure" in d