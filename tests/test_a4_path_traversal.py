"""A4 tests: path traversal category + file content disclosure detection.

Verifies:
- path_traversal category exists with unix/windows/wrapper variants
- FILE_CONTENT_SIGNATURES detect /etc/passwd, win.ini, raw PHP source
- has_file_disclosure sets is_confirmed_hit = True
- dialect_hint="windows" filters out unix variants
"""

import pytest
from nagapasha.engine.diff import (
    FILE_CONTENT_SIGNATURES,
    ResponseDelta,
    BaselineFingerprint,
    compute_delta,
)
from nagapasha.utils.technique_categories import (
    TECHNIQUE_CATEGORIES,
    CATEGORY_TARGET_LOCATIONS,
)


# ---------------------------------------------------------------------------
# path_traversal category structure
# ---------------------------------------------------------------------------

class TestPathTraversalCategory:
    """A4: Verify path traversal technique category structure."""

    def test_path_traversal_category_exists(self):
        """A4: path_traversal must be in TECHNIQUE_CATEGORIES."""
        assert "path_traversal" in TECHNIQUE_CATEGORIES

    def test_path_traversal_has_all_variants_in_generic_key(self):
        """A4: path_traversal is dialect_agnostic — variants under 'generic' key."""
        variants = TECHNIQUE_CATEGORIES["path_traversal"]["variants"]["generic"]
        # Unix variants
        assert any("../../" in v for v in variants)
        assert any("....//" in v for v in variants)  # filter-bypass
        assert any("%2f" in v for v in variants)     # URL-encoded
        assert any("%252f" in v for v in variants)   # double URL-encoded
        assert any("%00" in v for v in variants)     # null-byte
        # Windows variants
        assert any("\\..\\" in v or "..%5c" in v for v in variants)
        assert any("win.ini" in v for v in variants)
        # Wrapper variants
        assert any("php://filter" in v for v in variants)
        assert any("file://" in v for v in variants)

    def test_path_traversal_is_dialect_agnostic(self):
        """A4: path_traversal must be marked dialect_agnostic (not SQL-specific)."""
        assert TECHNIQUE_CATEGORIES["path_traversal"].get("dialect_agnostic") is True

    def test_path_traversal_in_target_locations(self):
        """A4: path_traversal must be in CATEGORY_TARGET_LOCATIONS."""
        assert "path_traversal" in CATEGORY_TARGET_LOCATIONS


# ---------------------------------------------------------------------------
# FILE_CONTENT_SIGNATURES
# ---------------------------------------------------------------------------

class TestFileContentSignatures:
    """A4: Verify positive file content signatures detect disclosure."""

    def test_passwd_signature(self):
        """A4: /etc/passwd content matches root:.*:0:0: pattern."""
        import re
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        assert any(sig.search(body) for sig in FILE_CONTENT_SIGNATURES)

    def test_winini_signature(self):
        """A4: win.ini content matches [boot loader] and [fonts] patterns."""
        import re
        body = "[boot loader]\n[extensions]\n[fonts]"
        assert any(sig.search(body) for sig in FILE_CONTENT_SIGNATURES)

    def test_php_source_signature(self):
        """A4: Raw PHP source matches <?php pattern."""
        import re
        body = "<?php\n// This is a PHP file\necho 'hello';"
        assert any(sig.search(body) for sig in FILE_CONTENT_SIGNATURES)

    def test_ssh_public_key_signature(self):
        """A4: SSH public key matches BEGIN PUBLIC KEY pattern."""
        import re
        body = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
        assert any(sig.search(body) for sig in FILE_CONTENT_SIGNATURES)

    def test_private_key_signature(self):
        """A4: Private key matches BEGIN RSA PRIVATE KEY pattern."""
        import re
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        assert any(sig.search(body) for sig in FILE_CONTENT_SIGNATURES)

    def test_no_false_positive_safe_body(self):
        """A4: Safe body content should not match any signature."""
        import re
        body = "<html><body><h1>Welcome to our site</h1></body></html>"
        assert not any(sig.search(body) for sig in FILE_CONTENT_SIGNATURES)


# ---------------------------------------------------------------------------
# compute_delta file disclosure integration
# ---------------------------------------------------------------------------

class TestComputeDeltaFileDisclosure:
    """A4: Integration tests for file disclosure detection in compute_delta."""

    def _make_baseline(self, status_code=200, body="<html>default</html>"):
        import hashlib
        return BaselineFingerprint(
            status_code=status_code,
            content_length=len(body),
            body_hash=hashlib.sha256(body.encode()).hexdigest(),
            avg_response_time=0.1,
            header_names=frozenset(["content-type"]),
        )

    def test_passwd_disclosure_sets_file_disclosure(self):
        """A4: Response with /etc/passwd content → has_file_disclosure = True."""
        baseline = self._make_baseline()
        body = "root:x:0:0:root:/root:/bin/bash"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/plain"},
            response_time=0.1,
            payload="../../../etc/passwd",
        )
        assert delta.has_file_disclosure
        assert delta.is_confirmed_hit
        assert any("file-disclosure" in d for d in delta.delta_details)

    def test_winini_disclosure_sets_file_disclosure(self):
        """A4: Response with win.ini content → has_file_disclosure = True."""
        baseline = self._make_baseline()
        body = "[boot loader]\n[extensions]\n[fonts]"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/plain"},
            response_time=0.1,
            payload="..\\..\\..\\windows\\win.ini",
        )
        assert delta.has_file_disclosure
        assert delta.is_confirmed_hit

    def test_php_source_disclosure_sets_file_disclosure(self):
        """A4: Response with raw PHP source → has_file_disclosure = True."""
        baseline = self._make_baseline()
        body = "<?php\n// This is a PHP file\necho 'hello';"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/plain"},
            response_time=0.1,
            payload="php://filter/convert.base64-encode/resource=index.php",
        )
        assert delta.has_file_disclosure
        assert delta.is_confirmed_hit

    def test_no_disclosure_safe_body(self):
        """A4: Response without file content → has_file_disclosure = False."""
        baseline = self._make_baseline()
        body = "<html><body><h1>Welcome</h1></body></html>"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/html"},
            response_time=0.1,
            payload="../../../etc/passwd",
        )
        assert not delta.has_file_disclosure
        assert not delta.is_confirmed_hit

    def test_file_disclosure_in_to_dict(self):
        """A4: has_file_disclosure must appear in delta.to_dict()."""
        baseline = self._make_baseline()
        body = "root:x:0:0:root:/root:/bin/bash"
        delta = compute_delta(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={"content-type": "text/plain"},
            response_time=0.1,
            payload="../../../etc/passwd",
        )
        d = delta.to_dict()
        assert "has_file_disclosure" in d
        assert d["has_file_disclosure"] is True


# ---------------------------------------------------------------------------
# Path traversal variant emission (no dialect filtering — OS-specific, not SQL-specific)
# ---------------------------------------------------------------------------

class TestPathTraversalVariantEmission:
    """A4: Verify path_traversal payloads are emitted regardless of dialect_hint."""

    def _build_payloads(self, req, param):
        """Import and call the private builder function."""
        from nagapasha.cli import _build_technique_category_payloads
        return _build_technique_category_payloads(
            param=param,
            req=req,
            tech_stack=None,
            waf_detected=False,
            waf_name=None,
            dialect_hint=req.dialect_hint,
        )

    def _make_param(self, name="file", location="query"):
        from nagapasha.models.request_model import ParameterModel
        return ParameterModel(
            name=name,
            location=location,
            inferred_type="filename",
            raw_value="test.txt",
            is_fuzz_target=True,
            do_not_fuzz=False,
        )

    def _make_req(self, dialect_hint=None):
        from nagapasha.models.request_model import RequestModel
        return RequestModel(
            method="GET",
            url="http://example.com/api/file",
            base_url="http://example.com",
            headers={"Host": "example.com"},
            dialect_hint=dialect_hint,
        )

    def test_all_variants_emitted_without_dialect_hint(self):
        """Without dialect_hint, all path_traversal variants are emitted."""
        req = self._make_req(dialect_hint=None)
        param = self._make_param()
        candidates = self._build_payloads(req, param)

        pt_payloads = [c for c in candidates
                       if c.attack_class == "path_traversal"]
        payload_texts = [c.payload for c in pt_payloads]

        # Must include unix variants (../../etc/passwd)
        assert any("../../" in p for p in payload_texts)
        # Must include windows variants (..\\..\\)
        assert any("\\..\\" in p for p in payload_texts)
        # Must include wrapper variants (php://)
        assert any("php://filter" in p for p in payload_texts)

    def test_all_variants_emitted_with_dialect_hint(self):
        """Even with dialect_hint, path_traversal emits all variants (OS-agnostic)."""
        req = self._make_req(dialect_hint="postgres")
        param = self._make_param()
        candidates = self._build_payloads(req, param)

        pt_payloads = [c for c in candidates
                       if c.attack_class == "path_traversal"]
        payload_texts = [c.payload for c in pt_payloads]

        # Path traversal is OS-specific, not SQL-specific — emit all
        assert any("../../" in p for p in payload_texts)
        assert any("\\..\\" in p for p in payload_texts)
