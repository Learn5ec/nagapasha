"""Tests for the HMAC request signing module."""

import pytest

from nagapasha.security.signing import RequestSigner


class TestRequestSigner:
    """Tests for RequestSigner."""

    def setup_method(self):
        """Create a signer with a known secret."""
        self.signer = RequestSigner(secret_key="test-secret-key-123")

    def test_sign_request(self):
        """Should sign a request and include signature."""
        request_data = {
            "method": "GET",
            "url": "https://example.com/api",
            "body": "",
        }
        signed = self.signer.sign_request(request_data)
        assert "X-Test-Signature" in signed
        assert signed["algorithm"] == "sha256"
        assert "timestamp" in signed
        assert signed["method"] == "GET"

    def test_verify_valid_signature(self):
        """Should verify a valid signature."""
        request_data = {
            "method": "POST",
            "url": "https://example.com/api",
            "body": '{"param": "value"}',
        }
        signed = self.signer.sign_request(request_data)
        assert self.signer.verify_signature(signed) is True

    def test_verify_tampered_signature(self):
        """Should reject a tampered request."""
        request_data = {
            "method": "POST",
            "url": "https://example.com/api",
            "body": '{"param": "value"}',
        }
        signed = self.signer.sign_request(request_data)
        # Tamper with the body
        signed["body"] = '{"param": "tampered"}'
        assert self.signer.verify_signature(signed) is False

    def test_verify_missing_signature(self):
        """Should reject a request without signature."""
        request_data = {
            "method": "GET",
            "url": "https://example.com/api",
        }
        assert self.signer.verify_signature(request_data) is False

    def test_verify_wrong_secret(self):
        """Should reject a request signed with wrong secret."""
        request_data = {
            "method": "GET",
            "url": "https://example.com/api",
        }
        signed = self.signer.sign_request(request_data)

        other_signer = RequestSigner(secret_key="wrong-secret")
        assert other_signer.verify_signature(signed) is False

    def test_sign_includes_timestamp(self):
        """Should include timestamp in signed request."""
        request_data = {"method": "GET", "url": "https://example.com"}
        signed = self.signer.sign_request(request_data)
        assert isinstance(signed["timestamp"], float)

    def test_custom_timestamp(self):
        """Should accept a custom timestamp."""
        request_data = {"method": "GET", "url": "https://example.com"}
        ts = 1234567890.0
        signed = self.signer.sign_request(request_data, timestamp=ts)
        assert signed["timestamp"] == ts

    def test_generate_secret_key(self):
        """Should generate a hex-encoded secret key."""
        key = self.signer.generate_secret_key()
        assert len(key) == 64  # 32 bytes = 64 hex chars
        # Verify it's valid hex
        int(key, 16)  # raises ValueError if not valid hex

    def test_generate_short_key(self):
        """Should generate a key of specified length."""
        key = self.signer.generate_secret_key(length=16)
        assert len(key) == 32  # 16 bytes = 32 hex chars
