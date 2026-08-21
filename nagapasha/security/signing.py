"""HMAC request signing for test security.

Signs outgoing test requests with HMAC-SHA256 to prevent tampering
and ensure test integrity. Used during CI/CD runs where security
is paramount.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, Optional


class RequestSigner:
    """Signs HTTP requests with HMAC-SHA256 for integrity verification.

    Usage:
        signer = RequestSigner(secret_key="my-secret-key")
        signed = signer.sign_request({
            "method": "GET",
            "url": "https://example.com/api",
            "body": '{"param": "value"}',
        })
        # signed contains the original data plus signature and timestamp
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "sha256",
        header_name: str = "X-Test-Signature",
    ) -> None:
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.header_name = header_name

    def sign_request(
        self,
        request_data: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Sign a request with HMAC-SHA256.

        Args:
            request_data: The request data to sign (method, url, body, etc.).
            timestamp: Optional timestamp (defaults to current time).

        Returns:
            Signed request dict with signature and timestamp added.
        """
        if timestamp is None:
            timestamp = time.time()

        # Create canonical form for signing
        canonical = self._build_canonical(request_data, timestamp)

        # Compute HMAC
        signature = hmac.new(
            self.secret_key.encode(),
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest()

        # Return signed request with metadata
        signed = dict(request_data)
        signed[self.header_name] = signature
        signed["timestamp"] = timestamp
        signed["algorithm"] = self.algorithm

        return signed

    def verify_signature(
        self,
        signed_request: Dict[str, Any],
    ) -> bool:
        """Verify a signed request's HMAC.

        Args:
            signed_request: The signed request dict.

        Returns:
            True if signature is valid, False otherwise.
        """
        signature = signed_request.get(self.header_name)
        timestamp = signed_request.get("timestamp")

        if not signature or timestamp is None:
            return False

        # Rebuild canonical from the request data (minus signature/timestamp)
        data = {k: v for k, v in signed_request.items()
                if k not in (self.header_name, "timestamp", "algorithm")}
        canonical = self._build_canonical(data, timestamp)

        # Verify using constant-time comparison
        expected = hmac.new(
            self.secret_key.encode(),
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    def _build_canonical(
        self,
        request_data: Dict[str, Any],
        timestamp: float,
    ) -> str:
        """Build canonical string for signing.

        Canonical form: method|url|body|timestamp
        """
        method = request_data.get("method", "").upper()
        url = request_data.get("url", "")
        body = request_data.get("body", "") or ""

        return f"{method}|{url}|{body}|{timestamp}"

    def generate_secret_key(self, length: int = 32) -> str:
        """Generate a random secret key for testing.

        Args:
            length: Key length in bytes (default 32).

        Returns:
            Hex-encoded secret key.
        """
        import secrets
        return secrets.token_hex(length)
