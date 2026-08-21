"""Tests for PII/secret redaction (Stage 13)."""

from pathlib import Path

import pytest

from nagapasha.security.redact import (
    REDACTION_REPLACEMENT,
    redact_dict,
    redact_evidence,
    redact_text,
)


class TestRedactText:
    def test_redact_email(self):
        """Test email redaction."""
        text = "Contact: john@example.com"
        result = redact_text(text)
        assert "john@example.com" not in result
        assert REDACTION_REPLACEMENT in result

    def test_redact_phone(self):
        """Test phone number redaction."""
        text = "Phone: +1-555-123-4567"
        result = redact_text(text)
        assert "+1-555-123-4567" not in result
        assert REDACTION_REPLACEMENT in result

    def test_redact_ssn(self):
        """Test SSN redaction."""
        text = "SSN: 123-45-6789"
        result = redact_text(text)
        assert "123-45-6789" not in result
        assert REDACTION_REPLACEMENT in result

    def test_redact_credit_card(self):
        """Test credit card redaction."""
        text = "Card: 4111-1111-1111-1111"
        result = redact_text(text)
        assert "4111-1111-1111-1111" not in result

    def test_redact_jwt(self):
        """Test JWT redaction."""
        text = "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        result = redact_text(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_redact_password(self):
        """Test password redaction."""
        text = "password: secret123"
        result = redact_text(text)
        assert "secret123" not in result

    def test_no_redaction_needed(self):
        """Test text without PII is unchanged."""
        text = "This is a test payload: <script>alert(1)</script>"
        result = redact_text(text)
        assert result == text


class TestRedactDict:
    def test_redact_nested_dict(self):
        """Test recursive dict redaction."""
        data = {
            "user_email": "john@example.com",
            "response": {
                "body": "SSN: 123-45-6789",
                "status": 200,
            },
        }

        result = redact_dict(data)
        assert "john@example.com" not in result["user_email"]
        assert "123-45-6789" not in result["response"]["body"]

    def test_redact_list(self):
        """Test list redaction."""
        data = ["john@example.com", "123-45-6789", 200]
        result = redact_dict(data)
        assert "john@example.com" not in result[0]
        assert "123-45-6789" not in result[1]
        assert result[2] == 200  # Non-string unchanged


class TestRedactEvidence:
    def test_redact_evidence_dict(self):
        """Test evidence dict redaction."""
        evidence = {
            "request": "GET /api?email=john@example.com",
            "response": "SSN: 123-45-6789",
            "status_code": 200,
        }

        result = redact_evidence(evidence)
        assert "john@example.com" not in result["request"]
        assert "123-45-6789" not in result["response"]
        assert result["status_code"] == 200
