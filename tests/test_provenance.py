"""Tests for payload provenance vetting (Stage 2.5)."""

from pathlib import Path

import pytest

from nagapasha.utils.payload_provenance import (
    ProvenanceError,
    extract_payloads_from_file,
    is_payload_file,
    is_source_vetted,
    verify_checksum,
)


class TestIsSourceVetted:
    def test_github_seclists(self):
        """Test SecLists source vetting."""
        assert is_source_vetted("github.com/danielmiessler/SecLists") == True

    def test_github_payloads_all_the_things(self):
        """Test PayloadsAllTheThings source vetting."""
        assert is_source_vetted("github.com/swisskyrepo/PayloadsAllTheThings") == True

    def test_unvetted_source(self):
        """Test unvetted source."""
        assert is_source_vetted("https://evil.com/payloads.txt") == False


class TestIsPayloadFile:
    def test_txt(self):
        """Test .txt file."""
        assert is_payload_file("payloads.txt") == True

    def test_json(self):
        """Test .json file."""
        assert is_payload_file("payloads.json") == True

    def test_zip(self):
        """Test .zip file."""
        assert is_payload_file("payloads.zip") == True

    def test_tar_gz(self):
        """Test .tar.gz file."""
        assert is_payload_file("payloads.tar.gz") == True

    def test_excluded(self):
        """Test excluded file types."""
        assert is_payload_file("payloads.exe") == False
        assert is_payload_file("payloads.dll") == False
        assert is_payload_file("payloads.so") == False


class TestExtractPayloadsFromFile:
    def test_extract_txt(self, tmp_path):
        """Test extracting payloads from .txt file."""
        txt_file = tmp_path / "payloads.txt"
        txt_file.write_text("<script>alert(1)</script>\n' OR '1'='1\n")

        payloads = extract_payloads_from_file(txt_file)
        assert len(payloads) == 2
        assert "<script>alert(1)</script>" in payloads
        assert "' OR '1'='1" in payloads

    def test_extract_json(self, tmp_path):
        """Test extracting payloads from .json file."""
        import json
        json_file = tmp_path / "payloads.json"
        json_file.write_text(json.dumps(["<script>", "' OR 1=1"]))

        payloads = extract_payloads_from_file(json_file)
        assert len(payloads) == 2

    def test_extract_zip(self, tmp_path):
        """Test extracting payloads from .zip file."""
        import zipfile

        zip_file = tmp_path / "payloads.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("payloads.txt", "payload1\npayload2\n")

        payloads = extract_payloads_from_file(zip_file)
        assert len(payloads) == 1
        assert "payload1" in payloads[0]

    def test_extract_missing_file(self, tmp_path):
        """Test extracting from missing file raises error."""
        missing = tmp_path / "missing.txt"

        with pytest.raises(ProvenanceError, match="File not found"):
            extract_payloads_from_file(missing)


class TestVerifyChecksum:
    def test_verify_sha256(self, tmp_path):
        """Test SHA256 checksum verification."""
        import hashlib

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        expected = hashlib.sha256(b"test content").hexdigest()
        assert verify_checksum(test_file, f"sha256:{expected}") == True

    def test_verify_wrong_checksum(self, tmp_path):
        """Test checksum mismatch raises error."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        with pytest.raises(ProvenanceError, match="Checksum mismatch"):
            verify_checksum(test_file, "sha256:wronghash")

    def test_verify_missing_file(self, tmp_path):
        """Test missing file raises error."""
        missing = tmp_path / "missing.txt"

        with pytest.raises(ProvenanceError, match="File not found"):
            verify_checksum(missing, "sha256:hash")
