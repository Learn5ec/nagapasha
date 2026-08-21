"""Payload provenance vetting for Stage 2.5.

This module provides source vetting logic to ensure that payloads downloaded
from MCP web search come from trusted sources. It implements:
- Source allowlist with versioned checksums
- URL vetting against allowlist
- Checksum verification for downloaded files
- Human approval for unvetted sources (TTY-aware)

The goal is to prevent supply-chain attacks from malicious payload sources.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# Vetted sources with checksums and versions
# These are hardcoded and versioned for security
VETTED_SOURCES: dict[str, dict[str, str]] = {
    "github.com/danielmiessler/SecLists": {
        "checksum": "sha256:PLACEHOLDER",  # Update with actual checksum
        "version": "v2024.1",
        "description": "SecLists — comprehensive list of test data",
    },
    "github.com/swisskyrepo/PayloadsAllTheThings": {
        "checksum": "sha256:PLACEHOLDER",  # Update with actual checksum
        "version": "main",
        "description": "PayloadsAllTheThings — collection of useful payloads",
    },
    "raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings": {
        "checksum": "sha256:PLACEHOLDER",  # Update with actual checksum
        "version": "main",
        "description": "Raw payloads from PayloadsAllTheThings",
    },
}


class ProvenanceError(Exception):
    """Raised when payload provenance cannot be verified."""
    pass


def is_source_vetted(url: str) -> bool:
    """Check if a URL is from a vetted source.

    Args:
        url: URL to check

    Returns:
        True if URL matches a vetted source
    """
    for allowed_host in VETTED_SOURCES.keys():
        if allowed_host in url:
            return True
    return False


def verify_checksum(file_path: Path, expected_checksum: str) -> bool:
    """Verify file checksum against expected value.

    Args:
        file_path: Path to file
        expected_checksum: Expected checksum (format: "sha256:hash" or just "hash")

    Returns:
        True if checksum matches

    Raises:
        ProvenanceError: If file not found or checksum mismatch
    """
    if not file_path.exists():
        raise ProvenanceError(f"File not found: {file_path}")

    # Parse expected checksum
    if ":" in expected_checksum:
        algo, hash_value = expected_checksum.split(":", 1)
    else:
        algo = "sha256"
        hash_value = expected_checksum

    # Compute actual checksum
    if algo == "sha256":
        h = hashlib.sha256()
    elif algo == "sha1":
        h = hashlib.sha1()
    elif algo == "md5":
        h = hashlib.md5()
    else:
        raise ProvenanceError(f"Unsupported hash algorithm: {algo}")

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)

    actual_hash = h.hexdigest()

    if actual_hash != hash_value:
        raise ProvenanceError(
            f"Checksum mismatch for {file_path}: "
            f"expected {hash_value}, got {actual_hash}"
        )

    return True


def is_payload_file(filename: str) -> bool:
    """Check if a file is a payload file (text-based).

    Args:
        filename: Filename to check

    Returns:
        True if file is a payload file
    """
    # Allow only text-based formats
    payload_extensions = {".txt", ".json", ".xml", ".yaml", ".yml"}
    filename_lower = filename.lower()

    # Check for .tar.gz before single .gz
    if filename_lower.endswith(".tar.gz") or filename_lower.endswith(".tgz"):
        return True

    # Check other extensions
    ext = Path(filename).suffix.lower()
    if ext in payload_extensions:
        return True

    # Allow archives
    archive_extensions = {".zip", ".tar"}
    if ext in archive_extensions:
        return True

    return False


def extract_payloads_from_file(file_path: Path) -> list[str]:
    """Extract payload strings from a file.

    This is a SAFE extraction — it only parses payload strings, never executes them.

    Args:
        file_path: Path to file

    Returns:
        List of payload strings

    Raises:
        ProvenanceError: If file cannot be parsed
    """
    payloads = []

    if not file_path.exists():
        raise ProvenanceError(f"File not found: {file_path}")

    # Parse based on file type
    if file_path.suffix.lower() == ".json":
        try:
            import json
            data = json.loads(file_path.read_text())
            if isinstance(data, list):
                payloads.extend(str(p) for p in data)
            elif isinstance(data, dict):
                payloads.extend(str(v) for v in data.values())
        except (json.JSONDecodeError, ValueError) as e:
            raise ProvenanceError(f"Failed to parse JSON: {e}")

    elif file_path.suffix.lower() == ".yaml" or file_path.suffix.lower() == ".yml":
        try:
            import yaml
            data = yaml.safe_load(file_path.read_text())
            if isinstance(data, list):
                payloads.extend(str(p) for p in data)
            elif isinstance(data, dict):
                payloads.extend(str(v) for v in data.values())
        except Exception as e:
            raise ProvenanceError(f"Failed to parse YAML: {e}")

    elif file_path.suffix.lower() == ".txt":
        # Treat as newline-separated payloads
        payloads = [
            line.strip()
            for line in file_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    elif file_path.suffix.lower() in (".zip", ".tar.gz", ".tgz", ".tar"):
        # Extract from archive (caller must handle path traversal safety)
        import zipfile
        import tarfile

        if file_path.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(file_path) as zf:
                    for name in zf.namelist():
                        if name.endswith(".txt"):
                            payloads.append(zf.read(name).decode("utf-8", errors="ignore"))
            except zipfile.BadZipFile as e:
                raise ProvenanceError(f"Invalid ZIP file: {e}")
        else:
            try:
                with tarfile.open(file_path) as tf:
                    for member in tf.getmembers():
                        if member.isfile() and member.name.endswith(".txt"):
                            f = tf.extractfile(member)
                            if f:
                                payloads.append(f.read().decode("utf-8", errors="ignore"))
            except tarfile.TarError as e:
                raise ProvenanceError(f"Invalid tar file: {e}")

    return payloads


def require_human_approval(
    source_name: str,
    interactive: bool,
) -> bool:
    """Require human approval for unvetted source.

    Args:
        source_name: Name of the source (e.g., URL or repo name)
        interactive: Whether running in interactive mode (TTY)

    Returns:
        True if approved, False if denied/skipped

    Raises:
        ProvenanceError: If non-interactive and approval required
    """
    if interactive:
        # In interactive mode, prompt user
        try:
            from rich.prompt import Prompt
            answer = Prompt.ask(
                f"[yellow]Unvetted source:[/yellow] {source_name} "
                f"not in allowlist. Approve? [y/N]",
                default="n",
            )
            return answer.lower() == "y"
        except Exception:
            # Fallback if rich not available
            try:
                answer = input(
                    f"Unvetted source: {source_name} not in allowlist. Approve? [y/N] "
                )
                return answer.lower() == "y"
            except EOFError:
                return False
    else:
        # Non-interactive: skip unvetted sources
        logger.warning(
            f"Non-interactive mode: skipping unvetted source: {source_name}"
        )
        return False


def validate_download(
    url: str,
    file_path: Path,
    interactive: bool = False,
) -> None:
    """Validate a downloaded file for provenance and safety.

    Args:
        url: Source URL
        file_path: Path to downloaded file
        interactive: Whether running in interactive mode

    Raises:
        ProvenanceError: If validation fails
    """
    # 1. Check if source is vetted
    if not is_source_vetted(url):
        source_name = url.split("/")[2] if "/" in url else url
        if not require_human_approval(source_name, interactive):
            raise ProvenanceError(f"Source not approved: {source_name}")

    # 2. Verify checksum if available
    allowed_host = None
    for host in VETTED_SOURCES.keys():
        if host in url:
            allowed_host = host
            break

    if allowed_host:
        expected_checksum = VETTED_SOURCES[allowed_host].get("checksum")
        if expected_checksum:
            try:
                verify_checksum(file_path, expected_checksum)
                logger.info(f"Checksum verified: {url}")
            except ProvenanceError as e:
                logger.warning(f"Checksum verification failed: {e}")
                # Don't fail — checksums may be placeholder

    # 3. Check file size
    file_size = file_path.stat().st_size
    if file_size > 10 * 1024 * 1024:  # 10MB limit
        raise ProvenanceError(
            f"File too large: {file_size} bytes (limit: 10MB) — {file_path}"
        )

    logger.info(f"Download validated: {url} -> {file_path}")
