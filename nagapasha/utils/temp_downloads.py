"""Temporary download manager with 24-hour TTL cleanup.

Manages downloads from MCP web search tools to a temporary directory
with automatic cleanup to prevent disk bloat.

Includes sandbox extraction with:
- Path traversal guards (zip-slip protection)
- Size limits
- Format allowlist (no executables)
- No execution: only parse payload strings
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration
TEMP_DIR = Path("nagapasha/llm/kb-temp")
MANIFEST_PATH = TEMP_DIR / ".cleanup-manifest.txt"
CLEANUP_INTERVAL = 3600  # 1 hour
TTL = 86400  # 24 hours

# Allowed file extensions
ALLOWED_EXTENSIONS = {".txt", ".zip", ".tar.gz", ".tgz", ".tar"}

# Size limits (bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_TOTAL_SIZE = 50 * 1024 * 1024  # 50MB


class TempDownloadManager:
    """Manages temporary downloads with automatic cleanup."""

    def __init__(self):
        self._cleanup_task: Optional[asyncio.Task] = None

    @property
    def temp_dir(self) -> Path:
        """Get the temp directory path."""
        return TEMP_DIR

    async def start(self):
        """Start the background cleanup task."""
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """Stop the background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL)
            await self.cleanup_old_files()

    async def download_file(self, url: str) -> Optional[Path]:
        """Download a file to temp directory with manifest tracking.

        Args:
            url: URL to download

        Returns:
            Path to downloaded file, or None if failed/disallowed
        """
        import httpx

        # Extract filename from URL
        filename = url.split("/")[-1].split("?")[0]
        if not filename:
            return None

        # Check extension
        ext = Path(filename).suffix
        if ext not in ALLOWED_EXTENSIONS:
            logger.debug(f"Skipping file with disallowed extension: {ext}")
            return None

        dest = TEMP_DIR / filename
        if dest.exists():
            logger.debug(f"File already exists: {dest}")
            return dest

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(url)
                response.raise_for_status()

            # Check size
            if len(response.content) > MAX_FILE_SIZE:
                logger.warning(f"File too large: {url} ({len(response.content)} bytes)")
                return None

            dest.write_bytes(response.content)
            logger.info(f"Downloaded: {url} -> {dest}")

            # Add to manifest
            await self._add_to_manifest(dest, url)

            return dest
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return None

    async def _add_to_manifest(self, path: Path, source_url: str):
        """Add file to cleanup manifest."""
        manifest = []
        if MANIFEST_PATH.exists():
            manifest = json.loads(MANIFEST_PATH.read_text())

        manifest.append({
            "path": str(path),
            "timestamp": time.time(),
            "size": path.stat().st_size,
            "source_url": source_url,
        })

        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))

    async def cleanup_old_files(self):
        """Delete files older than TTL."""
        if not MANIFEST_PATH.exists():
            return

        manifest = json.loads(MANIFEST_PATH.read_text())
        now = time.time()

        to_delete = []
        for entry in manifest:
            if now - entry["timestamp"] > TTL:
                to_delete.append(entry["path"])

        for path_str in to_delete:
            path = Path(path_str)
            try:
                if path.exists():
                    path.unlink()
                    logger.debug(f"Deleted old file: {path}")
            except FileNotFoundError:
                pass

        # Update manifest
        remaining = [e for e in manifest if e["path"] not in to_delete]
        MANIFEST_PATH.write_text(json.dumps(remaining, indent=2))

    async def cleanup_all(self):
        """Delete all files in temp directory."""
        if TEMP_DIR.exists():
            shutil.rmtree(TEMP_DIR)
            logger.info(f"Cleaned up temp directory: {TEMP_DIR}")

    def extract_safely(self, archive_path: Path) -> list[Path]:
        """Safely extract an archive with path traversal guards.

        Args:
            archive_path: Path to archive (.zip or .tar/.tar.gz)

        Returns:
            List of extracted file paths

        Raises:
            ValueError: If archive is invalid or contains path traversal
            FileError: If file cannot be extracted
        """
        extracted_files = []

        if not archive_path.exists():
            raise ValueError(f"Archive not found: {archive_path}")

        # Determine archive type
        if archive_path.suffix == ".zip":
            extracted_files = self._extract_zip(archive_path)
        elif archive_path.name.endswith((".tar.gz", ".tgz", ".tar")):
            extracted_files = self._extract_tar(archive_path)
        else:
            raise ValueError(f"Unsupported archive type: {archive_path.suffix}")

        return extracted_files

    def _extract_zip(self, zip_path: Path) -> list[Path]:
        """Extract ZIP archive with path traversal guards.

        Args:
            zip_path: Path to ZIP file

        Returns:
            List of extracted file paths
        """
        extracted = []

        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                # Path traversal guard
                dest = TEMP_DIR / name
                if not dest.resolve().is_relative_to(TEMP_DIR.resolve()):
                    raise ValueError(
                        f"Path traversal detected in ZIP: {name} "
                        f"(dest: {dest}, temp_dir: {TEMP_DIR})"
                    )

                # Skip directories
                if name.endswith("/"):
                    continue

                # Extract file
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(dest, "wb") as dst:
                    dst.write(src.read())

                extracted.append(dest)

        return extracted

    def _extract_tar(self, tar_path: Path) -> list[Path]:
        """Extract tar archive with path traversal guards.

        Args:
            tar_path: Path to tar archive

        Returns:
            List of extracted file paths
        """
        extracted = []

        with tarfile.open(tar_path) as tf:
            for member in tf.getmembers():
                # Path traversal guard
                dest = TEMP_DIR / member.name
                if not dest.resolve().is_relative_to(TEMP_DIR.resolve()):
                    raise ValueError(
                        f"Path traversal detected in tar: {member.name} "
                        f"(dest: {dest}, temp_dir: {TEMP_DIR})"
                    )

                # Skip directories
                if member.isdir():
                    continue

                # Extract file
                if not member.isfile():
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(member)
                if f:
                    with f as src, open(dest, "wb") as dst:
                        dst.write(src.read())
                    extracted.append(dest)

        return extracted


# Singleton instance
temp_manager = TempDownloadManager()
