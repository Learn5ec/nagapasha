"""Template support for engagement profiles.

Templates are reusable JSON files that capture engagement configuration:
target URL, method, headers, cookies, body, and fuzzing preferences.

Usage:
    template = TemplateManager(template_dir="templates")
    template.create(name="my-api", curl_command="curl -X POST ...")
    template.load("my-api") -> dict

Template schema:
    {
        "name": "string",
        "version": "1.0",
        "target_url": "string",
        "method": "GET|POST|...",
        "headers": { ... },
        "cookies": { ... },
        "body": "string",
        "body_type": "json|form|raw|null",
        "fuzz_preferences": {
            "max_requests": 1000,
            "batch_size": 1,
            "dry_run": false,
        }
    }
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TemplateError(Exception):
    """Raised when a template operation fails."""


class TemplateManager:
    """Manages engagement templates on disk.

    Features:
        - Create templates from curl commands
        - Load templates by name
        - List available templates
        - Validate template schema
        - Save/load with JSON
    """

    VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    VALID_BODY_TYPES = {"json", "form", "raw", "null"}
    TEMPLATE_VERSION = "1.0"

    def __init__(self, template_dir: Optional[Path] = None) -> None:
        self.template_dir = template_dir or Path("templates")
        self.template_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        name: str,
        target_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        body_type: Optional[str] = None,
        fuzz_preferences: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Create a new template.

        Args:
            name: Template name (used as filename).
            target_url: Target URL.
            method: HTTP method.
            headers: Request headers.
            cookies: Request cookies.
            body: Request body.
            body_type: Body type (json, form, raw, null).
            fuzz_preferences: Fuzzing preferences.

        Returns:
            Path to the created template file.

        Raises:
            TemplateError: If validation fails.
        """
        # Validate
        if not name:
            raise TemplateError("Template name is required")
        if not target_url:
            raise TemplateError("Target URL is required")
        if method.upper() not in self.VALID_METHODS:
            raise TemplateError(
                f"Invalid method: {method}. Must be one of {self.VALID_METHODS}"
            )
        if body_type and body_type not in self.VALID_BODY_TYPES:
            raise TemplateError(
                f"Invalid body_type: {body_type}. Must be one of {self.VALID_BODY_TYPES}"
            )

        # Build template data
        template_data = {
            "name": name,
            "version": self.TEMPLATE_VERSION,
            "target_url": target_url,
            "method": method.upper(),
            "headers": headers or {},
            "cookies": cookies or {},
            "body": body,
            "body_type": body_type or "null",
            "fuzz_preferences": fuzz_preferences or {
                "max_requests": 1000,
                "batch_size": 1,
                "dry_run": False,
            },
        }

        # Save
        template_path = self.template_dir / f"{name}.json"
        if template_path.exists():
            raise TemplateError(f"Template already exists: {template_path}")

        template_path.write_text(json.dumps(template_data, indent=2))
        logger.info(f"Created template: {template_path}")
        return template_path

    def create_from_curl(self, name: str, curl_command: str) -> Path:
        """Create a template from a curl command.

        Args:
            name: Template name.
            curl_command: Full curl command string.

        Returns:
            Path to the created template file.
        """
        from nagapasha.stages.stage01_parse import parse_curl, CurlParseError

        try:
            req = parse_curl(curl_command)
        except CurlParseError as e:
            raise TemplateError(f"Failed to parse curl command: {e}")

        return self.create(
            name=name,
            target_url=req.url,
            method=req.method,
            headers=dict(req.headers),
            cookies=dict(req.cookies),
            body=req.body,
            body_type=req.body_type,
        )

    def load(self, name: str) -> Dict[str, Any]:
        """Load a template by name.

        Args:
            name: Template name (without .json extension).

        Returns:
            Template data dict.

        Raises:
            TemplateError: If template not found or invalid.
        """
        template_path = self.template_dir / f"{name}.json"
        if not template_path.exists():
            raise TemplateError(f"Template not found: {template_path}")

        try:
            template_data = json.loads(template_path.read_text())
        except json.JSONDecodeError as e:
            raise TemplateError(f"Invalid JSON in template {template_path}: {e}")

        self.validate(template_data)
        return template_data

    def list_templates(self) -> List[Dict[str, str]]:
        """List all available templates.

        Returns:
            List of template info dicts with name, target_url, method.
        """
        templates = []
        for template_path in sorted(self.template_dir.glob("*.json")):
            try:
                template_data = json.loads(template_path.read_text())
                self.validate(template_data)
                templates.append({
                    "name": template_data.get("name", template_path.stem),
                    "target_url": template_data.get("target_url", "N/A"),
                    "method": template_data.get("method", "N/A"),
                })
            except TemplateError:
                logger.warning(f"Skipping invalid template: {template_path}")
                continue
        return templates

    def delete(self, name: str) -> bool:
        """Delete a template by name.

        Args:
            name: Template name.

        Returns:
            True if deleted, False if not found.
        """
        template_path = self.template_dir / f"{name}.json"
        if template_path.exists():
            template_path.unlink()
            logger.info(f"Deleted template: {template_path}")
            return True
        return False

    def validate(self, template_data: Dict[str, Any]) -> None:
        """Validate template data against schema.

        Args:
            template_data: Template data to validate.

        Raises:
            TemplateError: If validation fails.
        """
        required_fields = ["name", "target_url", "method"]
        for field in required_fields:
            if field not in template_data:
                raise TemplateError(f"Missing required field: {field}")

        if template_data["method"] not in self.VALID_METHODS:
            raise TemplateError(
                f"Invalid method: {template_data['method']}"
            )

        if template_data.get("body_type") and template_data["body_type"] not in self.VALID_BODY_TYPES:
            raise TemplateError(
                f"Invalid body_type: {template_data['body_type']}"
            )

    def get_curl_command(self, template_data: Dict[str, Any]) -> str:
        """Generate a curl command from template data.

        Args:
            template_data: Template data.

        Returns:
            curl command string.
        """
        parts = ['curl']

        # Method
        method = template_data.get("method", "GET")
        if method != "GET":
            parts.append(f"-X {method}")

        # URL
        url = template_data.get("target_url", "")
        parts.append(f"'{url}'")

        # Headers
        for key, value in template_data.get("headers", {}).items():
            parts.append(f"-H '{key}: {value}'")

        # Cookies
        for key, value in template_data.get("cookies", {}).items():
            parts.append(f"-b '{key}={value}'")

        # Body
        body = template_data.get("body")
        if body:
            body_type = template_data.get("body_type", "raw")
            if body_type == "json":
                parts.append(f"-H 'Content-Type: application/json'")
                parts.append(f"-d '{body}'")
            elif body_type == "form":
                parts.append(f"-d '{body}'")
            else:
                parts.append(f"-d '{body}'")

        return " \\\n  ".join(parts)
