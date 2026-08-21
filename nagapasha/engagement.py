"""EngagementContext — Authorization gate data model.

This module defines the EngagementContext data model that represents an authorized
security testing engagement. It includes:
- Signed engagement ID for audit trail
- Scope allowlist/denylist for host/path restrictions
- Method and attack class restrictions
- Time window enforcement
- Kill switch mechanism (file-based)
- HMAC-SHA256 signing to prevent tampering

The EngagementContext is created by `nagapasha init` (Stage 0) and used by all
subsequent commands (recon, run, report) to enforce scope and authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from nagapasha.utils.config import get_config


@dataclass
class EngagementContext:
    """Authorization context for a security testing engagement.

    This dataclass represents all the authorization and scope information for an
    engagement. It is signed with HMAC-SHA256 to prevent tampering and used by
    the ScopeChecker to validate every outbound request.

    Attributes:
        engagement_id: Unique, immutable identifier for this engagement
        roe_hash: SHA256 hash of the signed ROE document
        scope_allowlist: Host patterns allowed (e.g., "example.com", "*.example.com")
        scope_denylist: Host patterns explicitly excluded (win over allowlist)
        allowed_methods: HTTP methods allowed (e.g., ["GET", "POST"])
        allowed_attack_classes: Attack classes allowed (can exclude destructive)
        time_window_start: Engagement start time (UTC)
        time_window_end: Engagement end time (UTC)
        authorized_by: Name/email of the person who authorized this engagement
        roe_path: Path to the ROE document (for audit)
        kill_switch: Whether the kill switch has been triggered
        created_at: When this context was created
        signature: HMAC-SHA256 signature of all context fields
        settings: Additional settings (dry_run, non_interactive, etc.)
    """

    engagement_id: str
    roe_hash: str
    scope_allowlist: list[str] = field(default_factory=list)
    scope_denylist: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    allowed_attack_classes: list[str] = field(default_factory=list)
    time_window_start: Optional[datetime] = None
    time_window_end: Optional[datetime] = None
    authorized_by: str = ""
    roe_path: Optional[str] = None
    kill_switch: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = ""
    settings: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementContext":
        """Create EngagementContext from a dictionary.

        Args:
            data: Dictionary with engagement context fields

        Returns:
            EngagementContext instance

        Raises:
            ValueError: If signature verification fails or required fields missing
        """
        required_fields = ["engagement_id", "roe_hash", "signature"]
        for field_name in required_fields:
            if field_name not in data:
                raise ValueError(f"Missing required field: {field_name}")

        context = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

        # Verify signature
        if not context.verify_signature():
            raise ValueError(
                "EngagementContext signature verification failed — "
                "context may have been tampered with"
            )

        return context

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Handles datetime objects by converting them to ISO format strings.

        Returns:
            Dictionary with all context fields
        """
        d = asdict(self)
        # Convert datetime objects to ISO format strings
        for key, value in d.items():
            if isinstance(value, datetime):
                d[key] = value.isoformat()
            elif isinstance(value, (list, tuple)):
                d[key] = [
                    item.isoformat() if isinstance(item, datetime) else item
                    for item in value
                ]
        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON.

        Args:
            indent: JSON indentation level

        Returns:
            JSON string
        """
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "EngagementContext":
        """Deserialize from JSON.

        Args:
            json_str: JSON string

        Returns:
            EngagementContext instance
        """
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "EngagementContext":
        """Deserialize from YAML.

        Args:
            yaml_str: YAML string

        Returns:
            EngagementContext instance
        """
        import yaml

        data = yaml.safe_load(yaml_str)
        return cls.from_dict(data)

    def save(self, path: Path) -> None:
        """Save to file.

        Args:
            path: Path to save to (.ctx or .yaml)
        """
        path = Path(path)
        if path.suffix == ".yaml":
            import yaml

            path.write_text(yaml.dump(self.to_dict(), default_flow_style=False))
        else:
            path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> "EngagementContext":
        """Load from file.

        Args:
            path: Path to load from (.ctx or .yaml)

        Returns:
            EngagementContext instance
        """
        path = Path(path)
        if path.suffix == ".yaml":
            import yaml

            return cls.from_yaml(path.read_text())
        else:
            return cls.from_json(path.read_text())

    def verify_signature(self) -> bool:
        """Verify HMAC-SHA256 signature.

        The signature is computed over all fields except `signature` itself,
        using the HMAC key from config or environment.

        Returns:
            True if signature is valid
        """
        config = get_config()
        hmac_key = config.get("engagement_hmac_key", "")

        if not hmac_key:
            # For testing/dev, skip signature verification if no key is set
            return True

        # Compute signature over all fields except `signature`
        sig_fields = {k: v for k, v in self.to_dict().items() if k != "signature"}
        sig_data = json.dumps(sig_fields, sort_keys=True).encode()
        expected_signature = hmac.new(
            hmac_key.encode(), sig_data, hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_signature, self.signature)

    @classmethod
    def create(
        cls,
        engagement_id: str,
        roe_hash: str,
        scope_allowlist: list[str],
        scope_denylist: list[str],
        allowed_methods: list[str],
        allowed_attack_classes: list[str],
        time_window_start: datetime,
        time_window_end: datetime,
        authorized_by: str,
        roe_path: Optional[str] = None,
        settings: Optional[dict[str, Any]] = None,
    ) -> "EngagementContext":
        """Create a new EngagementContext with signature.

        This is the factory method for creating a new engagement context.
        It computes the HMAC-SHA256 signature before returning.

        Args:
            engagement_id: Unique engagement identifier
            roe_hash: SHA256 hash of ROE document
            scope_allowlist: Host patterns allowed
            scope_denylist: Host patterns excluded
            allowed_methods: HTTP methods allowed
            allowed_attack_classes: Attack classes allowed
            time_window_start: Engagement start time
            time_window_end: Engagement end time
            authorized_by: Authorizer name/email
            roe_path: Path to ROE document
            settings: Additional settings

        Returns:
            Signed EngagementContext instance
        """
        context = cls(
            engagement_id=engagement_id,
            roe_hash=roe_hash,
            scope_allowlist=scope_allowlist,
            scope_denylist=scope_denylist,
            allowed_methods=allowed_methods,
            allowed_attack_classes=allowed_attack_classes,
            time_window_start=time_window_start,
            time_window_end=time_window_end,
            authorized_by=authorized_by,
            roe_path=roe_path,
            created_at=datetime.now(timezone.utc),
            settings=settings or {},
        )

        # Compute signature
        config = get_config()
        hmac_key = config.get("engagement_hmac_key", "")

        if hmac_key:
            sig_fields = {k: v for k, v in context.to_dict().items() if k != "signature"}
            sig_data = json.dumps(sig_fields, sort_keys=True).encode()
            context.signature = hmac.new(
                hmac_key.encode(), sig_data, hashlib.sha256
            ).hexdigest()
        else:
            # For testing/dev, generate a placeholder signature
            import secrets

            context.signature = f"dev_{secrets.token_hex(32)}"

        return context

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within engagement scope.

        Args:
            url: URL to check

        Returns:
            True if URL is in scope
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""

        # Check denylist first (win over allowlist)
        for deny_pattern in self.scope_denylist:
            if self._match_pattern(host, deny_pattern):
                return False

        # Check allowlist
        if not self.scope_allowlist:
            return True  # No allowlist means all hosts allowed

        for allow_pattern in self.scope_allowlist:
            if self._match_pattern(host, allow_pattern):
                return True

        return False

    def is_method_allowed(self, method: str) -> bool:
        """Check if HTTP method is allowed.

        Args:
            method: HTTP method (GET, POST, etc.)

        Returns:
            True if method is allowed
        """
        return method.upper() in [m.upper() for m in self.allowed_methods]

    def is_attack_class_allowed(self, attack_class: str) -> bool:
        """Check if attack class is allowed.

        Args:
            attack_class: Attack class name

        Returns:
            True if attack class is allowed
        """
        if not self.allowed_attack_classes:
            return True  # No restrictions

        return attack_class in self.allowed_attack_classes

    def is_time_window_valid(self) -> bool:
        """Check if current time is within engagement time window.

        Returns:
            True if within time window
        """
        now = datetime.now(timezone.utc)

        if self.time_window_start and now < self.time_window_start:
            return False

        if self.time_window_end and now > self.time_window_end:
            return False

        return True

    def is_kill_switch_active(self) -> bool:
        """Check if kill switch is active.

        Reads from the kill switch file in the engagement state directory.

        Returns:
            True if kill switch is active
        """
        state_dir = self._state_dir()
        kill_switch_file = state_dir / "kill_switch"

        if kill_switch_file.exists():
            return kill_switch_file.read_text().strip() == "KILL"

        return False

    def _state_dir(self) -> Path:
        """Get the state directory for this engagement.

        Returns:
            Path to state directory
        """
        from nagapasha.utils.paths import get_state_dir

        return get_state_dir(self.engagement_id)

    @staticmethod
    def _match_pattern(host: str, pattern: str) -> bool:
        """Match host against pattern with wildcard support.

        Args:
            host: Hostname to check
            pattern: Pattern with optional wildcard (e.g., "*.example.com")

        Returns:
            True if host matches pattern
        """
        if pattern.startswith("*."):
            # Wildcard match: *.example.com matches foo.example.com
            suffix = pattern[2:]  # Remove "*."
            return host.endswith(suffix) and host != suffix
        return host == pattern

    def __str__(self) -> str:
        """Human-readable representation."""
        return (
            f"EngagementContext(\n"
            f"  engagement_id={self.engagement_id},\n"
            f"  authorized_by={self.authorized_by},\n"
            f"  scope={len(self.scope_allowlist)} allow, {len(self.scope_denylist)} deny,\n"
            f"  methods={self.allowed_methods},\n"
            f"  time_window={self.time_window_start} to {self.time_window_end}\n"
            f")"
        )


def hash_roe(roe_content: str) -> str:
    """Compute SHA256 hash of ROE document.

    Args:
        roe_content: ROE document content

    Returns:
        SHA256 hex digest
    """
    return hashlib.sha256(roe_content.encode()).hexdigest()


def validate_roe(roe_data: dict[str, Any], engagement_id: str) -> EngagementContext:
    """Validate ROE data and create EngagementContext.

    Args:
        roe_data: ROE data from YAML/JSON
        engagement_id: Engagement ID from ROE or command line

    Returns:
        Validated EngagementContext

    Raises:
        ValueError: If ROE validation fails
    """
    # Extract required fields
    required_fields = ["target_hosts", "allowed_methods", "authorized_by"]
    for field_name in required_fields:
        if field_name not in roe_data:
            raise ValueError(f"Missing required ROE field: {field_name}")

    # Parse scope
    scope_allowlist = roe_data.get("target_hosts", [])
    scope_denylist = roe_data.get("excluded_hosts", [])
    allowed_methods = roe_data.get("allowed_methods", ["GET", "POST"])

    # Parse attack class restrictions (optional)
    allowed_attack_classes = roe_data.get("allowed_attack_classes", [])

    # Parse time window (optional)
    time_window_start = None
    time_window_end = None

    if "time_window" in roe_data:
        tw = roe_data["time_window"]
        if isinstance(tw, dict):
            time_window_start = datetime.fromisoformat(tw["start"])
            time_window_end = datetime.fromisoformat(tw["end"])
        elif isinstance(tw, (list, tuple)) and len(tw) == 2:
            time_window_start = datetime.fromisoformat(tw[0])
            time_window_end = datetime.fromisoformat(tw[1])

    # Create engagement context
    context = EngagementContext.create(
        engagement_id=engagement_id,
        roe_hash="",  # Will be set by caller
        scope_allowlist=scope_allowlist,
        scope_denylist=scope_denylist,
        allowed_methods=allowed_methods,
        allowed_attack_classes=allowed_attack_classes,
        time_window_start=time_window_start,
        time_window_end=time_window_end,
        authorized_by=roe_data["authorized_by"],
        roe_path=roe_data.get("path"),
        settings=roe_data.get("settings", {}),
    )

    return context


def write_kill_switch(engagement_id: str) -> None:
    """Write kill switch file.

    Args:
        engagement_id: Engagement ID
    """
    state_dir = get_state_dir(engagement_id)
    state_dir.mkdir(parents=True, exist_ok=True)

    kill_switch_file = state_dir / "kill_switch"
    kill_switch_file.write_text("KILL")


def read_kill_switch(engagement_id: str) -> bool:
    """Read kill switch state.

    Args:
        engagement_id: Engagement ID

    Returns:
        True if kill switch is active
    """
    state_dir = get_state_dir(engagement_id)
    kill_switch_file = state_dir / "kill_switch"

    if kill_switch_file.exists():
        return kill_switch_file.read_text().strip() == "KILL"

    return False


def get_state_dir(engagement_id: str) -> Path:
    """Get state directory for an engagement.

    Args:
        engagement_id: Engagement ID

    Returns:
        Path to state directory
    """
    from nagapasha.utils.paths import get_state_dir

    return get_state_dir(engagement_id)
