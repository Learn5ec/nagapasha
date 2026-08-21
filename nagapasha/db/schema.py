"""SQLite storage layer for engagements, findings, and audit logs.

All tables are created on first connection. Uses in-memory SQLite by default.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS engagements (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    target_host     TEXT NOT NULL,
    target_url      TEXT NOT NULL,
    method          TEXT NOT NULL,
    scope_confirmed INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'planning',
    rate_limit_pps  REAL,
    jwt_expires_at  REAL,
    tech_stack_json TEXT,
    generated_script_path TEXT,
    notes           TEXT,
    retention_days  INTEGER DEFAULT 30,
    engagement_end  TEXT  -- Optional: when to delete data after engagement ends
);

CREATE TABLE IF NOT EXISTS parameters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    name            TEXT NOT NULL,
    location        TEXT NOT NULL,
    inferred_type   TEXT NOT NULL,
    raw_value       TEXT NOT NULL,
    is_fuzz_target  INTEGER NOT NULL DEFAULT 0,
    do_not_fuzz     INTEGER NOT NULL DEFAULT 1,
    attack_class    TEXT,
    payload_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    parameter_id    INTEGER REFERENCES parameters(id),
    parameter_name  TEXT NOT NULL,
    attack_class    TEXT NOT NULL,
    payload         TEXT NOT NULL,
    placement_mode  TEXT NOT NULL,
    encoding        TEXT,
    severity        TEXT,
    evidence_req    TEXT,
    evidence_resp   TEXT,
    confidence      REAL,
    specialist_verdict TEXT,
    specialist_notes TEXT,
    wstg_reference  TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT REFERENCES engagements(id),
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    stage           TEXT NOT NULL,
    action          TEXT NOT NULL,
    detail_json     TEXT
);

CREATE TABLE IF NOT EXISTS llm_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT REFERENCES engagements(id),
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    stage           TEXT NOT NULL,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    status          TEXT,
    error_message   TEXT
);
"""


class EngagementStore:
    """SQLite CRUD operations for engagements."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path is None:
            self.db_path = Path(":memory:")
            self._in_memory = True
        else:
            self.db_path = db_path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._in_memory = False
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def create_engagement(
        self,
        target_host: str,
        target_url: str,
        method: str,
        scope_confirmed: bool = False,
        notes: Optional[str] = None,
    ) -> str:
        """Create a new engagement. Returns the engagement ID."""
        eid = str(uuid.uuid4())[:8]
        self._conn.execute(
            """INSERT INTO engagements
               (id, target_host, target_url, method, scope_confirmed, notes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (eid, target_host, target_url, method,
             1 if scope_confirmed else 0, notes),
        )
        self._conn.commit()
        return eid

    def update_engagement(
        self,
        engagement_id: str,
        **kwargs: Any,
    ) -> None:
        """Update an engagement row with the given fields."""
        allowed = {"status", "rate_limit_pps", "jwt_expires_at",
                   "tech_stack_json", "generated_script_path", "notes",
                   "scope_confirmed"}
        filtered = {k: v for k, v in kwargs.items() if k in allowed}
        if not filtered:
            return

        sets = ", ".join(f"{k} = ?" for k in filtered)
        values = list(filtered.values()) + [engagement_id]
        self._conn.execute(
            f"UPDATE engagements SET {sets} WHERE id = ?",
            values,
        )
        self._conn.commit()

    def get_engagement(self, engagement_id: str) -> Optional[dict[str, Any]]:
        """Get a single engagement by ID."""
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_engagements(self) -> list[dict[str, Any]]:
        """Get all engagements, ordered by most recent first."""
        rows = self._conn.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_engagement_status(
        self, engagement_id: str, status: str
    ) -> None:
        """Update only the status field of an engagement."""
        self._conn.execute(
            "UPDATE engagements SET status = ? WHERE id = ?",
            (status, engagement_id),
        )
        self._conn.commit()

    def log_audit(
        self,
        engagement_id: str,
        stage: str,
        action: str,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        """Log an audit event."""
        detail_json = json.dumps(detail or {})
        self._conn.execute(
            """INSERT INTO audit_log (engagement_id, stage, action, detail_json)
               VALUES (?, ?, ?, ?)""",
            (engagement_id, stage, action, detail_json),
        )
        self._conn.commit()

    def log_llm_call(
        self,
        engagement_id: str,
        stage: str,
        input_tokens: int,
        output_tokens: int,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Log an LLM call for cost tracking."""
        self._conn.execute(
            """INSERT INTO llm_calls
               (engagement_id, stage, input_tokens, output_tokens, status, error_message)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (engagement_id, stage, input_tokens, output_tokens, status, error_message),
        )
        self._conn.commit()

    def add_finding(
        self,
        engagement_id: str,
        parameter_name: str,
        attack_class: str,
        payload: str,
        placement_mode: str,
        encoding: Optional[str],
        severity: str,
        evidence_req: Optional[dict],
        evidence_resp: Optional[dict],
        confidence: float,
        wstg_reference: Optional[str] = None,
    ) -> str:
        """Add a finding. Returns the finding ID."""
        fid = str(uuid.uuid4())
        self._conn.execute(
            """INSERT INTO findings
               (id, engagement_id, parameter_name, attack_class, payload,
                placement_mode, encoding, severity, evidence_req, evidence_resp,
                confidence, wstg_reference)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (fid, engagement_id, parameter_name, attack_class, payload,
             placement_mode, encoding, severity,
             json.dumps(evidence_req) if evidence_req else None,
             json.dumps(evidence_resp) if evidence_resp else None,
             confidence, wstg_reference),
        )
        self._conn.commit()
        return fid

    def get_findings(self, engagement_id: str) -> list[dict[str, Any]]:
        """Get all findings for an engagement, ordered by severity."""
        rows = self._conn.execute(
            """SELECT * FROM findings
               WHERE engagement_id = ?
               ORDER BY
                   CASE severity
                       WHEN 'confirmed' THEN 1
                       WHEN 'near_miss' THEN 2
                       ELSE 3
                   END,
                   confidence DESC""",
            (engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "EngagementStore":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def cleanup_expired_engagements(
    db_path: Optional[Path] = None,
    retention_days: int = 30,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Clean up expired engagement data based on retention policy.

    Args:
        db_path: Database path (uses in-memory if None)
        retention_days: Number of days to retain data (default: 30)
        dry_run: If True, only count expired engagements without deleting

    Returns:
        Stats dict with deleted engagement IDs and affected rows
    """
    import sqlite3
    from datetime import datetime, timedelta, timezone

    conn = sqlite3.connect(str(db_path) if db_path else ":memory:")
    conn.row_factory = sqlite3.Row

    # Find expired engagements
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()

    expired = conn.execute(
        """SELECT id, created_at, status, target_url
           FROM engagements
           WHERE created_at < ?
           OR (engagement_end IS NOT NULL AND engagement_end < ?)""",
        (cutoff_date, cutoff_date),
    ).fetchall()

    stats = {
        "expired_count": len(expired),
        "deleted_ids": [],
        "deleted_findings": 0,
        "deleted_parameters": 0,
    }

    if dry_run or not expired:
        conn.close()
        return stats

    if not dry_run:
        for eng in expired:
            eng_id = eng["id"]
            stats["deleted_ids"].append(eng_id)

            # Delete findings
            findings_deleted = conn.execute(
                "DELETE FROM findings WHERE engagement_id = ?",
                (eng_id,),
            ).rowcount
            stats["deleted_findings"] += findings_deleted

            # Delete parameters
            params_deleted = conn.execute(
                "DELETE FROM parameters WHERE engagement_id = ?",
                (eng_id,),
            ).rowcount
            stats["deleted_parameters"] += params_deleted

            # Delete engagement
            conn.execute(
                "DELETE FROM engagements WHERE id = ?",
                (eng_id,),
            )

            # Delete audit log
            conn.execute(
                "DELETE FROM audit_log WHERE engagement_id = ?",
                (eng_id,),
            )

            # Delete LLM calls
            conn.execute(
                "DELETE FROM llm_calls WHERE engagement_id = ?",
                (eng_id,),
            )

        conn.commit()

    conn.close()
    return stats


def retention_report(db_path: Optional[Path] = None) -> dict[str, Any]:
    """Generate retention policy report.

    Args:
        db_path: Database path

    Returns:
        Report dict with engagement counts and storage size
    """
    import sqlite3
    from pathlib import Path

    conn = sqlite3.connect(str(db_path) if db_path else ":memory:")
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
    active = conn.execute(
        "SELECT COUNT(*) FROM engagements WHERE status IN ('running', 'recon_complete')"
    ).fetchone()[0]
    completed = conn.execute(
        "SELECT COUNT(*) FROM engagements WHERE status = 'completed'"
    ).fetchone()[0]

    report = {
        "total_engagements": total,
        "active": active,
        "completed": completed,
        "db_path": str(db_path) if db_path else ":memory:",
        "db_size_bytes": db_path.stat().st_size if db_path and db_path.exists() else 0,
    }

    conn.close()
    return report
