"""Local SQLite cache for scan history and baseline fingerprints."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".cache" / "secret-scanner" / "history.db"


class Cache:
    """SQLite-backed cache for scan history and baselines."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    files_scanned INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    severity_counts TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    provider TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    masked_value TEXT,
    commit_sha TEXT,
    detected_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS baseline (
    fingerprint TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    severity TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    file_path TEXT
);
""")

    def record_scan(self, result: Any) -> int:  # noqa: ANN001
        """Record a scan and all its findings. Returns the scan ID."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, scan_type, started_at, finished_at, files_scanned, findings_count, risk_score, severity_counts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.target,
                    result.scan_type,
                    (
                        result.started_at.isoformat()
                        if result.started_at
                        else datetime.now(UTC).isoformat()
                    ),
                    result.finished_at.isoformat() if result.finished_at else None,
                    result.files_scanned,
                    result.finding_count,
                    result.risk_score(),
                    json.dumps(result.severity_counts()),
                ),
            )
            scan_id = cur.lastrowid
            now = datetime.now(UTC).isoformat()
            for f in result.findings:
                conn.execute(
                    "INSERT INTO findings (scan_id, fingerprint, rule_id, rule_name, provider, severity, confidence, file_path, line_number, masked_value, commit_sha, detected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        f.fingerprint,
                        f.rule_id,
                        f.rule_name,
                        f.provider,
                        f.severity.label,
                        f.confidence,
                        f.file_path,
                        f.line_number,
                        f.masked_value,
                        f.commit_sha,
                        now,
                    ),
                )
            conn.commit()
            return scan_id or 0

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    def save_baseline(self, result: Any) -> int:  # noqa: ANN001
        """Replace the baseline with findings from ``result``.

        Returns the number of fingerprints in the new baseline.
        """
        with self._conn() as conn:
            conn.execute("DELETE FROM baseline")
            now = datetime.now(UTC).isoformat()
            # Dedupe by fingerprint; keep first occurrence.
            seen: set[str] = set()
            for f in result.findings:
                if f.fingerprint in seen:
                    continue
                seen.add(f.fingerprint)
                conn.execute(
                    "INSERT OR REPLACE INTO baseline (fingerprint, rule_id, provider, severity, first_seen, file_path) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (f.fingerprint, f.rule_id, f.provider, f.severity.label, now, f.file_path),
                )
            conn.commit()
            return len(seen)

    def load_baseline_fingerprints(self) -> set[str]:
        """Return the set of baseline fingerprints (to suppress)."""
        with self._conn() as conn:
            rows = conn.execute("SELECT fingerprint FROM baseline").fetchall()
            return {row["fingerprint"] for row in rows}

    def baseline_count(self) -> int:
        """Return the number of fingerprints in the baseline."""
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) as c FROM baseline").fetchone()
            return row["c"] if row else 0

    # ------------------------------------------------------------------
    # History queries
    # ------------------------------------------------------------------

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent scans."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]


__all__ = ["Cache", "DEFAULT_DB_PATH"]
