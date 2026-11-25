from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from security_analyzer.models import ScanResult


_DEFAULT_TYPE_CHECK = {
    "status": "not_requested",
    "message": None,
    "issues": [],
    "error_count": 0,
    "warning_count": 0,
    "note_count": 0,
    "files_checked": 0,
    "files_skipped": 0,
}


def _connect(database_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _managed_connection(database_path: str | Path) -> Iterator[sqlite3.Connection]:
    connection = _connect(database_path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    declaration: str,
) -> None:
    existing = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        )


def init_db(database_path: str | Path) -> None:
    """Create or migrate the scan-history schema without storing source code."""
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _managed_connection(path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                file_name TEXT NOT NULL,
                status TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                severity_counts TEXT NOT NULL,
                syntax_error TEXT,
                scanner_warnings TEXT NOT NULL,
                file_count INTEGER NOT NULL DEFAULT 1,
                files_scanned TEXT NOT NULL DEFAULT '[]',
                file_errors TEXT NOT NULL DEFAULT '[]',
                type_check TEXT NOT NULL DEFAULT '{}',
                deduplicated_findings INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                source TEXT NOT NULL,
                cwe_id TEXT,
                related_findings TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                UNIQUE (scan_id, finding_id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan_id
            ON findings(scan_id);
            """
        )

        # Migrate databases created by v0.3/v0.4 in place.
        _ensure_column(connection, "scans", "file_count", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(connection, "scans", "files_scanned", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "scans", "file_errors", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "scans", "type_check", "TEXT NOT NULL DEFAULT '{}'" )
        _ensure_column(
            connection,
            "scans",
            "deduplicated_findings",
            "INTEGER NOT NULL DEFAULT 0",
        )
        _ensure_column(
            connection,
            "findings",
            "related_findings",
            "TEXT NOT NULL DEFAULT '[]'",
        )


def save_scan(
    database_path: str | Path,
    scan_id: str,
    created_at: str,
    file_name: str,
    result: ScanResult,
) -> None:
    """Persist scan metadata and findings, never the submitted source code."""
    payload = result.to_dict()
    if payload["syntax_error"]:
        status = "syntax_error"
    elif payload.get("file_errors"):
        status = "completed_with_errors"
    else:
        status = "completed"

    with _managed_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO scans (
                id, created_at, file_name, status, total_findings,
                severity_counts, syntax_error, scanner_warnings,
                file_count, files_scanned, file_errors, type_check,
                deduplicated_findings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                created_at,
                file_name,
                status,
                payload["total_findings"],
                json.dumps(payload["severity_counts"]),
                json.dumps(payload["syntax_error"]),
                json.dumps(payload["scanner_warnings"]),
                payload.get("file_count", 1),
                json.dumps(payload.get("files_scanned", [payload["file_path"]])),
                json.dumps(payload.get("file_errors", [])),
                json.dumps(payload.get("type_check", _DEFAULT_TYPE_CHECK)),
                payload.get("deduplicated_findings", 0),
            ),
        )

        for finding in payload["findings"]:
            connection.execute(
                """
                INSERT INTO findings (
                    scan_id, finding_id, rule_id, file_path, line_number,
                    severity, confidence, title, description, evidence,
                    recommendation, source, cwe_id, related_findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding["finding_id"],
                    finding["rule_id"],
                    finding["file_path"],
                    finding["line_number"],
                    finding["severity"],
                    finding["confidence"],
                    finding["title"],
                    finding["description"],
                    finding["evidence"],
                    finding["recommendation"],
                    finding["source"],
                    finding["cwe_id"],
                    json.dumps(finding.get("related_findings", [])),
                ),
            )


def list_scans(database_path: str | Path, limit: int = 50) -> list[dict[str, Any]]:
    with _managed_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, file_name, status, total_findings,
                   severity_counts, file_count, deduplicated_findings, type_check
            FROM scans
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    summaries = []
    for row in rows:
        type_check = json.loads(row["type_check"] or "{}")
        summaries.append(
            {
                "scan_id": row["id"],
                "created_at": row["created_at"],
                "file_name": row["file_name"],
                "status": row["status"],
                "total_findings": row["total_findings"],
                "severity_counts": json.loads(row["severity_counts"]),
                "file_count": row["file_count"],
                "deduplicated_findings": row["deduplicated_findings"],
                "type_check_status": type_check.get("status", "not_requested"),
                "type_error_count": type_check.get("error_count", 0),
            }
        )
    return summaries


def get_scan(database_path: str | Path, scan_id: str) -> dict[str, Any] | None:
    with _managed_connection(database_path) as connection:
        scan = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if scan is None:
            return None

        finding_rows = connection.execute(
            """
            SELECT finding_id, rule_id, file_path, line_number, severity,
                   confidence, title, description, evidence, recommendation,
                   source, cwe_id, related_findings
            FROM findings
            WHERE scan_id = ?
            ORDER BY file_path ASC, line_number ASC, finding_id ASC
            """,
            (scan_id,),
        ).fetchall()

    findings = []
    for row in finding_rows:
        finding = dict(row)
        finding["related_findings"] = json.loads(finding["related_findings"] or "[]")
        findings.append(finding)

    type_check = json.loads(scan["type_check"] or "{}")
    if not type_check:
        type_check = dict(_DEFAULT_TYPE_CHECK)

    return {
        "scan_id": scan["id"],
        "created_at": scan["created_at"],
        "file_name": scan["file_name"],
        "status": scan["status"],
        "file_path": scan["file_name"],
        "file_count": scan["file_count"],
        "files_scanned": json.loads(scan["files_scanned"] or "[]"),
        "file_errors": json.loads(scan["file_errors"] or "[]"),
        "total_findings": scan["total_findings"],
        "severity_counts": json.loads(scan["severity_counts"]),
        "syntax_error": json.loads(scan["syntax_error"]),
        "scanner_warnings": json.loads(scan["scanner_warnings"]),
        "type_check": type_check,
        "deduplicated_findings": scan["deduplicated_findings"],
        "findings": findings,
    }
