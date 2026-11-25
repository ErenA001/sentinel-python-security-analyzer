from security_analyzer.analyzer import analyze_source
from security_analyzer.reports import render_html_report
from security_analyzer.storage import get_scan, init_db, list_scans, save_scan


def test_sqlite_scan_round_trip_does_not_store_full_source(tmp_path):
    database = tmp_path / "nested" / "history.sqlite3"
    init_db(database)
    result = analyze_source("eval(user_input)\n", "sample.py", include_bandit=False)

    save_scan(database, "scan-123", "2026-11-24T10:00:00+00:00", "sample.py", result)

    stored = get_scan(database, "scan-123")
    assert stored is not None
    assert stored["total_findings"] == 1
    assert stored["findings"][0]["rule_id"] == "PY-SEC-002"
    assert list_scans(database)[0]["scan_id"] == "scan-123"


def test_html_report_escapes_untrusted_values():
    scan = {
        "scan_id": "scan-123",
        "created_at": "2026-11-24T10:00:00+00:00",
        "file_name": "<script>alert(1)</script>.py",
        "status": "completed",
        "total_findings": 1,
        "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "syntax_error": None,
        "scanner_warnings": [],
        "findings": [
            {
                "line_number": 1,
                "severity": "HIGH",
                "rule_id": "PY-SEC-002",
                "title": "<img src=x onerror=alert(1)>",
                "description": "Unsafe <script> text",
                "evidence": "eval('<script>')",
                "recommendation": "Do not execute untrusted input.",
            }
        ],
    }

    html = render_html_report(scan)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_database_migrates_v04_schema_in_place(tmp_path):
    import sqlite3

    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                file_name TEXT NOT NULL,
                status TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                severity_counts TEXT NOT NULL,
                syntax_error TEXT,
                scanner_warnings TEXT NOT NULL
            );
            CREATE TABLE findings (
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
                UNIQUE (scan_id, finding_id)
            );
            """
        )

    init_db(database)
    with sqlite3.connect(database) as connection:
        scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}

    assert {"type_check", "file_count", "files_scanned", "file_errors"}.issubset(scan_columns)
    assert "related_findings" in finding_columns


def test_related_duplicate_detection_and_type_check_round_trip(tmp_path):
    from security_analyzer.models import Finding, ScanResult

    database = tmp_path / "extended.sqlite3"
    init_db(database)
    finding = Finding(
        finding_id="PY-SEC-002-1-001",
        rule_id="PY-SEC-002",
        file_path="sample.py",
        line_number=1,
        severity="HIGH",
        confidence="HIGH",
        title="Dynamic code execution",
        description="eval is used.",
        evidence="eval(user_input)",
        recommendation="Avoid eval.",
        cwe_id="CWE-95",
        related_findings=[{"finding_id": "BANDIT-B307-1-001", "rule_id": "B307", "source": "bandit"}],
    )
    result = ScanResult(
        file_path="sample.py",
        findings=[finding],
        type_check={
            "status": "completed",
            "message": None,
            "issues": [{"file_path": "sample.py", "line_number": 1, "severity": "error", "message": "Bad type"}],
            "error_count": 1,
            "warning_count": 0,
            "note_count": 0,
            "files_checked": 1,
        },
        files_scanned=["sample.py"],
        deduplicated_findings=1,
    )

    save_scan(database, "scan-extended", "2026-11-24T10:00:00+00:00", "sample.py", result)
    stored = get_scan(database, "scan-extended")

    assert stored["type_check"]["error_count"] == 1
    assert stored["deduplicated_findings"] == 1
    assert stored["findings"][0]["related_findings"][0]["rule_id"] == "B307"


def test_html_report_includes_separate_type_check_section_and_related_scanners():
    scan = {
        "scan_id": "scan-type",
        "created_at": "2026-11-24T10:00:00+00:00",
        "file_name": "project.zip",
        "status": "completed",
        "file_count": 1,
        "files_scanned": ["src/demo.py"],
        "deduplicated_findings": 1,
        "total_findings": 1,
        "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "type_check": {
            "status": "completed",
            "error_count": 1,
            "warning_count": 0,
            "files_checked": 1,
            "issues": [
                {
                    "file_path": "src/demo.py",
                    "line_number": 2,
                    "column": 3,
                    "severity": "error",
                    "code": "assignment",
                    "message": "Type mismatch <script>",
                }
            ],
        },
        "findings": [
            {
                "file_path": "src/demo.py",
                "line_number": 1,
                "severity": "HIGH",
                "rule_id": "PY-SEC-002",
                "title": "Dynamic execution",
                "description": "Unsafe call.",
                "evidence": "eval(user_input)",
                "recommendation": "Avoid eval.",
                "related_findings": [
                    {"source": "bandit", "rule_id": "B307"}
                ],
            }
        ],
    }
    html = render_html_report(scan)
    assert "Type safety check (mypy)" in html
    assert "src/demo.py" in html
    assert "bandit B307" in html
    assert "Type mismatch &lt;script&gt;" in html
    assert "Type mismatch <script>" not in html
