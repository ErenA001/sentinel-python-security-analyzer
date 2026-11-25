from security_analyzer.analyzer import analyze_source
from security_analyzer.models import Finding


def test_syntax_error_returns_no_findings():
    result = analyze_source("def broken(:\n pass\n", "broken.py", include_bandit=False)
    assert result.syntax_error is not None
    assert result.findings == []


def test_result_contains_summary_and_file_path():
    result = analyze_source("eval(user_input)\n", "demo.py", include_bandit=False)
    payload = result.to_dict()
    assert payload["file_path"] == "demo.py"
    assert payload["total_findings"] == 1
    assert payload["severity_counts"]["HIGH"] == 1
    assert payload["findings"][0]["line_number"] == 1
    assert payload["scanner_warnings"] == []


def test_bandit_findings_are_included_when_requested(monkeypatch):
    bandit_finding = Finding(
        finding_id="BANDIT-B101-1-001",
        rule_id="B101",
        file_path="demo.py",
        line_number=1,
        severity="LOW",
        confidence="HIGH",
        title="Assert Used",
        description="Use of assert detected.",
        evidence="assert value",
        recommendation="Review assertion use.",
        source="bandit",
        cwe_id="CWE-703",
    )
    monkeypatch.setattr(
        "security_analyzer.analyzer.scan_with_bandit",
        lambda source, file_path: [bandit_finding],
    )

    result = analyze_source("assert value\n", "demo.py", include_bandit=True)

    assert len(result.findings) == 1
    assert result.findings[0].source == "bandit"


def test_bandit_duplicate_is_removed_when_custom_rule_has_same_cwe_and_line(monkeypatch):
    duplicate = Finding(
        finding_id="BANDIT-B307-1-001",
        rule_id="B307",
        file_path="demo.py",
        line_number=1,
        severity="HIGH",
        confidence="HIGH",
        title="Eval Used",
        description="Use of eval detected.",
        evidence="eval(user_input)",
        recommendation="Avoid eval.",
        source="bandit",
        cwe_id="CWE-95",
    )
    monkeypatch.setattr(
        "security_analyzer.analyzer.scan_with_bandit",
        lambda source, file_path: [duplicate],
    )

    result = analyze_source("eval(user_input)\n", "demo.py", include_bandit=True)

    assert len(result.findings) == 1
    assert result.findings[0].source == "custom_ast_rule"


def test_mypy_type_issues_are_kept_separate_from_security_findings(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.analyzer.run_mypy",
        lambda source, file_path: {
            "status": "completed",
            "message": None,
            "issues": [
                {
                    "file_path": file_path,
                    "line_number": 1,
                    "column": 1,
                    "severity": "error",
                    "message": "Incompatible types in assignment",
                    "code": "assignment",
                }
            ],
            "error_count": 1,
            "warning_count": 0,
            "note_count": 0,
            "files_checked": 1,
        },
    )

    result = analyze_source(
        "value: int = 'wrong'\n",
        "typed.py",
        include_bandit=False,
        include_mypy=True,
    )

    assert result.findings == []
    assert result.type_check["error_count"] == 1
    assert result.to_dict()["type_check"]["issues"][0]["code"] == "assignment"


def test_duplicate_bandit_detection_is_attached_to_custom_finding(monkeypatch):
    duplicate = Finding(
        finding_id="BANDIT-B307-1-001",
        rule_id="B307",
        file_path="demo.py",
        line_number=1,
        severity="MEDIUM",
        confidence="HIGH",
        title="Eval Used",
        description="Use of eval detected.",
        evidence="eval(user_input)",
        recommendation="Review eval use.",
        source="bandit",
        cwe_id="CWE-95",
    )
    monkeypatch.setattr(
        "security_analyzer.analyzer.scan_with_bandit",
        lambda source, file_path: [duplicate],
    )

    result = analyze_source("eval(user_input)\n", "demo.py", include_bandit=True)

    assert len(result.findings) == 1
    assert result.deduplicated_findings == 1
    assert result.findings[0].source == "custom_ast_rule"
    assert result.findings[0].related_findings[0]["rule_id"] == "B307"


def test_zip_source_analysis_aggregates_findings_and_type_check(monkeypatch):
    from security_analyzer.analyzer import analyze_sources

    monkeypatch.setattr(
        "security_analyzer.analyzer.run_mypy_sources",
        lambda sources: {
            "status": "completed",
            "message": None,
            "issues": [
                {
                    "file_path": "pkg/typed.py",
                    "line_number": 1,
                    "column": 1,
                    "severity": "error",
                    "message": "Bad type",
                    "code": "assignment",
                }
            ],
            "error_count": 1,
            "warning_count": 0,
            "note_count": 0,
            "files_checked": len(sources),
            "files_skipped": 0,
        },
    )

    result = analyze_sources(
        [
            ("pkg/unsafe.py", "eval(user_input)\n"),
            ("pkg/typed.py", "value: int = 'wrong'\n"),
        ],
        archive_name="project.zip",
        include_bandit=False,
        include_mypy=True,
    )

    assert result.file_path == "project.zip"
    assert result.file_count == 2
    assert result.files_scanned == ["pkg/unsafe.py", "pkg/typed.py"]
    assert len(result.findings) == 1
    assert result.findings[0].file_path == "pkg/unsafe.py"
    assert result.type_check["error_count"] == 1
    assert result.type_check["issues"][0]["file_path"] == "pkg/typed.py"


def test_known_bandit_equivalents_merge_even_when_cwe_mappings_differ(monkeypatch):
    bandit_findings = [
        Finding(
            finding_id="BANDIT-B307-1-001",
            rule_id="B307",
            file_path="demo.py",
            line_number=1,
            severity="MEDIUM",
            confidence="HIGH",
            title="Blacklist",
            description="eval may be unsafe.",
            evidence="result = eval(user_input)",
            recommendation="Prefer ast.literal_eval.",
            source="bandit",
            cwe_id="CWE-78",
        ),
        Finding(
            finding_id="BANDIT-B110-4-002",
            rule_id="B110",
            file_path="demo.py",
            line_number=4,
            severity="LOW",
            confidence="HIGH",
            title="Try Except Pass",
            description="Try except pass detected.",
            evidence="except Exception:",
            recommendation="Handle the exception.",
            source="bandit",
            cwe_id="CWE-703",
        ),
    ]
    monkeypatch.setattr(
        "security_analyzer.analyzer.scan_with_bandit",
        lambda source, file_path: bandit_findings,
    )

    source = (
        "result = eval(user_input)\n"
        "try:\n"
        "    work()\n"
        "except Exception:\n"
        "    pass\n"
    )
    result = analyze_source(source, "demo.py", include_bandit=True)

    assert len(result.findings) == 2
    by_rule = {finding.rule_id: finding for finding in result.findings}
    assert by_rule["PY-SEC-002"].related_findings[0]["rule_id"] == "B307"
    assert by_rule["PY-QUAL-001"].related_findings[0]["rule_id"] == "B110"
    assert result.deduplicated_findings == 2
