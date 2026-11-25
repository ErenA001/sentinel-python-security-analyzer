from __future__ import annotations

from dataclasses import replace
from typing import Any

from security_analyzer.integrations.bandit_adapter import BanditScanError, scan_with_bandit
from security_analyzer.integrations.mypy_adapter import run_mypy, run_mypy_sources
from security_analyzer.models import Finding, ScanResult
from security_analyzer.parser import parse_source
from security_analyzer.rules import SecurityRuleVisitor


_BANDIT_EQUIVALENT_RULES = {
    # Bandit uses CWE-78 for eval while the project rule uses the more specific CWE-95.
    "B307": "PY-SEC-002",
    "B110": "PY-QUAL-001",
}


def _normalize_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge duplicate scanner reports and retain the related scanner metadata."""
    custom_by_cwe: dict[tuple[str, int, str], int] = {}
    custom_by_rule_line: dict[tuple[str, int, str], int] = {}
    for index, item in enumerate(findings):
        if item.source != "custom_ast_rule":
            continue
        if item.cwe_id:
            custom_by_cwe.setdefault(
                (item.file_path, item.line_number, item.cwe_id),
                index,
            )
        custom_by_rule_line.setdefault(
            (item.file_path, item.line_number, item.rule_id),
            index,
        )

    normalized: list[Finding] = []
    original_to_normalized: dict[int, int] = {}
    seen_exact: dict[tuple[Any, ...], int] = {}
    deduplicated_count = 0

    for original_index, item in enumerate(findings):
        matching_custom_index = None
        if item.source == "bandit":
            if item.cwe_id:
                matching_custom_index = custom_by_cwe.get(
                    (item.file_path, item.line_number, item.cwe_id)
                )
            if matching_custom_index is None:
                equivalent_rule = _BANDIT_EQUIVALENT_RULES.get(item.rule_id)
                if equivalent_rule:
                    matching_custom_index = custom_by_rule_line.get(
                        (item.file_path, item.line_number, equivalent_rule)
                    )

        if matching_custom_index is not None:
            normalized_index = original_to_normalized.get(matching_custom_index)
            if normalized_index is None:
                custom_item = findings[matching_custom_index]
                exact_key = (
                    custom_item.source,
                    custom_item.rule_id,
                    custom_item.file_path,
                    custom_item.line_number,
                    custom_item.title,
                    custom_item.evidence,
                )
                normalized_index = seen_exact.get(exact_key)
                if normalized_index is None:
                    normalized_index = len(normalized)
                    normalized.append(custom_item)
                    seen_exact[exact_key] = normalized_index
                original_to_normalized[matching_custom_index] = normalized_index

            related = {
                "finding_id": item.finding_id,
                "rule_id": item.rule_id,
                "title": item.title,
                "source": item.source,
                "severity": item.severity,
                "confidence": item.confidence,
                "cwe_id": item.cwe_id,
            }
            current = normalized[normalized_index]
            if related not in current.related_findings:
                normalized[normalized_index] = replace(
                    current,
                    related_findings=[*current.related_findings, related],
                )
            deduplicated_count += 1
            continue

        exact_key = (
            item.source,
            item.rule_id,
            item.file_path,
            item.line_number,
            item.title,
            item.evidence,
        )
        if exact_key in seen_exact:
            original_to_normalized[original_index] = seen_exact[exact_key]
            deduplicated_count += 1
            continue

        original_to_normalized[original_index] = len(normalized)
        seen_exact[exact_key] = len(normalized)
        normalized.append(item)

    return normalized, deduplicated_count


def _type_check_not_requested() -> dict[str, Any]:
    return {
        "status": "not_requested",
        "message": None,
        "issues": [],
        "error_count": 0,
        "warning_count": 0,
        "note_count": 0,
        "files_checked": 0,
        "files_skipped": 0,
    }


def analyze_source(
    source: str,
    file_path: str = "<memory>",
    include_bandit: bool = True,
    include_mypy: bool = False,
) -> ScanResult:
    """Analyze source text without importing or executing the program."""
    parsed = parse_source(source, filename=file_path)
    if parsed.tree is None:
        type_check = (
            {
                **_type_check_not_requested(),
                "status": "skipped",
                "message": "Type checking skipped because Python syntax could not be parsed.",
                "files_skipped": 1,
            }
            if include_mypy
            else _type_check_not_requested()
        )
        return ScanResult(
            file_path=file_path,
            findings=[],
            syntax_error=parsed.error,
            type_check=type_check,
            files_scanned=[file_path],
            file_errors=[{"file_path": file_path, "syntax_error": parsed.error}],
        )

    visitor = SecurityRuleVisitor(source=source, file_path=file_path)
    visitor.visit(parsed.tree)
    findings = list(visitor.findings)
    scanner_warnings: list[str] = []

    if include_bandit:
        try:
            findings.extend(scan_with_bandit(source, file_path=file_path))
        except BanditScanError as exc:
            scanner_warnings.append(str(exc))

    normalized, deduplicated_count = _normalize_findings(findings)
    type_check = run_mypy(source, file_path) if include_mypy else _type_check_not_requested()

    return ScanResult(
        file_path=file_path,
        findings=normalized,
        scanner_warnings=scanner_warnings,
        type_check=type_check,
        files_scanned=[file_path],
        deduplicated_findings=deduplicated_count,
    )


def analyze_sources(
    sources: list[tuple[str, str]],
    archive_name: str,
    include_bandit: bool = True,
    include_mypy: bool = False,
) -> ScanResult:
    """Analyze a validated list of Python sources from a ZIP without extracting them."""
    results = [
        analyze_source(
            source,
            file_path=file_path,
            include_bandit=include_bandit,
            include_mypy=False,
        )
        for file_path, source in sources
    ]

    findings = [finding for result in results for finding in result.findings]
    scanner_warnings = [
        f"{result.file_path}: {warning}"
        for result in results
        for warning in result.scanner_warnings
    ]
    file_errors = [
        error
        for result in results
        for error in result.file_errors
    ]
    if include_mypy:
        valid_sources = [
            (file_path, source)
            for (file_path, source), result in zip(sources, results)
            if result.syntax_error is None
        ]
        skipped_count = len(sources) - len(valid_sources)
        type_check = run_mypy_sources(valid_sources)
        type_check["files_skipped"] = skipped_count
        if skipped_count and type_check.get("status") == "completed":
            type_check["status"] = "partial"
            type_check["message"] = (
                f"Skipped {skipped_count} file(s) with Python syntax errors."
            )
    else:
        type_check = _type_check_not_requested()

    return ScanResult(
        file_path=archive_name,
        findings=findings,
        syntax_error=None,
        scanner_warnings=scanner_warnings,
        type_check=type_check,
        files_scanned=[file_path for file_path, _ in sources],
        file_count=len(sources),
        file_errors=file_errors,
        deduplicated_findings=sum(result.deduplicated_findings for result in results),
    )
