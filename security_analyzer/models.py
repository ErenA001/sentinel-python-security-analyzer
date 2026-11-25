from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    file_path: str
    line_number: int
    severity: str
    confidence: str
    title: str
    description: str
    evidence: str
    recommendation: str
    source: str = "custom_ast_rule"
    cwe_id: str | None = None
    related_findings: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    file_path: str
    findings: list[Finding]
    syntax_error: dict[str, Any] | None = None
    scanner_warnings: list[str] = field(default_factory=list)
    type_check: dict[str, Any] = field(
        default_factory=lambda: {
            "status": "not_requested",
            "issues": [],
            "error_count": 0,
            "warning_count": 0,
            "note_count": 0,
            "files_checked": 0,
            "files_skipped": 0,
        }
    )
    files_scanned: list[str] = field(default_factory=list)
    file_count: int = 1
    file_errors: list[dict[str, Any]] = field(default_factory=list)
    deduplicated_findings: int = 0

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_count": self.file_count,
            "files_scanned": self.files_scanned or [self.file_path],
            "file_errors": self.file_errors,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "syntax_error": self.syntax_error,
            "scanner_warnings": self.scanner_warnings,
            "deduplicated_findings": self.deduplicated_findings,
            "type_check": self.type_check,
            "findings": [finding.to_dict() for finding in self.findings],
        }
