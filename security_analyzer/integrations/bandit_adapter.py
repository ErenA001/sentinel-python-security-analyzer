from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from security_analyzer.models import Finding
from security_analyzer.rules import redact_evidence


class BanditScanError(RuntimeError):
    """Raised when Bandit cannot complete a scan or return valid JSON."""


def _severity(value: Any) -> str:
    normalized = str(value or "LOW").upper()
    return normalized if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO"


def _confidence(value: Any) -> str:
    normalized = str(value or "MEDIUM").upper()
    return normalized if normalized in {"HIGH", "MEDIUM", "LOW"} else "MEDIUM"


def _cwe_id(issue_cwe: Any) -> str | None:
    if not isinstance(issue_cwe, dict):
        return None
    value = issue_cwe.get("id")
    if value is None or value == "":
        return None
    value_text = str(value)
    return value_text if value_text.startswith("CWE-") else f"CWE-{value_text}"


def scan_with_bandit(
    source: str,
    file_path: str = "<memory>",
    timeout_seconds: int = 10,
) -> list[Finding]:
    """Run Bandit against a temporary copy of source without executing it.

    The subprocess uses the current interpreter, a fixed argument list, and
    shell=False. The caller-supplied file path is used only in the report and
    is never used as a filesystem path or command argument.
    """
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".py",
            prefix="security-analyzer-",
            delete=False,
        ) as temporary_file:
            temporary_file.write(source)
            temporary_path = temporary_file.name

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                "--exit-zero",
                temporary_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BanditScanError(
            f"Bandit scan timed out after {timeout_seconds} seconds."
        ) from exc
    except OSError as exc:
        raise BanditScanError("Bandit could not be started on this system.") from exc
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)

    output = completed.stdout.strip()
    if not output:
        if "No module named bandit" in completed.stderr:
            raise BanditScanError(
                "Bandit is not installed. Run 'python -m pip install bandit'."
            )
        raise BanditScanError("Bandit returned no JSON output.")

    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise BanditScanError("Bandit returned invalid JSON output.") from exc

    results = payload.get("results", []) if isinstance(payload, dict) else None
    if not isinstance(results, list):
        raise BanditScanError("Bandit JSON output has an unexpected format.")

    source_lines = source.splitlines()
    findings: list[Finding] = []
    for index, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            continue

        try:
            line_number = max(1, int(item.get("line_number", 1)))
        except (TypeError, ValueError):
            line_number = 1

        raw_evidence = (
            source_lines[line_number - 1]
            if line_number <= len(source_lines)
            else str(item.get("code", "")).strip()
        )
        evidence = redact_evidence(raw_evidence.strip())

        test_id = str(item.get("test_id") or "BANDIT")
        test_name = str(item.get("test_name") or "security_check")
        title = test_name.replace("_", " ").strip().title()
        description = str(item.get("issue_text") or "Bandit detected a potential issue.")
        more_info = item.get("more_info")
        recommendation = "Review this finding in context and apply the relevant secure coding mitigation."
        if isinstance(more_info, str) and more_info.startswith(("https://", "http://")):
            recommendation += f" Reference: {more_info}"

        findings.append(
            Finding(
                finding_id=f"BANDIT-{test_id}-{line_number}-{index:03d}",
                rule_id=test_id,
                file_path=file_path,
                line_number=line_number,
                severity=_severity(item.get("issue_severity")),
                confidence=_confidence(item.get("issue_confidence")),
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                source="bandit",
                cwe_id=_cwe_id(item.get("issue_cwe")),
            )
        )

    return findings
