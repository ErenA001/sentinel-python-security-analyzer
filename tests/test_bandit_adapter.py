from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from security_analyzer.integrations.bandit_adapter import BanditScanError, scan_with_bandit


def test_bandit_json_is_normalized_and_secret_evidence_is_masked(monkeypatch):
    payload = {
        "results": [
            {
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password.",
                "line_number": 1,
                "issue_cwe": {"id": 259},
                "more_info": "https://example.test/bandit-rule",
            }
        ]
    }
    monkeypatch.setattr(
        "security_analyzer.integrations.bandit_adapter.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=json.dumps(payload), stderr="", returncode=0
        ),
    )

    findings = scan_with_bandit('PASSWORD = "do-not-show-this"\n', "demo.py")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "B105"
    assert finding.file_path == "demo.py"
    assert finding.line_number == 1
    assert finding.severity == "HIGH"
    assert finding.confidence == "MEDIUM"
    assert finding.cwe_id == "CWE-259"
    assert finding.source == "bandit"
    assert "do-not-show-this" not in finding.evidence
    assert "[REDACTED]" in finding.evidence
    assert "https://example.test/bandit-rule" in finding.recommendation


def test_bandit_missing_module_returns_clear_error(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.bandit_adapter.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="", stderr="/usr/bin/python: No module named bandit", returncode=1
        ),
    )

    with pytest.raises(BanditScanError, match="Bandit is not installed"):
        scan_with_bandit("print('hello')\n")


def test_bandit_timeout_returns_clear_error(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=1)

    monkeypatch.setattr(
        "security_analyzer.integrations.bandit_adapter.subprocess.run", timeout
    )

    with pytest.raises(BanditScanError, match="timed out"):
        scan_with_bandit("print('hello')\n", timeout_seconds=1)


def test_bandit_command_does_not_use_a_shell(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(stdout='{"results": []}', stderr="", returncode=0)

    monkeypatch.setattr(
        "security_analyzer.integrations.bandit_adapter.subprocess.run", fake_run
    )
    scan_with_bandit("print('hello')\n")

    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 10
    assert "-m" in captured["args"]
    assert "bandit" in captured["args"]


def test_invalid_bandit_json_returns_clear_error(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.bandit_adapter.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="not-json", stderr="", returncode=0
        ),
    )

    with pytest.raises(BanditScanError, match="invalid JSON"):
        scan_with_bandit("print('hello')\n")
