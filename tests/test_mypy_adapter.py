from __future__ import annotations

import subprocess

from security_analyzer.integrations.mypy_adapter import run_mypy


def test_mypy_reports_are_parsed_and_kept_separate(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.importlib.util.find_spec",
        lambda name: object(),
    )

    def fake_run(command, **kwargs):
        target = command[-1]
        return subprocess.CompletedProcess(
            command,
            1,
            stdout=f'{target}:2:5: error: Incompatible types in assignment [assignment]\n',
            stderr="",
        )

    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.subprocess.run",
        fake_run,
    )

    result = run_mypy("value: int = 'wrong'\n", "sample.py")

    assert result["status"] == "completed"
    assert result["error_count"] == 1
    assert result["issues"] == [
        {
            "file_path": "sample.py",
            "line_number": 2,
            "column": 5,
            "severity": "error",
            "message": "Incompatible types in assignment",
            "code": "assignment",
        }
    ]


def test_mypy_missing_is_a_non_fatal_optional_result(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.importlib.util.find_spec",
        lambda name: None,
    )

    result = run_mypy("print('ok')\n", "sample.py")

    assert result["status"] == "unavailable"
    assert result["issues"] == []
    assert "not installed" in result["message"]


def test_mypy_timeout_is_reported_without_crashing(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.importlib.util.find_spec",
        lambda name: object(),
    )

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=1)

    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.subprocess.run",
        timeout,
    )

    result = run_mypy("print('ok')\n", "sample.py", timeout_seconds=1)
    assert result["status"] == "timed_out"
    assert result["files_checked"] == 0


def test_mypy_checks_multiple_sources_in_one_process(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.importlib.util.find_spec",
        lambda name: object(),
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        first = command[-2]
        second = command[-1]
        return subprocess.CompletedProcess(
            command,
            1,
            stdout=(
                f"{first}:1:1: error: Bad first type [assignment]\n"
                f"{second}:4:2: warning: Check second type [misc]\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.subprocess.run",
        fake_run,
    )

    from security_analyzer.integrations.mypy_adapter import run_mypy_sources

    result = run_mypy_sources([
        ("src/first.py", "value: int = 'bad'\n"),
        ("src/second.py", "value = 2\n"),
    ])

    assert len(calls) == 1
    assert result["files_checked"] == 2
    assert result["error_count"] == 1
    assert result["warning_count"] == 1
    assert {issue["file_path"] for issue in result["issues"]} == {
        "src/first.py",
        "src/second.py",
    }


def test_mypy_invocation_uses_fixed_args_and_no_shell(monkeypatch):
    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.importlib.util.find_spec",
        lambda name: object(),
    )
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(
        "security_analyzer.integrations.mypy_adapter.subprocess.run",
        fake_run,
    )

    run_mypy("print('safe')\n", "../untrusted/name.py")

    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 30
    assert "--config-file" in captured["command"]
    assert "--follow-imports=skip" in captured["command"]
    assert all("untrusted" not in arg for arg in captured["command"])
