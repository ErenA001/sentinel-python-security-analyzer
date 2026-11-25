from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 30
_DIAGNOSTIC = re.compile(
    r"^(?:.*[/\\])?target_(?P<index>\d+)\.py:(?P<line>\d+)"
    r"(?::(?P<column>\d+))?:\s+"
    r"(?P<severity>error|warning|note):\s+"
    r"(?P<message>.*?)"
    r"(?:\s+\[(?P<code>[A-Za-z0-9_-]+)\])?$"
)


def _empty_result(status: str, message: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "message": message,
        "issues": [],
        "error_count": 0,
        "warning_count": 0,
        "note_count": 0,
        "files_checked": 0,
        "files_skipped": 0,
    }


def run_mypy_sources(
    sources: list[tuple[str, str]],
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Type-check several source strings in one isolated mypy process.

    Source is written only to a temporary directory. The target modules are not
    imported or executed, project mypy plugins/config are not loaded, and imports
    from the submitted project are not followed.
    """
    if not sources:
        return _empty_result("skipped", "No syntactically valid files were available for type checking.")

    try:
        mypy_spec = importlib.util.find_spec("mypy")
    except (ImportError, ValueError):
        mypy_spec = None
    if mypy_spec is None:
        return _empty_result(
            "unavailable",
            "mypy is not installed. Install project requirements to enable type checking.",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="security-analyzer-mypy-") as temp_dir:
            root = Path(temp_dir)
            config = root / "mypy.ini"
            config.write_text("[mypy]\n", encoding="utf-8")

            target_paths: list[str] = []
            path_map: dict[int, str] = {}
            for index, (file_path, source) in enumerate(sources):
                target = root / f"target_{index}.py"
                target.write_text(source, encoding="utf-8")
                target_paths.append(str(target))
                path_map[index] = file_path

            command = [
                sys.executable,
                "-m",
                "mypy",
                "--config-file",
                str(config),
                f"--python-version={sys.version_info.major}.{sys.version_info.minor}",
                "--follow-imports=skip",
                "--ignore-missing-imports",
                "--no-incremental",
                "--no-error-summary",
                "--show-column-numbers",
                "--no-pretty",
                "--no-color-output",
                *target_paths,
            ]

            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
    except subprocess.TimeoutExpired:
        return _empty_result(
            "timed_out",
            f"mypy exceeded the {timeout_seconds}-second time limit.",
        )
    except OSError as exc:
        return _empty_result("failed", f"Could not start mypy: {exc}")

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    issues: list[dict[str, Any]] = []

    for raw_line in output.splitlines():
        match = _DIAGNOSTIC.match(raw_line.strip())
        if not match:
            continue
        index = int(match.group("index"))
        issues.append(
            {
                "file_path": path_map.get(index, f"target_{index}.py"),
                "line_number": int(match.group("line")),
                "column": int(match.group("column")) if match.group("column") else None,
                "severity": match.group("severity"),
                "message": match.group("message").strip(),
                "code": match.group("code"),
            }
        )

    # mypy returns 1 when it found type errors. Return code 2 indicates a
    # configuration/runtime problem and must not be mistaken for a clean check.
    if completed.returncode == 0 or (completed.returncode == 1 and issues):
        status = "completed"
        message = None
    else:
        status = "failed"
        message = output.strip()[-1200:] or "mypy returned an unexpected error."

    return {
        "status": status,
        "message": message,
        "issues": issues,
        "error_count": sum(item["severity"] == "error" for item in issues),
        "warning_count": sum(item["severity"] == "warning" for item in issues),
        "note_count": sum(item["severity"] == "note" for item in issues),
        "files_checked": len(sources) if status == "completed" else 0,
        "files_skipped": 0,
    }


def run_mypy(
    source: str,
    file_path: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Compatibility wrapper for a single source file."""
    return run_mypy_sources([(file_path, source)], timeout_seconds=timeout_seconds)
