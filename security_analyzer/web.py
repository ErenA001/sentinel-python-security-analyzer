from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import time
import uuid
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from security_analyzer.analyzer import analyze_source, analyze_sources
from security_analyzer.ai.assistant import (
    AssistantInputError,
    AssistantOutputError,
    chat_with_assistant,
    validate_chat_input,
)
from security_analyzer.ai.explainer import ExplanationProviderError, explain_finding, redact_sensitive_text
from security_analyzer.reports import render_html_report
from security_analyzer.storage import get_scan, init_db, list_scans, save_scan

MAX_FILE_SIZE = 1_000_000
MAX_ZIP_SIZE = 10_000_000
MAX_ZIP_TOTAL_SOURCE_SIZE = 5_000_000
MAX_ZIP_FILES = 25
MAX_ZIP_ENTRIES = 100
MAX_REQUEST_SIZE = MAX_ZIP_SIZE + 64 * 1024


def _error(message: str, status_code: int):
    return jsonify({"error": message}), status_code


def _provider_error_response(error: ExplanationProviderError):
    response, status_code = _error(str(error), error.status_code)
    if error.retry_after is not None:
        response.headers["Retry-After"] = str(error.retry_after)
    return response, status_code


def _parse_bool(value: Any, field_name: str = "include_bandit") -> bool:
    if isinstance(value, bool):
        return value
    if value in (1, "1", "true", "yes", "on"):
        return True
    if value in (0, "0", "false", "no", "off"):
        return False
    raise ValueError(f"{field_name} must be a boolean value.")


def _validated_filename(raw_name: Any, allowed_suffixes: tuple[str, ...] = (".py",)) -> str:
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise ValueError("A filename is required.")
    filename = secure_filename(raw_name)
    if not filename or Path(filename).suffix.lower() not in allowed_suffixes:
        allowed = " or ".join(allowed_suffixes)
        raise TypeError(f"Only {allowed} files are supported.")
    return filename


def _decode_python_source(raw_source: bytes, file_path: str) -> str:
    try:
        return raw_source.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{file_path} must use UTF-8 encoding.") from exc


def _read_zip_entry_limited(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limit: int,
) -> bytes:
    """Stream one ZIP entry while enforcing a hard decompressed-byte limit."""
    chunks: list[bytes] = []
    total = 0
    with archive.open(info, "r") as stream:
        while True:
            chunk = stream.read(min(64 * 1024, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise RequestEntityTooLarge(
                    description="A ZIP entry expands beyond the configured source-size limit."
                )
            chunks.append(chunk)
    return b"".join(chunks)


def _safe_zip_sources(raw_archive: bytes) -> tuple[list[tuple[str, str]], list[str]]:
    """Read Python files from a ZIP in memory; never extract archive paths to disk."""
    try:
        archive = zipfile.ZipFile(BytesIO(raw_archive))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("The uploaded ZIP archive is invalid or corrupted.") from exc

    sources: list[tuple[str, str]] = []
    warnings: list[str] = []
    seen_paths: set[str] = set()
    total_uncompressed = 0
    actual_python_bytes = 0

    try:
        with archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise RequestEntityTooLarge(
                    description=f"ZIP archives may contain at most {MAX_ZIP_ENTRIES} entries."
                )

            skipped_non_python = 0
            for info in entries:
                raw_name = info.filename
                if not raw_name or "\x00" in raw_name:
                    raise ValueError("The ZIP archive contains an invalid entry name.")

                normalized = raw_name.replace("\\", "/")
                if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
                    raise ValueError("The ZIP archive contains an absolute path.")

                clean_name = normalized.rstrip("/") if info.is_dir() else normalized
                parts = clean_name.split("/")
                if not clean_name or any(part in ("", ".", "..") for part in parts):
                    raise ValueError("The ZIP archive contains an unsafe path.")

                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ValueError("The ZIP archive contains a symbolic link.")

                if info.flag_bits & 0x1:
                    raise ValueError("Encrypted ZIP entries are not supported.")

                if clean_name in seen_paths:
                    raise ValueError("The ZIP archive contains duplicate entry paths.")
                seen_paths.add(clean_name)

                if info.is_dir():
                    continue

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ZIP_TOTAL_SOURCE_SIZE:
                    raise RequestEntityTooLarge(
                        description=(
                            "The ZIP archive expands beyond the "
                            f"{MAX_ZIP_TOTAL_SOURCE_SIZE}-byte limit."
                        )
                    )

                if Path(clean_name).suffix.lower() != ".py":
                    skipped_non_python += 1
                    continue

                if len(sources) >= MAX_ZIP_FILES:
                    raise RequestEntityTooLarge(
                        description=f"ZIP archives may contain at most {MAX_ZIP_FILES} Python files."
                    )

                if info.file_size > MAX_FILE_SIZE:
                    raise RequestEntityTooLarge(
                        description=f"Each Python file in a ZIP must be at most {MAX_FILE_SIZE} bytes."
                    )

                remaining_total = MAX_ZIP_TOTAL_SOURCE_SIZE - actual_python_bytes
                entry_limit = min(MAX_FILE_SIZE, remaining_total)
                try:
                    raw_source = _read_zip_entry_limited(archive, info, entry_limit)
                except RequestEntityTooLarge:
                    raise
                except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError) as exc:
                    raise ValueError("A ZIP entry could not be read safely.") from exc

                if len(raw_source) != info.file_size:
                    raise ValueError("A ZIP entry has an inconsistent uncompressed size.")

                actual_python_bytes += len(raw_source)
                source = _decode_python_source(raw_source, clean_name)
                sources.append((clean_name, source))

            if skipped_non_python:
                warnings.append(
                    f"Skipped {skipped_non_python} non-Python file(s) in the ZIP archive."
                )

    except RequestEntityTooLarge:
        raise

    if not sources:
        raise ValueError("The ZIP archive does not contain any .py files.")

    return sources, warnings


def _extract_input() -> tuple[list[tuple[str, str]], str, bool, bool, list[str], str]:
    """Return sources, display filename, scanner flags, warnings and input kind."""
    if request.is_json:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ValueError("The JSON body must be an object.")

        source = payload.get("source")
        if not isinstance(source, str):
            raise ValueError("JSON requests must include source as a string.")

        filename = _validated_filename(payload.get("filename", "pasted_code.py"))
        include_bandit = _parse_bool(payload.get("include_bandit", True))
        include_mypy = _parse_bool(payload.get("include_mypy", False), "include_mypy")

        try:
            source_size = len(source.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("Source text must be valid UTF-8.") from exc

        if source_size > MAX_FILE_SIZE:
            raise RequestEntityTooLarge(
                description=f"Source file exceeds the {MAX_FILE_SIZE}-byte limit."
            )

        return [(filename, source)], filename, include_bandit, include_mypy, [], "python"

    uploaded = request.files.get("file")
    if uploaded is None:
        raise ValueError(
            "Upload a .py or .zip file using the 'file' field, or send JSON source text."
        )

    filename = _validated_filename(uploaded.filename, (".py", ".zip"))
    include_bandit = _parse_bool(request.form.get("include_bandit", "true"))
    include_mypy = _parse_bool(request.form.get("include_mypy", "false"), "include_mypy")
    suffix = Path(filename).suffix.lower()

    if suffix == ".py":
        raw_source = uploaded.stream.read(MAX_FILE_SIZE + 1)
        if len(raw_source) > MAX_FILE_SIZE:
            raise RequestEntityTooLarge(
                description=f"Source file exceeds the {MAX_FILE_SIZE}-byte limit."
            )
        source = _decode_python_source(raw_source, filename)
        return [(filename, source)], filename, include_bandit, include_mypy, [], "python"

    raw_archive = uploaded.stream.read(MAX_ZIP_SIZE + 1)
    if len(raw_archive) > MAX_ZIP_SIZE:
        raise RequestEntityTooLarge(
            description=f"ZIP archive exceeds the {MAX_ZIP_SIZE}-byte upload limit."
        )
    sources, warnings = _safe_zip_sources(raw_archive)
    return sources, filename, include_bandit, include_mypy, warnings, "zip"


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    default_database = os.environ.get(
        "SECURITY_ANALYZER_DB",
        str(Path(app.instance_path) / "scans.sqlite3"),
    )
    app.config.from_mapping(
        DATABASE=default_database,
        MAX_CONTENT_LENGTH=MAX_REQUEST_SIZE,
        JSON_SORT_KEYS=False,
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    init_db(app.config["DATABASE"])

    assistant_request_log: dict[str, list[float]] = {}

    def assistant_rate_limited(client_key: str) -> bool:
        now = time.monotonic()
        window = float(app.config.get("ASSISTANT_RATE_WINDOW_SECONDS", 600))
        limit = int(app.config.get("ASSISTANT_RATE_LIMIT", 8))
        recent = [stamp for stamp in assistant_request_log.get(client_key, []) if now - stamp < window]
        if len(recent) >= limit:
            assistant_request_log[client_key] = recent
            return True
        recent.append(now)
        assistant_request_log[client_key] = recent
        if len(assistant_request_log) > 256:
            assistant_request_log.clear()
            assistant_request_log[client_key] = [now]
        return False

    frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(error):
        description = getattr(error, "description", None)
        return _error(
            description or f"Request exceeds the {MAX_ZIP_SIZE}-byte upload limit.",
            413,
        )

    @app.errorhandler(404)
    def handle_not_found(error):
        return _error("The requested resource was not found.", 404)

    @app.errorhandler(500)
    def handle_internal_error(error):
        app.logger.error("Unhandled server error: %s", error)
        return _error("An internal server error occurred.", 500)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/")
    def index():
        built_index = frontend_dist / "index.html"
        # Tests must receive the backend status payload even when a frontend
        # production build is present in the repository.
        if not app.testing and built_index.is_file():
            return send_file(built_index)
        return jsonify(
            {
                "service": "programming-language-security-analyzer",
                "status": "ok",
                "message": "Backend API is running. Start the Vite frontend on port 5173.",
                "frontend": "http://127.0.0.1:5173",
                "endpoints": {
                    "health": "/api/health",
                    "scan": "POST /api/scan",
                    "scans": "GET /api/scans",
                    "assistant": "POST /api/assistant/chat",
                },
            }
        )

    @app.get("/assets/<path:filename>")
    def frontend_asset(filename: str):
        assets_dir = frontend_dist / "assets"
        if not assets_dir.is_dir():
            return _error("Frontend build not found. Run npm run build in frontend/.", 404)
        return send_from_directory(assets_dir, filename)

    @app.get("/api/health")
    def health():
        try:
            import importlib.util

            mypy_available = importlib.util.find_spec("mypy") is not None
        except (ImportError, ValueError):
            mypy_available = False
        return jsonify(
            {
                "status": "ok",
                "service": "programming-language-security-analyzer",
                "features": {
                    "zip_upload": True,
                    "mypy_available": mypy_available,
                    "ai_explanation_mode": "nvidia" if os.environ.get("NVIDIA_API_KEY", "").strip() else "local",
                    "ai_model": "nvidia/nemotron-3.5-lightning-30b-a3b",
                    "security_assistant": True,
                    "assistant_message_limit": 700,
                    "assistant_rate_limit": 8,
                },
            }
        )

    @app.post("/api/scan")
    def scan():
        try:
            sources, filename, include_bandit, include_mypy, input_warnings, input_kind = (
                _extract_input()
            )
        except RequestEntityTooLarge:
            raise
        except TypeError as exc:
            return _error(str(exc), 415)
        except ValueError as exc:
            return _error(str(exc), 400)

        if input_kind == "zip":
            result = analyze_sources(
                sources,
                archive_name=filename,
                include_bandit=include_bandit,
                include_mypy=include_mypy,
            )
        else:
            file_path, source = sources[0]
            result = analyze_source(
                source,
                file_path=file_path,
                include_bandit=include_bandit,
                include_mypy=include_mypy,
            )

        result.scanner_warnings.extend(input_warnings)
        scan_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        try:
            save_scan(
                app.config["DATABASE"],
                scan_id,
                created_at,
                filename,
                result,
            )
        except sqlite3.Error:
            app.logger.exception("Could not persist scan results")
            return _error(
                "The scan completed, but its result could not be saved.",
                500,
            )

        if result.syntax_error:
            status = "syntax_error"
        elif result.file_errors:
            status = "completed_with_errors"
        else:
            status = "completed"

        return (
            jsonify(
                {
                    "scan_id": scan_id,
                    "created_at": created_at,
                    "file_name": filename,
                    "status": status,
                    "result": result.to_dict(),
                    "links": {
                        "details": f"/api/scans/{scan_id}",
                        "json_report": f"/api/scans/{scan_id}/report.json",
                        "html_report": f"/api/scans/{scan_id}/report.html",
                    },
                }
            ),
            201,
        )

    @app.get("/api/scans")
    def scans():
        raw_limit = request.args.get("limit", "50")
        try:
            limit = int(raw_limit)
        except ValueError:
            return _error("limit must be an integer between 1 and 100.", 400)
        if not 1 <= limit <= 100:
            return _error("limit must be an integer between 1 and 100.", 400)
        return jsonify({"scans": list_scans(app.config["DATABASE"], limit=limit)})

    @app.get("/api/scans/<scan_id>")
    def scan_detail(scan_id: str):
        scan_data = get_scan(app.config["DATABASE"], scan_id)
        if scan_data is None:
            return _error("Scan not found.", 404)
        return jsonify(scan_data)

    @app.post("/api/scans/<scan_id>/findings/<finding_id>/explain")
    def explain_scan_finding(scan_id: str, finding_id: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _error("A JSON body with consent status is required.", 400)
        consent = payload.get("consent", False)
        if not isinstance(consent, bool):
            return _error("consent must be a boolean value.", 400)

        scan_data = get_scan(app.config["DATABASE"], scan_id)
        if scan_data is None:
            return _error("Scan not found.", 404)
        finding = next(
            (item for item in scan_data.get("findings", []) if item.get("finding_id") == finding_id),
            None,
        )
        if finding is None:
            return _error("Finding not found in this scan.", 404)

        if os.environ.get("NVIDIA_API_KEY", "").strip() and not consent:
            return _error("Explicit consent is required before sending finding data to NVIDIA.", 403)

        try:
            explanation = explain_finding(finding, consent=consent)
        except PermissionError as exc:
            return _error(str(exc), 403)
        except ExplanationProviderError as exc:
            app.logger.warning("AI explanation provider failed: %s", exc)
            return _provider_error_response(exc)

        return jsonify({"scan_id": scan_id, "finding_id": finding_id, **explanation})

    @app.post("/api/assistant/chat")
    def assistant_chat():
        # Keep chat requests small. The assistant never receives original source files.
        raw_body = request.get_data(cache=True)
        if len(raw_body) > 8192:
            return _error("Chat request exceeds the 8 KB limit.", 413)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return _error("A JSON chat request is required.", 400)

        scan_id = payload.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id or len(scan_id) > 64:
            return _error("Open a scan before using Security Assistant.", 400)

        try:
            message, history = validate_chat_input(
                payload.get("message"),
                payload.get("history", []),
            )
        except AssistantInputError as exc:
            return _error(str(exc), 400)

        consent = payload.get("consent", False)
        if not isinstance(consent, bool):
            return _error("consent must be a boolean value.", 400)

        scan_data = get_scan(app.config["DATABASE"], scan_id)
        if scan_data is None:
            return _error("Scan not found. Open a valid scan before chatting.", 404)

        client_key = request.remote_addr or "local-client"
        if assistant_rate_limited(client_key):
            return _error("Assistant rate limit reached. Wait a few minutes before sending another message.", 429)

        selected_finding = None
        finding_id = payload.get("finding_id")
        def safe_finding_field(item: dict[str, Any], key: str) -> str:
            limits = {
                "rule_id": 40,
                "title": 80,
                "severity": 12,
                "confidence": 12,
                "description": 160,
                "recommendation": 160,
                "cwe_id": 24,
            }
            return redact_sensitive_text(item.get(key, ""))[:limits.get(key, 160)]

        if finding_id is not None:
            if not isinstance(finding_id, str) or len(finding_id) > 100:
                return _error("Invalid finding reference.", 400)
            raw_finding = next(
                (item for item in scan_data.get("findings", []) if item.get("finding_id") == finding_id),
                None,
            )
            if raw_finding is None:
                return _error("Finding not found in this scan.", 404)
            selected_finding = {
                key: safe_finding_field(raw_finding, key)
                for key in ("rule_id", "title", "severity", "confidence", "description", "recommendation", "cwe_id")
            }

        counts = scan_data.get("severity_counts", {})
        summary = {
            "total_findings": int(scan_data.get("total_findings", 0)),
            "file_count": int(scan_data.get("file_count", 1)),
            "high_risk": int(counts.get("CRITICAL", 0)) + int(counts.get("HIGH", 0)),
            "severity_counts": {
                level: int(counts.get(level, 0))
                for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
        }
        raw_type_check = scan_data.get("type_check", {}) or {}
        type_check_summary = {
            "status": str(raw_type_check.get("status", "not_requested"))[:24],
            "error_count": int(raw_type_check.get("error_count", 0)),
            "warning_count": int(raw_type_check.get("warning_count", 0)),
            "issues": [
                {
                    "line": int(issue.get("line", 0) or 0),
                    "level": str(issue.get("level", ""))[:12],
                    "code": str(issue.get("code", ""))[:24],
                    "message": redact_sensitive_text(issue.get("message", ""))[:160],
                }
                for issue in raw_type_check.get("issues", [])[:3]
                if isinstance(issue, dict)
            ],
        }
        safe_findings = []
        ranked_findings = sorted(
            scan_data.get("findings", []),
            key=lambda item: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(item.get("severity"), 5),
                item.get("line_number", 0),
            ),
        )
        for item in ranked_findings[:3]:
            safe_findings.append({
                key: safe_finding_field(item, key)
                for key in ("rule_id", "title", "severity", "description", "recommendation", "cwe_id")
            })

        try:
            result = chat_with_assistant(
                message,
                context={
                    "scan_summary": summary,
                    "type_check_summary": type_check_summary,
                    "selected_finding": selected_finding,
                    "findings": safe_findings,
                },
                history=history,
                consent=consent,
            )
        except PermissionError as exc:
            return _error(str(exc), 403)
        except (ExplanationProviderError, AssistantOutputError) as exc:
            app.logger.warning("Security Assistant request failed: %s", exc)
            return _provider_error_response(exc)

        return jsonify({"scan_id": scan_id, **result})

    @app.get("/api/scans/<scan_id>/report.json")
    def json_report(scan_id: str):
        scan_data = get_scan(app.config["DATABASE"], scan_id)
        if scan_data is None:
            return _error("Scan not found.", 404)
        report = json.dumps(scan_data, indent=2, ensure_ascii=False).encode("utf-8")
        return send_file(
            BytesIO(report),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"scan-{scan_id}.json",
        )

    @app.get("/api/scans/<scan_id>/report.html")
    def html_report(scan_id: str):
        scan_data = get_scan(app.config["DATABASE"], scan_id)
        if scan_data is None:
            return _error("Scan not found.", 404)
        report = render_html_report(scan_data).encode("utf-8")
        return send_file(
            BytesIO(report),
            mimetype="text/html",
            as_attachment=True,
            download_name=f"scan-{scan_id}.html",
        )

    return app


if __name__ == "__main__":
    # Local-only development server. Do not expose the Flask development server publicly.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
