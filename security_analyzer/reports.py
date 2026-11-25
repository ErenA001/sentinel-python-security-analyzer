from __future__ import annotations

from html import escape
from typing import Any


def render_html_report(scan: dict[str, Any]) -> str:
    """Render a self-contained HTML report with escaped, source-derived values."""
    counts = scan.get("severity_counts", {})
    count_items = "".join(
        f'<li><strong>{escape(level)}:</strong> {int(counts.get(level, 0))}</li>'
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    files_scanned = scan.get("files_scanned") or [scan.get("file_name", "unknown.py")]
    file_items = "".join(f"<li><code>{escape(str(path))}</code></li>" for path in files_scanned)

    finding_rows: list[str] = []
    for finding in scan.get("findings", []):
        related = finding.get("related_findings") or []
        related_text = ", ".join(
            f"{item.get('source', 'scanner')} {item.get('rule_id', '')}".strip()
            for item in related
        )
        related_cell = escape(related_text) if related_text else "—"
        finding_rows.append(
            "<tr>"
            f"<td>{escape(str(finding.get('file_path', scan.get('file_name', 'unknown.py'))))}</td>"
            f"<td>{escape(str(finding['line_number']))}</td>"
            f"<td>{escape(str(finding.get('severity', 'INFO')))}</td>"
            f"<td>{escape(str(finding.get('rule_id', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(finding.get('title', 'Untitled finding')))}</td>"
            f"<td>{escape(str(finding.get('description', '')))}</td>"
            f"<td><code>{escape(str(finding.get('evidence', '')))}</code></td>"
            f"<td>{escape(str(finding.get('recommendation', '')))}</td>"
            f"<td>{related_cell}</td>"
            "</tr>"
        )

    if not finding_rows:
        finding_rows.append('<tr><td colspan="9">No security findings were reported.</td></tr>')

    syntax_error = scan.get("syntax_error")
    file_errors = scan.get("file_errors") or []
    error_items = []
    if syntax_error:
        error_items.append(
            f"<li>{escape(str(scan.get('file_name', 'source.py')))}: "
            f"line {escape(str(syntax_error.get('line', 'unknown')))} - "
            f"{escape(str(syntax_error.get('message', 'Syntax error')))}</li>"
        )
    for item in file_errors:
        if syntax_error and item.get("file_path") == scan.get("file_name"):
            continue
        error = item.get("syntax_error") or {}
        error_items.append(
            f"<li>{escape(str(item.get('file_path', 'source.py')))}: "
            f"line {escape(str(error.get('line', 'unknown')))} - "
            f"{escape(str(error.get('message', 'Syntax error')))}</li>"
        )
    syntax_section = (
        f"<section><h2>Parser errors</h2><ul>{''.join(error_items)}</ul></section>"
        if error_items
        else ""
    )

    warning_items = "".join(
        f"<li>{escape(str(warning))}</li>" for warning in scan.get("scanner_warnings", [])
    )
    warnings_section = (
        f"<section><h2>Scanner warnings</h2><ul>{warning_items}</ul></section>"
        if warning_items
        else ""
    )

    type_check = scan.get("type_check") or {"status": "not_requested", "issues": []}
    type_issues = type_check.get("issues", [])
    type_rows = []
    for issue in type_issues:
        type_rows.append(
            "<tr>"
            f"<td>{escape(str(issue.get('file_path', '')))}</td>"
            f"<td>{escape(str(issue.get('line_number', '')))}</td>"
            f"<td>{escape(str(issue.get('column') or ''))}</td>"
            f"<td>{escape(str(issue.get('severity', '')).upper())}</td>"
            f"<td>{escape(str(issue.get('code') or ''))}</td>"
            f"<td>{escape(str(issue.get('message', '')))}</td>"
            "</tr>"
        )
    if not type_rows:
        type_rows.append('<tr><td colspan="6">No type issues were reported.</td></tr>')

    type_message = type_check.get("message")
    type_message_html = (
        f'<p class="muted">{escape(str(type_message))}</p>' if type_message else ""
    )
    type_section = f"""
  <section>
    <h2>Type safety check (mypy)</h2>
    <p>Status: <strong>{escape(str(type_check.get('status', 'not_requested')))}</strong> |
       Errors: <strong>{int(type_check.get('error_count', 0))}</strong> |
       Warnings: <strong>{int(type_check.get('warning_count', 0))}</strong> |
       Files checked: <strong>{int(type_check.get('files_checked', 0))}</strong> |
       Files skipped: <strong>{int(type_check.get('files_skipped', 0))}</strong></p>
    {type_message_html}
    <table>
      <thead><tr><th>File</th><th>Line</th><th>Column</th><th>Level</th><th>Code</th><th>Message</th></tr></thead>
      <tbody>{''.join(type_rows)}</tbody>
    </table>
    <p class="muted">Type-check diagnostics are reported separately and are not classified as security vulnerabilities.</p>
  </section>
"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Analysis Report - {escape(str(scan.get('file_name', 'source')))}</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2rem auto; max-width: 1400px; padding: 0 1rem; color: #202124; line-height: 1.5; }}
    h1, h2 {{ color: #172554; }}
    h1 {{ margin-bottom: .35rem; }}
    h2 {{ margin-top: 1.7rem; }}
    .meta, .muted {{ color: #64748b; }}
    ul {{ line-height: 1.7; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; table-layout: auto; }}
    th, td {{ border: 1px solid #d9e0e8; padding: .65rem; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; white-space: nowrap; }}
    td {{ overflow-wrap: anywhere; }}
    code {{ white-space: pre-wrap; overflow-wrap: anywhere; font-size: .9em; }}
    .notice {{ background: #f8fafc; border-left: 4px solid #64748b; padding: .8rem 1rem; margin-top: 1.5rem; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: .75rem 2rem; }}
    @media print {{ body {{ margin: 0; }} }}
  </style>
</head>
<body>
  <h1>Programming Language Security Analyzer</h1>
  <p class="meta">File: {escape(str(scan.get('file_name', 'unknown')))} | Scan ID: {escape(str(scan.get('scan_id', 'unknown')))}</p>
  <p class="meta">Created: {escape(str(scan.get('created_at', 'unknown')))} | Status: {escape(str(scan.get('status', 'unknown')))}</p>
  <section>
    <h2>Summary</h2>
    <div class="summary">
      <p>Files scanned: <strong>{int(scan.get('file_count', len(files_scanned)))}</strong></p>
      <p>Total security findings: <strong>{int(scan.get('total_findings', len(scan.get('findings', []))))}</strong></p>
      <p>Duplicate detections merged: <strong>{int(scan.get('deduplicated_findings', 0))}</strong></p>
    </div>
    <ul>{count_items}</ul>
    <h3>Files included</h3><ul>{file_items}</ul>
  </section>
  {syntax_section}
  {warnings_section}
  <section>
    <h2>Security findings</h2>
    <table>
      <thead><tr><th>File</th><th>Line</th><th>Severity</th><th>Rule</th><th>Title</th><th>Description</th><th>Evidence</th><th>Recommendation</th><th>Also detected by</th></tr></thead>
      <tbody>{''.join(finding_rows)}</tbody>
    </table>
  </section>
  {type_section}
  <p class="notice">Static analysis results are heuristic indicators. They do not prove exploitability or prove that the source code is secure. Submitted source code was analyzed, not executed. Type-check diagnostics are not security findings.</p>
</body>
</html>
"""
