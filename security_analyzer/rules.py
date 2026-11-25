from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from security_analyzer.models import Finding

SECRET_NAME_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
SECRET_PLACEHOLDERS = {
    "",
    "changeme",
    "change_me",
    "your_api_key",
    "your-secret-here",
    "placeholder",
    "example",
    "dummy",
    "none",
    "null",
    "xxx",
}
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key))"
    r"(\s*=\s*)([rRuUbBfF]*)(['\"])(.*?)(\4)"
)
SQL_KEYWORD_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP)\b", re.I)


def redact_evidence(line: str) -> str:
    """Mask likely secret literals before evidence is displayed or exported."""
    return SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}[REDACTED]{match.group(4)}",
        line,
    )


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name_of(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _target_names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)


def _sql_expression_parts(node: ast.AST) -> tuple[str, bool]:
    """Return constant text and whether the expression contains dynamic data."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, False
    if isinstance(node, ast.JoinedStr):
        text_parts: list[str] = []
        dynamic = False
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text_parts.append(value.value)
            else:
                dynamic = True
        return " ".join(text_parts), dynamic
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_text, left_dynamic = _sql_expression_parts(node.left)
        right_text, right_dynamic = _sql_expression_parts(node.right)
        return f"{left_text} {right_text}", left_dynamic or right_dynamic or not isinstance(node.right, ast.Constant) or not isinstance(node.left, ast.Constant)
    return "", not isinstance(node, ast.Constant)


def _is_dynamic_sql(node: ast.AST) -> bool:
    text, dynamic = _sql_expression_parts(node)
    return dynamic and bool(SQL_KEYWORD_RE.search(text))


class SecurityRuleVisitor(ast.NodeVisitor):
    """Small AST rule set for the first project milestone."""

    def __init__(self, source: str, file_path: str) -> None:
        self.source_lines = source.splitlines()
        self.file_path = file_path
        self.findings: list[Finding] = []
        self.sql_query_variables: set[str] = set()

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        title: str,
        severity: str,
        confidence: str,
        description: str,
        recommendation: str,
        cwe_id: str | None = None,
    ) -> None:
        line_number = max(1, int(getattr(node, "lineno", 1)))
        raw_line = self.source_lines[line_number - 1] if line_number <= len(self.source_lines) else ""
        evidence = redact_evidence(raw_line.strip())
        sequence = len(self.findings) + 1
        self.findings.append(
            Finding(
                finding_id=f"{rule_id}-{line_number}-{sequence:03d}",
                rule_id=rule_id,
                file_path=self.file_path,
                line_number=line_number,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                cwe_id=cwe_id,
            )
        )

    def _check_secret_assignment(self, node: ast.AST, targets: Iterable[ast.AST], value: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        secret_value = value.value.strip()
        if secret_value.lower() in SECRET_PLACEHOLDERS or len(secret_value) < 4:
            return
        for target in targets:
            for name in _target_names(target):
                if SECRET_NAME_RE.search(name):
                    self._add(
                        node,
                        "PY-SEC-001",
                        "Possible hardcoded secret",
                        "HIGH",
                        "MEDIUM",
                        "A variable with a secret-like name is assigned a string literal. This may expose a credential in source control.",
                        "Read the value from an environment variable or a dedicated secret manager. Do not commit real credentials.",
                        "CWE-798",
                    )
                    return

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_secret_assignment(node, node.targets, node.value)
        if _is_dynamic_sql(node.value):
            for target in node.targets:
                self.sql_query_variables.update(_target_names(target))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret_assignment(node, [node.target], node.value)
            if _is_dynamic_sql(node.value):
                self.sql_query_variables.update(_target_names(node.target))
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._check_secret_assignment(node, [node.target], node.value)
        if _is_dynamic_sql(node.value):
            self.sql_query_variables.update(_target_names(node.target))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function_name = _name_of(node.func) or ""
        short_name = function_name.rsplit(".", 1)[-1]

        if short_name in {"eval", "exec"} and function_name in {"eval", "exec"}:
            self._add(
                node,
                "PY-SEC-002",
                "Dynamic code execution",
                "HIGH",
                "HIGH",
                f"The code calls {short_name}(), which interprets a string as Python code.",
                "Avoid evaluating untrusted input. Use a safe parser or a narrowly scoped expression evaluator instead.",
                "CWE-95",
            )

        if function_name == "os.system":
            self._add(
                node,
                "PY-SEC-003",
                "Shell command execution risk",
                "HIGH",
                "MEDIUM",
                "os.system() passes a command string to the system shell.",
                "Prefer subprocess calls with an argument list and shell=False. Validate any externally supplied arguments.",
                "CWE-78",
            )
        elif function_name.startswith("subprocess."):
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_true:
                self._add(
                    node,
                    "PY-SEC-003",
                    "Shell command execution risk",
                    "HIGH",
                    "HIGH",
                    "A subprocess call enables shell=True, which can make command construction vulnerable to injection.",
                    "Prefer an argument list with shell=False. Validate and constrain values passed to the process.",
                    "CWE-78",
                )

        if function_name in {"pickle.load", "pickle.loads"}:
            self._add(
                node,
                "PY-SEC-004",
                "Possible unsafe deserialization",
                "HIGH",
                "MEDIUM",
                f"The code uses {function_name}(). Untrusted pickle data can cause arbitrary code execution during deserialization.",
                "Do not deserialize untrusted pickle data. Prefer a safer data format such as JSON for simple data exchange.",
                "CWE-502",
            )

        if short_name == "execute" and node.args:
            query = node.args[0]
            is_variable_query = isinstance(query, ast.Name) and query.id in self.sql_query_variables
            if is_variable_query or _is_dynamic_sql(query):
                self._add(
                    node,
                    "PY-SEC-005",
                    "Possible SQL injection",
                    "HIGH",
                    "MEDIUM",
                    "A dynamically constructed SQL statement is passed to execute(). String interpolation or concatenation may allow input to alter the query.",
                    "Use parameterized queries and pass values separately from the SQL statement.",
                    "CWE-89",
                )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        exception_name = _name_of(node.type) if node.type is not None else None
        is_broad = node.type is None or exception_name in {"Exception", "BaseException"}
        silently_ignored = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        if is_broad and (node.type is None or silently_ignored):
            self._add(
                node,
                "PY-QUAL-001",
                "Overly broad or silently ignored exception",
                "LOW",
                "HIGH",
                "A broad exception handler can hide unexpected failures, especially when the handler does nothing.",
                "Catch the specific exception types that are expected and handle or log them explicitly.",
                None,
            )
        self.generic_visit(node)
