from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any


@dataclass
class ParseResult:
    tree: ast.Module | None
    error: dict[str, Any] | None = None


def parse_source(source: str, filename: str = "<memory>") -> ParseResult:
    """Parse Python source into an AST. The source is never executed."""
    try:
        tree = ast.parse(source, filename=filename, mode="exec")
        return ParseResult(tree=tree)
    except SyntaxError as exc:
        return ParseResult(
            tree=None,
            error={
                "message": exc.msg,
                "line": exc.lineno,
                "column": exc.offset,
                "end_line": exc.end_lineno,
                "end_column": exc.end_offset,
                "text": (exc.text or "").rstrip("\n"),
            },
        )
