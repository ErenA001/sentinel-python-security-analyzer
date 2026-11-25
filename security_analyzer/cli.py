from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from security_analyzer.analyzer import analyze_source

MAX_FILE_SIZE = 1_000_000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-analyzer",
        description="Statically analyze Python source code without executing it.",
    )
    parser.add_argument("file", help="Path to a .py source file")
    parser.add_argument("--json", dest="json_path", help="Optional path for a JSON report")
    parser.add_argument(
        "--no-bandit",
        action="store_true",
        help="Run only the built-in AST rules and skip the Bandit scanner",
    )
    parser.add_argument(
        "--mypy",
        action="store_true",
        help="Run an additional mypy type check (reported separately from security findings)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    path = Path(args.file)

    if path.suffix.lower() != ".py":
        print("Error: only .py files are supported.", file=sys.stderr)
        return 2
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            print(f"Error: file exceeds the {MAX_FILE_SIZE}-byte limit.", file=sys.stderr)
            return 2
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        print(f"Error: could not read source file ({exc}).", file=sys.stderr)
        return 2

    result = analyze_source(
        source,
        file_path=path.name,
        include_bandit=not args.no_bandit,
        include_mypy=args.mypy,
    )
    report = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)

    if args.json_path:
        try:
            Path(args.json_path).write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Error: could not write JSON report ({exc}).", file=sys.stderr)
            return 2

    print(report)
    return 1 if result.syntax_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
