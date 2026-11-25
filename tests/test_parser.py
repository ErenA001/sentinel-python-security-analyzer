from security_analyzer.parser import parse_source


def test_parse_valid_source():
    result = parse_source("value = 10\nprint(value)\n", "sample.py")
    assert result.tree is not None
    assert result.error is None


def test_parse_syntax_error_has_line_and_column():
    result = parse_source("def broken(:\n    pass\n", "broken.py")
    assert result.tree is None
    assert result.error is not None
    assert result.error["line"] == 1
    assert result.error["column"] is not None


def test_parser_does_not_execute_source(tmp_path):
    marker = tmp_path / "should_not_exist.txt"
    source = f"open({str(marker)!r}, 'w').write('executed')\nraise RuntimeError('no')\n"
    result = parse_source(source, "untrusted.py")
    assert result.tree is not None
    assert not marker.exists()
