from security_analyzer.analyzer import analyze_source


def rule_ids(source: str) -> list[str]:
    return [finding.rule_id for finding in analyze_source(source, "test.py").findings]


def test_hardcoded_secret_is_detected_and_masked():
    result = analyze_source('API_KEY = "sk_test_123456789"\n', "secrets.py")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "PY-SEC-001"
    assert "sk_test_123456789" not in finding.evidence
    assert "[REDACTED]" in finding.evidence


def test_environment_variable_secret_is_not_flagged():
    source = "import os\nAPI_KEY = os.getenv('API_KEY')\n"
    assert "PY-SEC-001" not in rule_ids(source)


def test_eval_is_detected_but_literal_eval_is_not():
    source = "result = eval(user_input)\nother = ast.literal_eval(text)\n"
    assert rule_ids(source).count("PY-SEC-002") == 1


def test_shell_true_is_detected():
    source = "import subprocess\nsubprocess.run(command, shell=True)\n"
    assert "PY-SEC-003" in rule_ids(source)


def test_safe_subprocess_arguments_are_not_flagged():
    source = "import subprocess\nsubprocess.run(['ls', '-l'], shell=False)\n"
    assert "PY-SEC-003" not in rule_ids(source)


def test_pickle_loads_is_detected():
    source = "import pickle\ndata = pickle.loads(payload)\n"
    assert "PY-SEC-004" in rule_ids(source)


def test_dynamic_sql_variable_is_detected_at_execute():
    source = (
        "query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
        "cursor.execute(query)\n"
    )
    assert "PY-SEC-005" in rule_ids(source)


def test_parameterized_sql_is_not_flagged():
    source = "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))\n"
    assert "PY-SEC-005" not in rule_ids(source)


def test_broad_empty_exception_is_detected():
    source = "try:\n    work()\nexcept Exception:\n    pass\n"
    assert "PY-QUAL-001" in rule_ids(source)


def test_specific_exception_is_not_flagged():
    source = "try:\n    work()\nexcept ValueError as error:\n    log(error)\n"
    assert "PY-QUAL-001" not in rule_ids(source)
