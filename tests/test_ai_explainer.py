import json
from email.message import Message
from urllib.error import HTTPError
from unittest.mock import patch

import pytest

from security_analyzer.ai.explainer import (
    NVIDIA_CHAT_COMPLETIONS_URL,
    NVIDIA_MODEL,
    ExplanationProviderError,
    explain_finding,
    local_explanation,
    redact_sensitive_text,
)


def sample_finding():
    return {
        "finding_id": "PY-SEC-002-1-001",
        "rule_id": "PY-SEC-002",
        "title": "Dynamic code execution",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "The code calls eval() on input.",
        "evidence": "result = eval(user_input)",
        "recommendation": "Avoid eval() for untrusted input.",
        "cwe_id": "CWE-95",
        "file_path": "private_source.py",
    }


def test_local_explanation_needs_no_api_key(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    result = explain_finding(sample_finding(), consent=False)
    assert result["provider"] == "local_guidance"
    assert "eval()" in result["explanation"]
    assert "Safer" not in result["explanation"]


def test_local_guidance_has_safe_fallback_for_unknown_rule():
    result = local_explanation({"rule_id": "UNKNOWN", "description": "Review me"})
    assert result["provider"] == "local_guidance"
    assert result["explanation"] == "Review me"


def test_redaction_masks_common_secret_formats():
    text = 'API_KEY = "super-secret-value" Authorization: Bearer abc.def.ghi'
    safe = redact_sensitive_text(text)
    assert "super-secret-value" not in safe
    assert "abc.def.ghi" not in safe
    assert safe.count("[REDACTED]") >= 2


def test_nvidia_mode_requires_explicit_consent(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    with pytest.raises(PermissionError):
        explain_finding(sample_finding(), consent=False)


def test_nvidia_request_uses_pinned_model_and_only_minimal_redacted_finding(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": (
                            "WHAT IT MEANS\neval() treats a string as Python code.\n"
                            "WHY IT MATTERS\nUntrusted input can run attacker-controlled code.\n"
                            "SAFER APPROACH\nAvoid eval() and use a constrained parser.\n"
                            "SAFE EXAMPLE\nUse ast.literal_eval() for literal data."
                        ),
                    }
                }]
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["body"] = request.data.decode("utf-8")
        captured["timeout"] = timeout
        return FakeResponse()

    finding = sample_finding()
    finding["evidence"] = 'API_KEY = "super-secret-value"'

    with patch("security_analyzer.ai.explainer.urlopen", side_effect=fake_urlopen):
        result = explain_finding(finding, consent=True)

    sent = json.loads(captured["body"])
    sent_text = json.dumps(sent, ensure_ascii=False)

    assert result["provider"] == "nvidia"
    assert result["model"] == NVIDIA_MODEL
    assert result["model"] == "nvidia/nemotron-3.5-lightning-30b-a3b"
    assert "eval() treats a string" in result["explanation"]
    instructions = sent["messages"][0]["content"]
    assert "English only" in instructions
    assert "WHAT IT MEANS" in instructions
    assert "WHY IT MATTERS" in instructions
    assert "SAFER APPROACH" in instructions
    assert "SAFE EXAMPLE" in instructions
    assert "in plain Turkish" not in instructions
    assert captured["url"] == NVIDIA_CHAT_COMPLETIONS_URL
    assert sent["model"] == NVIDIA_MODEL
    assert sent["stream"] is False
    assert sent["max_tokens"] == 1024
    assert sent["chat_template_kwargs"] == {"enable_thinking": False}
    assert "top_p" not in sent
    assert "super-secret-value" not in sent_text
    assert "private_source.py" not in sent_text
    assert "finding_id" not in sent_text
    assert captured["timeout"] == 45
    assert "Bearer test-key" in captured["headers"].get("Authorization", "")


def test_nvidia_empty_output_is_rejected(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"choices": []}'

    with patch("security_analyzer.ai.explainer.urlopen", return_value=FakeResponse()):
        with pytest.raises(ExplanationProviderError, match="no chat completion choices"):
            explain_finding(sample_finding(), consent=True)


def test_nvidia_401_error_is_safe_and_actionable(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    error = HTTPError(
        NVIDIA_CHAT_COMPLETIONS_URL,
        401,
        "Unauthorized",
        hdrs=None,
        fp=None,
    )
    with patch("security_analyzer.ai.explainer.urlopen", side_effect=error):
        with pytest.raises(ExplanationProviderError, match="NVIDIA rejected the API key"):
            explain_finding(sample_finding(), consent=True)


def test_nvidia_429_exposes_only_bounded_retry_after_and_local_status(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    headers = Message()
    headers["Retry-After"] = "31"
    error = HTTPError(NVIDIA_CHAT_COMPLETIONS_URL, 429, "Too Many Requests", headers, None)

    with patch("security_analyzer.ai.explainer.urlopen", side_effect=error) as mocked:
        with pytest.raises(ExplanationProviderError, match="rate limit or quota") as caught:
            explain_finding(sample_finding(), consent=True)

    assert caught.value.status_code == 429
    assert caught.value.retry_after == 31
    mocked.assert_called_once()


def test_nvidia_timeout_maps_to_gateway_timeout_without_retry(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    with patch("security_analyzer.ai.explainer.urlopen", side_effect=TimeoutError("slow")) as mocked:
        with pytest.raises(ExplanationProviderError, match="timed out") as caught:
            explain_finding(sample_finding(), consent=True)

    assert caught.value.status_code == 504
    mocked.assert_called_once()
