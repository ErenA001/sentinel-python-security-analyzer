from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from security_analyzer.analyzer import analyze_source


DATASET_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "labeled_samples.json"


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def calculate_metrics(
    true_positive: int,
    false_positive: int,
    false_negative: int,
    true_negative: int,
) -> dict[str, Any]:
    """Calculate standard binary classification metrics from labeled counts."""
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    specificity = _ratio(true_negative, true_negative + false_positive)

    if precision is None or recall is None or precision + recall == 0:
        f1_score = None
    else:
        f1_score = round(2 * precision * recall / (precision + recall), 4)

    total = true_positive + false_positive + false_negative + true_negative
    accuracy = _ratio(true_positive + true_negative, total)

    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "specificity": specificity,
        "accuracy": accuracy,
        "sample_count": total,
    }


def evaluate_labeled_samples(samples: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate custom rules against explicit vulnerable/safe synthetic samples."""
    counters: dict[str, dict[str, int]] = defaultdict(
        lambda: {"true_positive": 0, "false_positive": 0, "false_negative": 0, "true_negative": 0}
    )

    for index, sample in enumerate(samples):
        rule_id = sample.get("rule_id")
        label = sample.get("label")
        source = sample.get("source")
        if not isinstance(rule_id, str) or label not in {"vulnerable", "safe"} or not isinstance(source, str):
            raise ValueError(f"Invalid labeled sample at index {index}.")

        result = analyze_source(
            source,
            file_path=str(sample.get("id", f"sample-{index + 1}.py")) + ".py",
            include_bandit=False,
            include_mypy=False,
        )
        detected = any(finding.rule_id == rule_id for finding in result.findings)
        expected_vulnerable = label == "vulnerable"

        if expected_vulnerable and detected:
            key = "true_positive"
        elif expected_vulnerable and not detected:
            key = "false_negative"
        elif not expected_vulnerable and detected:
            key = "false_positive"
        else:
            key = "true_negative"
        counters[rule_id][key] += 1

    per_rule = {
        rule_id: calculate_metrics(**counts)
        for rule_id, counts in sorted(counters.items())
    }

    overall_counts = {
        key: sum(item[key] for item in counters.values())
        for key in ("true_positive", "false_positive", "false_negative", "true_negative")
    }

    return {
        "dataset_type": "synthetic_regression_samples",
        "warning": (
            "These metrics describe only this small, hand-labeled regression set. "
            "They are not a measure of real-world detection accuracy."
        ),
        "overall": calculate_metrics(**overall_counts),
        "per_rule": per_rule,
    }


def load_default_dataset() -> list[dict[str, Any]]:
    with DATASET_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("Evaluation dataset must be a JSON array.")
    return payload


def main() -> int:
    report = evaluate_labeled_samples(load_default_dataset())
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
