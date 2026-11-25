from security_analyzer.evaluation import (
    calculate_metrics,
    evaluate_labeled_samples,
    load_default_dataset,
)


def test_calculate_metrics_uses_standard_formulas():
    result = calculate_metrics(
        true_positive=8,
        false_positive=2,
        false_negative=2,
        true_negative=8,
    )
    assert result["precision"] == 0.8
    assert result["recall"] == 0.8
    assert result["f1_score"] == 0.8
    assert result["specificity"] == 0.8
    assert result["accuracy"] == 0.8


def test_default_labeled_dataset_covers_five_custom_rules():
    report = evaluate_labeled_samples(load_default_dataset())
    assert report["dataset_type"] == "synthetic_regression_samples"
    assert len(report["per_rule"]) == 5
    assert report["overall"]["sample_count"] == 50
    assert "not a measure of real-world detection accuracy" in report["warning"]


def test_default_dataset_has_balanced_positive_and_negative_samples_per_rule():
    samples = load_default_dataset()
    assert len({sample["id"] for sample in samples}) == 50

    for rule_id in {
        "PY-SEC-001",
        "PY-SEC-002",
        "PY-SEC-003",
        "PY-SEC-004",
        "PY-SEC-005",
    }:
        rule_samples = [sample for sample in samples if sample["rule_id"] == rule_id]
        assert len(rule_samples) == 10
        assert sum(sample["label"] == "vulnerable" for sample in rule_samples) == 5
        assert sum(sample["label"] == "safe" for sample in rule_samples) == 5


def test_current_rules_match_all_labeled_regression_samples():
    report = evaluate_labeled_samples(load_default_dataset())
    assert report["overall"]["true_positive"] == 25
    assert report["overall"]["false_positive"] == 0
    assert report["overall"]["false_negative"] == 0
    assert report["overall"]["true_negative"] == 25

    for metrics in report["per_rule"].values():
        assert metrics["true_positive"] == 5
        assert metrics["false_positive"] == 0
        assert metrics["false_negative"] == 0
        assert metrics["true_negative"] == 5
