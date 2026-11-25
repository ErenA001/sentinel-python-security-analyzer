# Labeled evaluation samples

Run the synthetic regression evaluation from the project root:

```bash
python -m security_analyzer.evaluation
```

The dataset contains 50 hand-labeled synthetic examples for the five custom security rules. Each rule has 10 examples: five labeled as vulnerable and five labeled as safe. The evaluation calculates precision, recall, F1-score, specificity, and accuracy from those labels.

These values describe only this small, hand-labeled regression set. They must not be presented as real-world detection accuracy or as evidence that the analyzer catches every vulnerability. The samples are deliberately constructed to exercise known rule patterns; they are not an independent benchmark. A larger, independently labeled dataset containing varied real-world code is required for a meaningful empirical evaluation.
