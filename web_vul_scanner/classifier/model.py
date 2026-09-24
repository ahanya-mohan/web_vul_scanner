"""A Gaussian Naive Bayes classifier, implemented from scratch.

Naive Bayes assumes the features are conditionally independent given the class.
For each class the model stores a prior and, per feature, a mean and variance;
prediction scores a URL by summing Gaussian log-likelihoods plus the log-prior
and picking the largest. The model serializes to plain JSON (no pickle), so a
trained model is a small, reviewable text file.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

# Floor on variance so a feature that is constant within a class does not make
# the Gaussian collapse to a spike (division by zero).
_MIN_VARIANCE = 1e-6


class GaussianNaiveBayes:
    def __init__(self, feature_names: list[str]) -> None:
        self.feature_names = feature_names
        self.classes: list[int] = []
        self.priors: dict[int, float] = {}
        self.means: dict[int, list[float]] = {}
        self.variances: dict[int, list[float]] = {}

    def fit(self, samples: list[list[float]], labels: list[int]) -> GaussianNaiveBayes:
        if not samples:
            raise ValueError("Cannot fit on an empty dataset")

        self.classes = sorted(set(labels))
        total = len(labels)
        width = len(self.feature_names)

        for cls in self.classes:
            rows = [x for x, y in zip(samples, labels, strict=True) if y == cls]
            self.priors[cls] = len(rows) / total
            self.means[cls] = [_mean(col) for col in _columns(rows, width)]
            self.variances[cls] = [
                max(_variance(col, mean), _MIN_VARIANCE)
                for col, mean in zip(_columns(rows, width), self.means[cls], strict=True)
            ]
        return self

    def _log_posterior(self, features: list[float], cls: int) -> float:
        score = math.log(self.priors[cls])
        for value, mean, var in zip(
            features, self.means[cls], self.variances[cls], strict=True
        ):
            score += -0.5 * math.log(2 * math.pi * var) - (value - mean) ** 2 / (2 * var)
        return score

    def predict_proba(self, features: list[float]) -> dict[int, float]:
        logs = {cls: self._log_posterior(features, cls) for cls in self.classes}
        top = max(logs.values())
        weights = {cls: math.exp(log - top) for cls, log in logs.items()}
        normalizer = sum(weights.values())
        return {cls: weight / normalizer for cls, weight in weights.items()}

    def predict(self, features: list[float]) -> int:
        return max(self.classes, key=lambda cls: self._log_posterior(features, cls))

    # -- persistence -----------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "feature_names": self.feature_names,
            "classes": self.classes,
            "priors": {str(c): self.priors[c] for c in self.classes},
            "means": {str(c): self.means[c] for c in self.classes},
            "variances": {str(c): self.variances[c] for c in self.classes},
        }

    @classmethod
    def from_dict(cls, data: dict) -> GaussianNaiveBayes:
        model = cls(data["feature_names"])
        model.classes = [int(c) for c in data["classes"]]
        model.priors = {int(c): v for c, v in data["priors"].items()}
        model.means = {int(c): v for c, v in data["means"].items()}
        model.variances = {int(c): v for c, v in data["variances"].items()}
        return model

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> GaussianNaiveBayes:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _columns(rows: list[list[float]], width: int) -> list[list[float]]:
    return [[row[i] for row in rows] for i in range(width)]


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _variance(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    return sum((v - mean) ** 2 for v in values) / (len(values) - 1)
