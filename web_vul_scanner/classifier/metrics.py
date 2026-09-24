"""Binary classification metrics for evaluating the phishing classifier.

The positive class is phishing (label 1).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        denom = self.precision + self.recall
        return 2 * self.precision * self.recall / denom if denom else 0.0

    def format(self) -> str:
        return (
            f"accuracy={self.accuracy:.3f}  precision={self.precision:.3f}  "
            f"recall={self.recall:.3f}  f1={self.f1:.3f}\n"
            f"confusion matrix: TP={self.tp} FP={self.fp} TN={self.tn} FN={self.fn}"
        )


def evaluate(y_true: list[int], y_pred: list[int]) -> Metrics:
    pairs = list(zip(y_true, y_pred, strict=True))
    tp = sum(t == 1 and p == 1 for t, p in pairs)
    fp = sum(t == 0 and p == 1 for t, p in pairs)
    tn = sum(t == 0 and p == 0 for t, p in pairs)
    fn = sum(t == 1 and p == 0 for t, p in pairs)
    return Metrics(tp=tp, fp=fp, tn=tn, fn=fn)
