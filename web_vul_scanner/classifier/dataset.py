"""Load the labelled URL dataset and split it deterministically."""

from __future__ import annotations

import csv
import random
from pathlib import Path

from web_vul_scanner.classifier.features import feature_vector

# Repo-root-relative default location of the dataset.
DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "data" / "urls.csv"
DEFAULT_MODEL = Path(__file__).resolve().parent / "model.json"


def load_dataset(path: str | Path = DEFAULT_DATASET) -> tuple[list[str], list[int]]:
    """Return ``(urls, labels)`` from a two-column ``url,label`` CSV."""
    urls: list[str] = []
    labels: list[int] = []
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def train_test_split(
    urls: list[str],
    labels: list[int],
    *,
    test_fraction: float = 0.3,
    seed: int = 42,
) -> tuple[list, list, list, list]:
    """Deterministically shuffle and split into train/test feature matrices."""
    indices = list(range(len(urls)))
    random.Random(seed).shuffle(indices)
    cut = int(len(indices) * (1 - test_fraction))

    train, test = indices[:cut], indices[cut:]
    x_train = [feature_vector(urls[i]) for i in train]
    y_train = [labels[i] for i in train]
    x_test = [feature_vector(urls[i]) for i in test]
    y_test = [labels[i] for i in test]
    return x_train, y_train, x_test, y_test
