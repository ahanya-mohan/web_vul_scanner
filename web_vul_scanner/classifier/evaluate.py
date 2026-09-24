"""Evaluate the phishing-URL classifier on the held-out split.

Run as a module:

    python -m web_vul_scanner.classifier.evaluate
"""

from __future__ import annotations

import argparse
from pathlib import Path

from web_vul_scanner.classifier.dataset import DEFAULT_DATASET, load_dataset, train_test_split
from web_vul_scanner.classifier.features import FEATURE_NAMES
from web_vul_scanner.classifier.metrics import evaluate
from web_vul_scanner.classifier.model import GaussianNaiveBayes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the phishing-URL classifier.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET)
    args = parser.parse_args(argv)

    urls, labels = load_dataset(args.data)
    x_train, y_train, x_test, y_test = train_test_split(urls, labels)

    model = GaussianNaiveBayes(FEATURE_NAMES).fit(x_train, y_train)
    predictions = [model.predict(x) for x in x_test]
    print(evaluate(y_test, predictions).format())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
