"""Train the phishing-URL classifier and save it to model.json.

Run as a module:

    python -m web_vul_scanner.classifier.train
"""

from __future__ import annotations

import argparse
from pathlib import Path

from web_vul_scanner.classifier.dataset import (
    DEFAULT_DATASET,
    DEFAULT_MODEL,
    load_dataset,
    train_test_split,
)
from web_vul_scanner.classifier.features import FEATURE_NAMES, feature_vector
from web_vul_scanner.classifier.metrics import evaluate
from web_vul_scanner.classifier.model import GaussianNaiveBayes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the phishing-URL classifier.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out", type=Path, default=DEFAULT_MODEL)
    args = parser.parse_args(argv)

    urls, labels = load_dataset(args.data)
    x_train, y_train, x_test, y_test = train_test_split(urls, labels)

    model = GaussianNaiveBayes(FEATURE_NAMES).fit(x_train, y_train)

    predictions = [model.predict(x) for x in x_test]
    metrics = evaluate(y_test, predictions)
    print(f"Trained on {len(y_train)} URLs, tested on {len(y_test)}.")
    print(metrics.format())

    # Refit on all data before saving the shipped model.
    all_x = [feature_vector(u) for u in urls]
    GaussianNaiveBayes(FEATURE_NAMES).fit(all_x, labels).save(args.out)
    print(f"\nSaved model to {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
