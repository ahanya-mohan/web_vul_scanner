"""The phishing-URL classifier: features, model, persistence and CLI."""

from __future__ import annotations

from web_vul_scanner.classifier.dataset import DEFAULT_MODEL, load_dataset, train_test_split
from web_vul_scanner.classifier.features import FEATURE_NAMES, extract_features, feature_vector
from web_vul_scanner.classifier.metrics import evaluate
from web_vul_scanner.classifier.model import GaussianNaiveBayes
from web_vul_scanner.cli import main


def test_features_capture_scheme_and_host_shape() -> None:
    phishing = extract_features("http://192.168.0.1/paypal@login-secure.tk")
    assert phishing["has_ip_host"] == 1.0
    assert phishing["is_https"] == 0.0
    assert phishing["has_at"] == 1.0
    assert phishing["num_suspicious_words"] >= 1.0

    legit = extract_features("https://github.com/login")
    assert legit["is_https"] == 1.0
    assert legit["has_ip_host"] == 0.0
    assert legit["has_at"] == 0.0


def test_model_learns_to_separate_the_classes() -> None:
    urls, labels = load_dataset()
    x_train, y_train, x_test, y_test = train_test_split(urls, labels)

    model = GaussianNaiveBayes(FEATURE_NAMES).fit(x_train, y_train)
    predictions = [model.predict(x) for x in x_test]

    assert evaluate(y_test, predictions).accuracy >= 0.8


def test_model_round_trips_through_json(tmp_path) -> None:
    urls, labels = load_dataset()
    features = [feature_vector(u) for u in urls]
    model = GaussianNaiveBayes(FEATURE_NAMES).fit(features, labels)

    path = tmp_path / "model.json"
    model.save(path)
    reloaded = GaussianNaiveBayes.load(path)

    for vector in features:
        assert reloaded.predict(vector) == model.predict(vector)


def test_bundled_model_exists_and_loads() -> None:
    model = GaussianNaiveBayes.load(DEFAULT_MODEL)
    assert model.feature_names == FEATURE_NAMES


def test_classify_cli_uses_a_trained_model(tmp_path, capsys) -> None:
    urls, labels = load_dataset()
    GaussianNaiveBayes(FEATURE_NAMES).fit([feature_vector(u) for u in urls], labels).save(
        tmp_path / "m.json"
    )

    model_arg = str(tmp_path / "m.json")
    phishing_url = "http://10.0.0.1/paypal-verify-account.tk/login"

    exit_code = main(["classify", phishing_url, "--model", model_arg])
    assert exit_code == 0
    assert "PHISHING" in capsys.readouterr().out

    main(["classify", "https://www.wikipedia.org/", "--model", model_arg])
    assert "legitimate" in capsys.readouterr().out


def test_classify_cli_errors_without_a_model(tmp_path, capsys) -> None:
    exit_code = main(["classify", "http://example.com", "--model", str(tmp_path / "missing.json")])
    assert exit_code == 2
    assert "no model" in capsys.readouterr().err
