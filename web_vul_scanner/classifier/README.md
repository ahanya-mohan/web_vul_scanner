# Phishing-URL classifier

A Gaussian Naive Bayes classifier that labels a URL as legitimate or phishing
from lexical features of the URL string. It is **offline and standalone**: it
sends no network requests and is independent of the active scanner.

## Use it

```bash
web_vul_scanner classify "http://192.168.0.5/paypal-secure-login.tk/verify"
# PHISHING  (phishing probability 100.0%)

web_vul_scanner classify "https://github.com/login"
# legitimate  (phishing probability 0.0%)
```

## Retrain and evaluate

```bash
python -m web_vul_scanner.classifier.train      # writes classifier/model.json + prints metrics
python -m web_vul_scanner.classifier.evaluate   # metrics on the held-out split
```

## How it works

- `features.py` — extracts 13 numeric features per URL (length, host shape,
  dot/hyphen counts, IP-address host, HTTPS, subdomain count, suspicious
  tokens, ...).
- `model.py` — Gaussian Naive Bayes implemented from scratch (no ML library);
  stores a prior and per-feature mean/variance per class, serialized to JSON.
- `dataset.py` — loads `data/urls.csv` and makes a deterministic train/test
  split.
- `metrics.py` — accuracy, precision, recall, F1 and a confusion matrix.

The bundled `model.json` is trained on the full `data/urls.csv`. See
[`data/README.md`](../../data/README.md) for the dataset's scope and limits.
