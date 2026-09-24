"""Turn a URL string into a fixed numeric feature vector.

The features are cheap, lexical properties of the URL that tend to differ
between legitimate and phishing links: overall length, host shape, the number
of dots and hyphens, whether the host is a raw IP address, whether the scheme
is HTTPS, and whether the URL contains tokens phishing pages favour.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

# Tokens disproportionately common in phishing URLs.
_SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "bank", "billing", "password", "support", "security", "webscr", "limited",
)

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special",
    "has_at",
    "has_ip_host",
    "is_https",
    "num_subdomains",
    "digit_ratio",
    "num_suspicious_words",
]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(url: str) -> dict[str, float]:
    """Compute the named features for ``url``."""
    parts = urlsplit(url if "//" in url else f"http://{url}")
    host = parts.hostname or ""
    path = parts.path or ""
    lowered = url.lower()

    digits = sum(ch.isdigit() for ch in url)
    length = max(len(url), 1)
    subdomains = 0 if _is_ip(host) else max(0, host.count(".") - 1)

    return {
        "url_length": float(len(url)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "num_dots": float(host.count(".")),
        "num_hyphens": float(host.count("-")),
        "num_digits": float(digits),
        "num_special": float(sum(url.count(c) for c in "@?%=&_~")),
        "has_at": 1.0 if "@" in url else 0.0,
        "has_ip_host": 1.0 if _is_ip(host) else 0.0,
        "is_https": 1.0 if parts.scheme == "https" else 0.0,
        "num_subdomains": float(subdomains),
        "digit_ratio": digits / length,
        "num_suspicious_words": float(sum(word in lowered for word in _SUSPICIOUS_WORDS)),
    }


def feature_vector(url: str) -> list[float]:
    """The features for ``url`` as a list ordered by :data:`FEATURE_NAMES`."""
    features = extract_features(url)
    return [features[name] for name in FEATURE_NAMES]
