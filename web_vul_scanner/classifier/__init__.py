"""Phishing-URL classifier.

A small Gaussian Naive Bayes model that labels a URL as legitimate or phishing
from features of the URL string alone (length, host shape, suspicious tokens,
IP-address host, and so on). It is a standalone, offline capability: it sends
no requests and is independent of the active scanner.
"""

from web_vul_scanner.classifier.features import FEATURE_NAMES, feature_vector
from web_vul_scanner.classifier.model import GaussianNaiveBayes

__all__ = ["FEATURE_NAMES", "GaussianNaiveBayes", "feature_vector"]
