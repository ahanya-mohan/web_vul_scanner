"""Minimal Django settings for the scanner's web UI.

The UI is a thin front end over the ``web_vul_scanner`` library: no database,
no user accounts, no persisted state. A scan runs synchronously inside the
request and the result is rendered straight to the page.
"""

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Dev-only key: this app stores nothing and is meant for local use.
SECRET_KEY = "dev-only-not-a-secret-change-for-any-real-deployment"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = ["scans"]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
    }
]

WSGI_APPLICATION = "config.wsgi.application"

# No database: scans are computed on the fly and never stored.
DATABASES: dict = {}

USE_TZ = True
