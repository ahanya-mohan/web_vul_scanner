"""A deliberately vulnerable web app, bundled as the scanner's practice target.

WARNING: this application contains intentional security holes (SQL injection,
reflected XSS). It exists only so the scanner has a safe, self-contained target
to run against in development and CI. Do not deploy it or expose it to a
network you do not fully control. It binds to loopback by default.

The vulnerable routes are added over the coming slices; each stays paired with
a safe equivalent so checks can prove both a true positive and no false
positive.
"""

from targets.vulnerable_app.app import create_app

__all__ = ["create_app"]
