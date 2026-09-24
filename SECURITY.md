# Security and authorized use

`web_vul_scanner` is an educational tool that sends test requests to web
applications to surface common vulnerability classes. Running it against a
system you do not own or have **explicit written permission** to test may be
illegal and is not supported.

## Rules of use

- Only scan hosts you own or are authorized to test.
- The scanner refuses any non-loopback host unless you authorize it explicitly
  with `--allow <host>`. This gate is a safeguard, not permission — the
  responsibility for having authorization is yours.
- The bundled target under `targets/vulnerable_app/` is intentionally
  vulnerable. It binds to loopback and must never be deployed or exposed.

## Reporting a vulnerability in this project

If you find a security issue in the scanner itself, please open a private
report via the repository's security advisory page rather than a public issue.
