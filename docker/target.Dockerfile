# The bundled vulnerable practice target. For local, loopback-only use.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY web_vul_scanner ./web_vul_scanner
COPY targets ./targets
RUN pip install --no-cache-dir ".[dev]"

EXPOSE 5000
# Flask's built-in server is fine here: this is a throwaway test target.
CMD ["python", "-m", "flask", "--app", "targets.vulnerable_app.app:create_app", "run", "--host", "0.0.0.0", "--port", "5000"]
