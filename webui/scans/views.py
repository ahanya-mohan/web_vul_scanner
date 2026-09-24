"""The single scan view: submit a URL, run the scanner, render the result.

This is a thin wrapper over the ``web_vul_scanner`` library — it holds no
scanning logic of its own and enforces the same authorization gate as the CLI.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from scans.forms import ScanForm
from web_vul_scanner.core.authorization import Authorization, UnauthorizedTargetError
from web_vul_scanner.scanner import Scanner


def scan_view(request: HttpRequest) -> HttpResponse:
    form = ScanForm(request.POST or None)
    result = None
    error = None

    if request.method == "POST" and form.is_valid():
        authorization = Authorization(form.cleaned_data["allow_hosts"])
        try:
            with Scanner(authorization) as scanner:
                result = scanner.scan(form.cleaned_data["url"])
        except UnauthorizedTargetError as exc:
            error = str(exc)

    return render(request, "scans/index.html", {"form": form, "result": result, "error": error})
