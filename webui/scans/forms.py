"""The scan request form."""

from __future__ import annotations

import re

from django import forms


class ScanForm(forms.Form):
    url = forms.URLField(
        label="Target URL",
        assume_scheme="http",
        widget=forms.URLInput(attrs={"placeholder": "http://127.0.0.1:5000", "autofocus": True}),
    )
    allow_hosts = forms.CharField(
        label="Authorized hosts",
        required=False,
        help_text="Non-loopback hosts you are authorized to scan, separated by spaces or commas.",
        widget=forms.TextInput(attrs={"placeholder": "staging.example.test"}),
    )

    def clean_allow_hosts(self) -> list[str]:
        raw = self.cleaned_data.get("allow_hosts", "")
        return [host for host in re.split(r"[\s,]+", raw) if host]
