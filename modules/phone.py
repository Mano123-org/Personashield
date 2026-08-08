"""Phone module — local validation/parsing only. No API keys, no carrier lookups."""
from __future__ import annotations

import re
from dataclasses import dataclass

# Minimal, local country-code table for basic metadata (not exhaustive).
_COUNTRY_CODES = {
    "1": "US/Canada", "44": "United Kingdom", "91": "India", "61": "Australia",
    "49": "Germany", "33": "France", "81": "Japan", "86": "China",
    "7": "Russia/Kazakhstan", "55": "Brazil", "27": "South Africa", "971": "UAE",
    "65": "Singapore", "82": "South Korea", "39": "Italy", "34": "Spain",
}


@dataclass
class PhoneMetadata:
    raw: str
    normalized: str
    likely_country: str | None
    digit_count: int
    is_plausible: bool


def parse_phone(value: str) -> PhoneMetadata:
    normalized = re.sub(r"[^\d+]", "", value.strip())
    digits = re.sub(r"\D", "", normalized)
    likely_country = None
    if normalized.startswith("+"):
        for code, name in sorted(_COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
            if digits.startswith(code):
                likely_country = name
                break
    plausible = 7 <= len(digits) <= 15
    return PhoneMetadata(
        raw=value, normalized=normalized, likely_country=likely_country,
        digit_count=len(digits), is_plausible=plausible,
    )
