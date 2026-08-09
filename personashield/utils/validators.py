"""Input validation and target-type auto-detection."""
from __future__ import annotations

import re

from personashield.models import TargetType

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\-\s()]{6,18}[0-9]$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def is_phone(value: str) -> bool:
    digits = re.sub(r"[^\d]", "", value)
    return bool(_PHONE_RE.match(value.strip())) and 7 <= len(digits) <= 15


def is_domain(value: str) -> bool:
    v = value.strip()
    if is_email(v):
        return False
    return bool(_DOMAIN_RE.match(v))


def detect_target_type(value: str) -> TargetType:
    v = value.strip()
    if is_email(v):
        return TargetType.EMAIL
    if is_domain(v):
        return TargetType.DOMAIN
    if is_phone(v):
        return TargetType.PHONE
    if re.match(r"^[A-Za-z0-9_.\-]{2,40}$", v):
        return TargetType.USERNAME
    return TargetType.UNKNOWN


def normalize_phone(value: str) -> str:
    return re.sub(r"[^\d+]", "", value.strip())
