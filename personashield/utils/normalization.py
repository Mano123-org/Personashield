"""Normalize inconsistent field names from imported breach datasets."""
from __future__ import annotations

FIELD_ALIASES: dict[str, list[str]] = {
    "email": ["email", "mail", "email_address", "e_mail", "emailaddress"],
    "username": ["username", "user", "user_name", "login", "handle"],
    "phone": ["phone", "phone_number", "mobile", "tel", "telephone"],
    "password_hash": [
        "password_hash", "password", "pass", "pwd", "hash",
        "password_hashed", "pwd_hash",
    ],
    "hash_type": ["hash_type", "hashtype", "algo", "algorithm"],
    "source": ["source", "breach", "breach_name", "db_name", "dataset"],
    "domain": ["domain", "site", "website"],
    "full_name": ["full_name", "fullname", "name", "real_name"],
    "ip_address": ["ip_address", "ip", "ipaddr"],
    "breach_date": ["breach_date", "date", "leaked_at", "leak_date"],
    "description": ["description", "notes", "desc"],
}

_REVERSE_LOOKUP: dict[str, str] = {
    alias.lower(): canonical
    for canonical, aliases in FIELD_ALIASES.items()
    for alias in aliases
}


def normalize_field_name(raw_name: str) -> str | None:
    """Map an arbitrary column/key name to a canonical PersonaShield field."""
    key = raw_name.strip().lower().replace(" ", "_").replace("-", "_")
    return _REVERSE_LOOKUP.get(key)


def normalize_row(raw_row: dict) -> dict:
    """Normalize an entire imported row's keys to canonical field names."""
    out: dict = {}
    for k, v in raw_row.items():
        if k is None:
            continue
        canonical = normalize_field_name(str(k))
        if canonical is None:
            continue
        if v is None or (isinstance(v, str) and v.strip() == ""):
            continue
        out[canonical] = v
    return out
