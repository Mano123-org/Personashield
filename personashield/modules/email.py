"""
Email module.

No key-gated lookups are performed. This module extracts local metadata
(domain part, MX/SPF/DMARC posture via the domain module) and defers
breach matching to modules/breach.py against the local database.
"""
from __future__ import annotations

from personashield.modules.domain import lookup_domain
from personashield.models import DomainIntel


def email_domain_posture(email: str) -> DomainIntel:
    domain = email.split("@")[-1].strip().lower()
    return lookup_domain(domain)
