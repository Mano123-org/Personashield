"""Domain module — DNS, MX, SPF, DMARC posture via public DNS. No API keys."""
from __future__ import annotations

from personashield.models import DomainIntel

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    _HAS_DNSPYTHON = False


def _resolve(domain: str, rtype: str) -> list[str]:
    if not _HAS_DNSPYTHON:
        return []
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5.0)
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def lookup_domain(domain: str) -> DomainIntel:
    domain = domain.strip().lower()
    a_records = _resolve(domain, "A")
    mx_records = _resolve(domain, "MX")
    txt_records = _resolve(domain, "TXT")

    spf_record = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    dmarc_records = _resolve(f"_dmarc.{domain}", "TXT")
    dmarc_record = next((t for t in dmarc_records if "v=dmarc1" in t.lower()), None)

    return DomainIntel(
        domain=domain,
        a_records=a_records,
        mx_records=mx_records,
        txt_records=txt_records,
        has_spf=spf_record is not None,
        has_dmarc=dmarc_record is not None,
        spf_record=spf_record,
        dmarc_record=dmarc_record,
    )
