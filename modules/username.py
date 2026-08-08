"""Username OSINT module — public profile-existence enumeration."""
from __future__ import annotations

from personashield.integrations.sherlock_adapter import enumerate_username
from personashield.models import UsernameHit


def search_username(username: str, timeout: float = 6.0) -> list[UsernameHit]:
    return enumerate_username(username, timeout=timeout)
