"""
Lightweight, self-contained username-enumeration adapter.

This is inspired by Sherlock's approach (check whether a username exists
on a platform by requesting its public profile URL) but is a clean,
minimal PersonaShield-owned implementation — no API keys, no scraping of
private data, only public profile-existence checks.

Add/edit entries in SITES to extend platform coverage.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from personashield.models import UsernameHit


@dataclass
class SiteDef:
    name: str
    url_template: str          # "{}" replaced with username
    error_type: str = "status_code"   # "status_code" or "message"
    error_msg: str | None = None      # substring indicating "not found" if error_type == "message"


SITES: list[SiteDef] = [
    SiteDef("GitHub", "https://github.com/{}"),
    SiteDef("GitLab", "https://gitlab.com/{}"),
    SiteDef("Reddit", "https://www.reddit.com/user/{}"),
    SiteDef("Instagram", "https://www.instagram.com/{}/"),
    SiteDef("Twitter/X", "https://x.com/{}"),
    SiteDef("YouTube", "https://www.youtube.com/@{}"),
    SiteDef("Pinterest", "https://www.pinterest.com/{}/"),
    SiteDef("Medium", "https://medium.com/@{}"),
    SiteDef("DockerHub", "https://hub.docker.com/u/{}"),
    SiteDef("HackerNews", "https://news.ycombinator.com/user?id={}"),
    SiteDef("Steam", "https://steamcommunity.com/id/{}"),
    SiteDef("Twitch", "https://www.twitch.tv/{}"),
    SiteDef("SoundCloud", "https://soundcloud.com/{}"),
    SiteDef("Keybase", "https://keybase.io/{}"),
    SiteDef("Dev.to", "https://dev.to/{}"),
    SiteDef("Replit", "https://replit.com/@{}"),
    SiteDef("npm", "https://www.npmjs.com/~{}"),
    SiteDef("PyPI", "https://pypi.org/user/{}/"),
]


async def _check_site(client: httpx.AsyncClient, site: SiteDef, username: str) -> UsernameHit:
    url = site.url_template.format(username)
    start = time.monotonic()
    try:
        resp = await client.get(url, follow_redirects=True)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if site.error_type == "status_code":
            status = "Found" if resp.status_code == 200 else "Not Found"
            if resp.status_code not in (200, 404, 403, 410):
                status = "Unknown"
        else:
            body = resp.text[:5000] if resp.text else ""
            status = "Not Found" if (site.error_msg and site.error_msg in body) else "Found"
        return UsernameHit(
            platform=site.name, username=username, url=url,
            status=status, response_ms=elapsed_ms,
        )
    except httpx.RequestError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return UsernameHit(
            platform=site.name, username=username, url=url,
            status="Error", response_ms=elapsed_ms,
        )


async def enumerate_username_async(
    username: str,
    sites: list[SiteDef] | None = None,
    timeout: float = 6.0,
    max_concurrency: int = 15,
) -> list[UsernameHit]:
    sites = sites or SITES
    limits = httpx.Limits(max_connections=max_concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (PersonaShield OSINT tool)"}
    async with httpx.AsyncClient(timeout=timeout, headers=headers, limits=limits) as client:
        sem = asyncio.Semaphore(max_concurrency)

        async def bounded(site: SiteDef) -> UsernameHit:
            async with sem:
                return await _check_site(client, site, username)

        return await asyncio.gather(*(bounded(s) for s in sites))


def enumerate_username(username: str, **kwargs) -> list[UsernameHit]:
    """Synchronous wrapper for CLI use."""
    return asyncio.run(enumerate_username_async(username, **kwargs))
