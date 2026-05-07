from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import requests

from . import __version__
from .targets import STUB_MARKERS

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
BODY_SNIPPET_LEN = 2000

# By default we send headers indistinguishable from a typical Chrome browser.
# This is a privacy choice for the *user*, not an attempt to hide from the
# servers being probed: an honest "RKN-Checker/<ver>" UA used to be the
# default, but it leaves a unique fingerprint in any logs along the path —
# including logs at VPN providers that, in some jurisdictions, hand data to
# regulators. A generic UA blends the probe in with normal traffic and
# minimizes the risk for users diagnosing their own connection. Operators
# who *want* to be seen as diagnostic tooling (e.g. probing infrastructure
# they own) can opt in via the --identify CLI flag, which switches to a
# self-identifying UA.
GENERIC_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/147.0.0.0 Safari/537.36"
)
HONEST_USER_AGENT = (
    f"rkn-block-checker/{__version__} "
    "(+https://github.com/MayersScott/rkn-block-checker)"
)

# Headers Chrome actually sends. Without these, requests still stand out
# even with the right UA — many sites and middleboxes fingerprint on the
# header *set*, not just User-Agent.
GENERIC_HEADERS: dict[str, str] = {
    "User-Agent": GENERIC_USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


@dataclass
class HttpProbe:
    status_code: Optional[int] = None
    elapsed_ms: Optional[float] = None
    body_snippet: str = ""
    error: Optional[str] = None
    timed_out: bool = False


def build_headers(identify: bool = False) -> dict[str, str]:
    """Return the header set to use for a probe.

    `identify=False` (default): generic Chrome-like headers — minimizes the
    fingerprint left in logs. This is what end users running the tool to
    check their own connection should send.

    `identify=True`: honest, self-identifying UA so that operators of probed
    infrastructure can distinguish this tool from anonymous traffic. Use
    this when you control or have permission to probe the target.
    """
    if identify:
        return {**GENERIC_HEADERS, "User-Agent": HONEST_USER_AGENT}
    return dict(GENERIC_HEADERS)


def fetch(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    identify: bool = False,
) -> HttpProbe:
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=build_headers(identify=identify),
        )
        return HttpProbe(
            status_code=r.status_code,
            elapsed_ms=r.elapsed.total_seconds() * 1000,
            body_snippet=r.text[:BODY_SNIPPET_LEN].lower(),
        )
    except requests.exceptions.Timeout:
        return HttpProbe(error="timeout", timed_out=True)
    except requests.exceptions.RequestException as e:
        return HttpProbe(error=f"{type(e).__name__}: {e}")


def looks_like_stub(body_snippet: str) -> bool:
    return any(marker in body_snippet for marker in STUB_MARKERS)
