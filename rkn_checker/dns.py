from __future__ import annotations

import json
import logging
import socket
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DOH_TIMEOUT = 5.0


def resolve_system(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        logger.debug("system DNS failed for %s: %s", host, e)
        return None


def resolve_doh(host: str, timeout: float = DOH_TIMEOUT) -> Optional[str]:
    try:
        r = requests.get(
            DOH_ENDPOINT,
            params={"name": host, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
        )
        if not r.ok:
            return None
        for ans in r.json().get("Answer", []):
            if ans.get("type") == 1:  # A record
                return ans.get("data")
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.debug("DoH failed for %s: %s", host, e)
    return None
