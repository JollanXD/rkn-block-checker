from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    OK = "OK"
    DNS_BLOCK = "DNS_BLOCK"
    TCP_RESET = "TCP_RESET"
    TLS_BLOCK = "TLS_BLOCK"
    HTTP_STUB = "HTTP_STUB"
    TIMEOUT = "TIMEOUT"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


BLOCKED_VERDICTS: frozenset[Verdict] = frozenset({
    Verdict.DNS_BLOCK,
    Verdict.TCP_RESET,
    Verdict.TLS_BLOCK,
    Verdict.HTTP_STUB,
    Verdict.TIMEOUT,
})


@dataclass
class CheckResult:
    name: str
    url: str

    verdict: Verdict = Verdict.UNKNOWN
    notes: list[str] = field(default_factory=list)

    sys_ip: Optional[str] = None
    doh_ip: Optional[str] = None
    dns_mismatch: bool = False
    dns_error: Optional[str] = None

    tcp_ok: bool = False
    tcp_time_ms: Optional[float] = None
    tcp_error: Optional[str] = None

    tls_ok: bool = False
    tls_time_ms: Optional[float] = None
    tls_cert_cn: Optional[str] = None
    tls_error: Optional[str] = None

    status_code: Optional[int] = None
    plt_ms: Optional[float] = None
    http_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d
