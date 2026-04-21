from __future__ import annotations

import os
import sys
from collections import Counter

from .models import BLOCKED_VERDICTS, CheckResult, Verdict


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


if not _colors_enabled():
    for _attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "CYAN", "GRAY"):
        setattr(C, _attr, "")


VERDICT_STYLE: dict[Verdict, tuple[str, str]] = {
    Verdict.OK:        (C.GREEN,  "✓ OK"),
    Verdict.DNS_BLOCK: (C.RED,    "✗ DNS BLOCK"),
    Verdict.TCP_RESET: (C.RED,    "✗ TCP RESET"),
    Verdict.TLS_BLOCK: (C.RED,    "✗ TLS BLOCK"),
    Verdict.HTTP_STUB: (C.RED,    "✗ HTTP STUB"),
    Verdict.TIMEOUT:   (C.YELLOW, "⚠ TIMEOUT"),
    Verdict.DOWN:      (C.GRAY,   "· DOWN"),
    Verdict.UNKNOWN:   (C.GRAY,   "? UNKNOWN"),
}


def print_header(info: dict) -> None:
    print(f"\n{C.BOLD}{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  RKN Block Checker{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 70}{C.RESET}")
    if info:
        print(f"  {C.DIM}IP:{C.RESET}       {info.get('ip', '?')}")
        print(f"  {C.DIM}ISP:{C.RESET}      {info.get('org', '?')}")
        loc = f"{info.get('city', '?')}, {info.get('region', '?')}, {info.get('country', '?')}"
        print(f"  {C.DIM}Location:{C.RESET} {loc}")
    else:
        print(f"  {C.YELLOW}couldn't fetch IP info{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'-' * 70}{C.RESET}")


def print_section(title: str) -> None:
    print(f"\n{C.BOLD}{title}{C.RESET}")
    print(
        f"  {C.DIM}{'name':<14}{'verdict':<14}"
        f"{'TCP':>8}{'TLS':>8}{'PLT':>8}  {'status':<6}{C.RESET}"
    )
    print(f"  {C.DIM}{'-' * 60}{C.RESET}")


def print_result(r: CheckResult) -> None:
    color, label = VERDICT_STYLE.get(r.verdict, (C.GRAY, r.verdict.value))

    status = str(r.status_code) if r.status_code else "—"
    tcp = f"{r.tcp_time_ms:.0f}ms" if r.tcp_time_ms is not None else "—"
    tls = f"{r.tls_time_ms:.0f}ms" if r.tls_time_ms is not None else "—"
    plt = f"{r.plt_ms:.0f}ms" if r.plt_ms is not None else "—"

    print(
        f"  {r.name:<14}"
        f"{color}{label:<14}{C.RESET}"
        f"{tcp:>8}{tls:>8}{plt:>8}  "
        f"{status:<6}"
    )
    for note in r.notes:
        print(f"    {C.DIM}└ {note}{C.RESET}")


def print_summary(white: list[CheckResult], black: list[CheckResult]) -> None:
    white_ok = sum(1 for r in white if r.verdict == Verdict.OK)
    black_ok = sum(1 for r in black if r.verdict == Verdict.OK)
    black_blocked = sum(1 for r in black if r.verdict in BLOCKED_VERDICTS)

    print(f"\n{C.BOLD}{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD}  Summary{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'-' * 70}{C.RESET}")
    print(f"  Whitelist: {white_ok}/{len(white)} working")
    print(
        f"  Blacklist: {black_ok}/{len(black)} open, "
        f"{black_blocked}/{len(black)} blocked"
    )

    color, verdict = _summary_verdict(
        white_ok, len(white), black_ok, black_blocked, len(black)
    )
    print(f"\n  {color}{C.BOLD}→ {verdict}{C.RESET}")

    types = Counter(r.verdict for r in black if r.verdict in BLOCKED_VERDICTS)
    if types:
        print(f"\n  {C.DIM}Block types in the blacklist:{C.RESET}")
        for verdict_type, count in types.most_common():
            type_color, label = VERDICT_STYLE.get(
                verdict_type, (C.GRAY, verdict_type.value)
            )
            print(f"    {type_color}{label}{C.RESET}: {count}")

    print(f"{C.BOLD}{C.CYAN}{'=' * 70}{C.RESET}\n")


def _summary_verdict(
    white_ok: int,
    white_total: int,
    black_ok: int,
    black_blocked: int,
    black_total: int,
) -> tuple[str, str]:
    if white_ok < white_total / 2:
        return C.YELLOW, "Connectivity is degraded — even the whitelist barely loads."
    if black_blocked == 0 and black_ok == black_total:
        return C.GREEN, "You're NOT in an RKN-blocked zone (or you're using a VPN)."
    if black_blocked >= black_total * 0.7:
        return C.RED, "You ARE in an RKN-blocked zone."
    return C.YELLOW, "Partial blocks — some blacklisted sites still load."
