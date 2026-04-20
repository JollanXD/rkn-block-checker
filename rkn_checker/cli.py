from __future__ import annotations

import argparse
import json
import logging
import sys

from .core import check_urls_parallel, get_self_info
from .output import print_header, print_result, print_section, print_summary
from .targets import BLACK_URLS, WHITE_URLS


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rkn-check",
        description=(
            "Probe a list of sites and decide whether the current network "
            "is in an RKN-blocked zone."
        ),
    )
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="emit machine-readable JSON instead of the colored report")
    p.add_argument("--white", dest="white_only", action="store_true",
                   help="check only the control (whitelist) targets")
    p.add_argument("--black", dest="black_only", action="store_true",
                   help="check only the blacklist targets")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="per-probe timeout in seconds (default: 5.0)")
    p.add_argument("--workers", type=int, default=10,
                   help="thread pool size for parallel checks (default: 10)")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="increase log verbosity (-v info, -vv debug)")
    return p


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    run_white = not args.black_only
    run_black = not args.white_only

    white_results = (
        check_urls_parallel(WHITE_URLS, args.workers, args.timeout)
        if run_white else []
    )
    black_results = (
        check_urls_parallel(BLACK_URLS, args.workers, args.timeout)
        if run_black else []
    )

    if args.as_json:
        payload = {
            "self_info": get_self_info(),
            "whitelist": [r.to_dict() for r in white_results],
            "blacklist": [r.to_dict() for r in black_results],
        }
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    print_header(get_self_info())
    if run_white:
        print_section("Whitelist (should always work)")
        for r in white_results:
            print_result(r)
    if run_black:
        print_section("Blacklist (RKN-restricted)")
        for r in black_results:
            print_result(r)
    if run_white and run_black:
        print_summary(white_results, black_results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
