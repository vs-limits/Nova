from __future__ import annotations

import argparse

from backend.helper.pipeline import NovaPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="NOVA",
        description="NOVA demo web security audit assistant.",
    )
    parser.add_argument("--url", required=True, help="Target URL to scan.")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print more runtime information.",
    )
    return parser


def run_scan() -> None:
    args = build_parser().parse_args()
    NovaPipeline(verbose=args.verbose).run(args.url)
