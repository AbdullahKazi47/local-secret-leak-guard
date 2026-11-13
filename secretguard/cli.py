"""Command-line interface for Local Secret Leak Guard."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .scanner import DEFAULT_MAX_BYTES, scan_path

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secretguard",
        description="Scan local directories for hardcoded secrets, API keys and private tokens.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="files or directories to scan (default: .)")
    parser.add_argument(
        "--ignore-file",
        metavar="PATH",
        help="ignore file to use instead of <path>/.secretignore",
    )
    parser.add_argument("--no-entropy", action="store_true", help="disable the high-entropy string check")
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        metavar="BITS",
        help="minimum bits/char for the entropy check (default: 4.5)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        metavar="N",
        help=f"skip files larger than N bytes (default: {DEFAULT_MAX_BYTES})",
    )
    parser.add_argument("--show-secret", action="store_true", help="print matched values unredacted")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _style(text, code, enabled):
    return f"\033[{code}m{text}\033[0m" if enabled else text


def format_finding(finding, show_secret=False, color=False):
    location = _style(f"{finding.path}:{finding.line_no}:{finding.column}", "1", color)
    rule = _style(finding.rule, "31", color)
    value = finding.secret if show_secret else finding.redacted
    return f"{location}: {rule} - {finding.description} [{value}]"


def main(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    color = not args.no_color and hasattr(out, "isatty") and out.isatty()

    total = 0
    for raw in args.paths:
        path = Path(raw)
        if not path.exists():
            print(f"error: path not found: {raw}", file=sys.stderr)
            return EXIT_ERROR
        findings = scan_path(
            path,
            ignore_file=args.ignore_file,
            use_entropy=not args.no_entropy,
            entropy_threshold=args.entropy_threshold,
            max_bytes=args.max_bytes,
        )
        for finding in findings:
            print(format_finding(finding, args.show_secret, color), file=out)
        total += len(findings)

    if total:
        noun = "potential secret" if total == 1 else "potential secrets"
        print(f"\n{total} {noun} found.", file=out)
        return EXIT_FINDINGS
    print("No secrets found.", file=out)
    return EXIT_CLEAN
