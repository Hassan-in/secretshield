"""
cli.py
Command-line interface:

    python -m secret_scanner.cli scan <path> [--json out.json] [--html out.html] [--no-entropy] [--fail-on HIGH]
"""

import argparse
import sys
import os

from .scanner import scan_directory, scan_git_history, _sort
from .report import render_html_report, render_json_report

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

RESET = "\033[0m"
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[92m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}


def print_console_report(summary):
    d = summary.to_dict()
    counts = d["counts_by_severity"]
    print(f"\n{COLORS['BOLD']}Secret & Weak-Crypto Scan{RESET}")
    print(f"{COLORS['DIM']}Files scanned: {d['files_scanned']}  |  Skipped: {d['files_skipped']}{RESET}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = COLORS[sev]
        print(f"  {c}{sev:<9}{RESET} {counts[sev]}")
    print()

    real = [f for f in d["findings"] if not f["likely_false_positive"]]
    if not real:
        print(f"{COLORS['LOW']}No issues detected.{RESET}\n")
        return

    for f in real:
        c = COLORS.get(f["severity"], "")
        loc = f"{f['file']}:{f['line_number']}" if f["line_number"] else f["file"]
        print(f"{c}[{f['severity']}]{RESET} {f['name']}  {COLORS['DIM']}({loc}){RESET}")
        print(f"   {f['description']}")
        if f["matched_value"]:
            print(f"   value: {f['matched_value']}")
        if f["line_preview"]:
            print(f"   {COLORS['DIM']}{f['line_preview'][:140]}{RESET}")
        print()

    fp_count = len(d["findings"]) - len(real)
    if fp_count:
        print(f"{COLORS['DIM']}({fp_count} likely false positive(s) hidden — see --json/--html for full detail){RESET}\n")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan source code for hardcoded secrets and weak cryptographic practices."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a directory")
    scan_p.add_argument("path", help="Path to the project directory to scan")
    scan_p.add_argument("--json", metavar="FILE", help="Write JSON report to FILE")
    scan_p.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    scan_p.add_argument("--no-entropy", action="store_true", help="Disable entropy-based detection")
    scan_p.add_argument("--git-history", action="store_true", help="Also scan lines added in past git commits")
    scan_p.add_argument("--exclude", action="append", default=[], help="Additional directory name to exclude (repeatable)")
    scan_p.add_argument(
        "--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], default="HIGH",
        help="Exit with non-zero status if a finding at or above this severity is present (default: HIGH)"
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        if not os.path.isdir(args.path):
            print(f"Error: '{args.path}' is not a directory", file=sys.stderr)
            return 2

        summary = scan_directory(
            args.path,
            extra_excludes=set(args.exclude),
            enable_entropy=not args.no_entropy,
        )
        if args.git_history:
            hist = scan_git_history(args.path, enable_entropy=not args.no_entropy)
            summary.findings.extend(hist.findings)
            _sort(summary)
        d = summary.to_dict()

        print_console_report(summary)

        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(render_json_report(d))
            print(f"JSON report written to {args.json}")

        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_html_report(d, os.path.abspath(args.path)))
            print(f"HTML report written to {args.html}")

        if args.fail_on != "NONE":
            threshold = SEVERITY_ORDER[args.fail_on]
            real_findings = [f for f in d["findings"] if not f["likely_false_positive"]]
            if any(SEVERITY_ORDER[f["severity"]] <= threshold for f in real_findings):
                return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())
