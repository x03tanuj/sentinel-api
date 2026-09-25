#!/usr/bin/env python3
"""SentinelAPI CI Security Quality Gate.

Evaluates exported scan findings JSON against user-configured severity
and confidence thresholds. Exits non-zero (1) if unacceptable vulnerabilities
are detected, or 0 if the security gate criteria pass.

Usage:
    python scripts/ci_gate.py --findings findings.json --fail-on CRITICAL,HIGH --min-confidence 0.7
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def parse_severities(sev_str: str) -> set[str]:
    """Parse and validate comma-separated severity list."""
    sevs = {s.strip().upper() for s in sev_str.split(",") if s.strip()}
    invalid = sevs - VALID_SEVERITIES
    if invalid:
        raise ValueError(
            f"Invalid severity level(s): {', '.join(sorted(invalid))}. "
            f"Allowed values: {', '.join(sorted(VALID_SEVERITIES))}"
        )
    return sevs


def evaluate_findings(
    findings: list[dict[str, Any]],
    fail_on: set[str],
    min_confidence: float,
) -> list[dict[str, Any]]:
    """Filter findings that breach the quality gate thresholds.

    A finding triggers the gate if its severity is in `fail_on` AND
    its confidence is >= `min_confidence`.
    """
    matching = []
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        try:
            conf = float(f.get("confidence", 0.0))
        except (ValueError, TypeError):
            conf = 0.0

        if sev in fail_on and conf >= min_confidence:
            matching.append(f)

    return matching


def print_report(
    total_count: int,
    matching: list[dict[str, Any]],
    fail_on: set[str],
    min_confidence: float,
) -> None:
    """Print a clean, structured security quality gate summary."""
    print("=" * 78)
    print("                 SENTINELAPI CI SECURITY QUALITY GATE")
    print("=" * 78)
    print(f"Policy: Fail on severities: {', '.join(sorted(fail_on))}")
    print(f"Policy: Minimum confidence: >= {min_confidence:.2f}")
    print(f"Total evaluated findings:   {total_count}")
    print(f"Policy-violating findings:  {len(matching)}")
    print("-" * 78)

    if matching:
        print(f"{'SEVERITY':<10} | {'CONF':<6} | {'CHECK':<16} | {'METHOD + PATH':<24} | {'TITLE'}")
        print("-" * 78)
        for f in matching:
            sev = str(f.get("severity", "UNKNOWN")).upper()
            conf = float(f.get("confidence", 0.0))
            chk = str(f.get("check", "-"))
            endpoint = f"{f.get('method', '')} {f.get('endpoint', '')}"
            title = str(f.get("title", ""))
            print(f"{sev:<10} | {conf:<6.2f} | {chk:<16} | {endpoint:<24} | {title}")
        print("=" * 78)
        print("❌ SECURITY GATE FAILED: Policy-violating vulnerabilities detected!")
        print("Remediation required before code can merge into production.")
        print("=" * 78)
    else:
        print("✅ SECURITY GATE PASSED: No policy-violating vulnerabilities detected.")
        print("All findings meet security compliance thresholds.")
        print("=" * 78)


def run_gate(
    findings_path: Path | str,
    fail_on: set[str],
    min_confidence: float,
) -> int:
    """Run gate logic and return exit code (0 = pass, 1 = fail)."""
    p = Path(findings_path)
    if not p.is_file():
        print(f"Error: Findings file not found: {p}", file=sys.stderr)
        return 1

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"Error: Failed to parse JSON findings file: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, list):
        print("Error: Findings file content must be a JSON array of finding objects.", file=sys.stderr)
        return 1

    matching = evaluate_findings(data, fail_on, min_confidence)
    print_report(len(data), matching, fail_on, min_confidence)
    return 1 if matching else 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="ci_gate.py",
        description="SentinelAPI Security Quality Gate for CI/CD Pipelines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/ci_gate.py --findings findings.json --fail-on CRITICAL,HIGH --min-confidence 0.7
  python scripts/ci_gate.py --findings findings.json --fail-on CRITICAL --min-confidence 0.8
        """,
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to exported scan findings JSON file (produced with --json-out)",
    )
    parser.add_argument(
        "--fail-on",
        default="CRITICAL,HIGH",
        help="Comma-separated severity levels that trigger gate failure (default: CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold [0.0 - 1.0] for breach detection (default: 0.7)",
    )

    args = parser.parse_args(argv)

    try:
        fail_severities = parse_severities(args.fail_on)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    if not (0.0 <= args.min_confidence <= 1.0):
        print("Error: --min-confidence must be between 0.0 and 1.0", file=sys.stderr)
        return 2

    return run_gate(args.findings, fail_severities, args.min_confidence)


if __name__ == "__main__":
    sys.exit(main())
