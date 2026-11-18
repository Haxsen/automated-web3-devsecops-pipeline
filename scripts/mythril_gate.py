#!/usr/bin/env python3
"""Turn a Mythril JSON report (`myth analyze -o json`) into a pass/fail decision.

Mythril's exit code is not a reliable gate: it exits 0 both when the analysis is clean and when it
crashes (for example, if it cannot download a compiler), and 1 whenever it reports issues of any
severity. This script reads the report instead:

  gate mode    fail if the analysis did not succeed, or found an issue at or above --fail-on.
  canary mode  (--expect-swc) fail unless every expected SWC weakness was detected. Used against
               the intentionally vulnerable contract to prove the analyser actually works.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def write_summary(text: str) -> None:
    print(text)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", help="Mythril JSON report")
    parser.add_argument("--label", default="Mythril", help="Heading used in the job summary")
    parser.add_argument("--fail-on", choices=sorted(SEVERITY_RANK), default="medium")
    parser.add_argument("--expect-swc", action="append", default=[], metavar="ID", help="Canary mode: SWC id that must be found (repeatable)")
    args = parser.parse_args()

    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error title={args.label}::Could not read Mythril report: {exc}")
        return 1

    if not report.get("success", False):
        error = str(report.get("error") or "unknown error").strip().splitlines()
        print(f"::error title={args.label}::Mythril analysis did not complete: {error[-1] if error else 'unknown'}")
        return 1

    issues = report.get("issues", [])
    lines = [f"### {args.label}", ""]
    if issues:
        lines += ["| SWC | Severity | Title | Function | Location |", "| --- | --- | --- | --- | --- |"]
        for issue in sorted(issues, key=lambda i: -SEVERITY_RANK.get(str(i.get("severity", "")).lower(), 0)):
            location = f"{issue.get('filename', '?')}:{issue.get('lineno', '?')}"
            lines.append(
                f"| SWC-{issue.get('swc-id', '?')} | {issue.get('severity', '?')} | {issue.get('title', '?')} "
                f"| `{issue.get('function', '?')}` | `{location}` |"
            )
    else:
        lines.append("No issues found.")

    if args.expect_swc:
        found = {str(issue.get("swc-id")) for issue in issues}
        missing = [swc for swc in args.expect_swc if swc not in found]
        lines += ["", f"Canary expectations: {', '.join('SWC-' + s for s in args.expect_swc)}"]
        write_summary("\n".join(lines) + "\n")
        if missing:
            print(f"::error title={args.label} canary::Mythril missed planted weaknesses: {', '.join('SWC-' + s for s in missing)}")
            return 1
        print(f"Canary passed: Mythril detected {', '.join('SWC-' + s for s in args.expect_swc)}.")
        return 0

    threshold = SEVERITY_RANK[args.fail_on]
    blocking = [i for i in issues if SEVERITY_RANK.get(str(i.get("severity", "")).lower(), 0) >= threshold]
    write_summary("\n".join(lines) + "\n")
    if blocking:
        print(f"::error title={args.label}::{len(blocking)} issue(s) at or above '{args.fail_on}' severity")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
