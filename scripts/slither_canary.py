#!/usr/bin/env python3
"""Assert that Slither detected every planted bug in the canary contract.

Usage: slither_canary.py <slither.json> --expect reentrancy-eth --expect tx-origin ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="Slither --json output")
    parser.add_argument("--expect", action="append", required=True, metavar="DETECTOR")
    args = parser.parse_args()

    with open(args.report, encoding="utf-8") as handle:
        report = json.load(handle)

    if not report.get("success", False):
        print(f"::error title=Slither canary::Slither failed: {report.get('error')}")
        return 1

    detected = {result["check"] for result in report.get("results", {}).get("detectors", [])}
    missing = [detector for detector in args.expect if detector not in detected]

    lines = ["### Slither scanner canary " + ("❌" if missing else "✅"), "", "| Expected detector | Fired |", "| --- | --- |"]
    lines += [f"| `{d}` | {'no' if d in missing else 'yes'} |" for d in args.expect]
    summary = "\n".join(lines) + "\n"
    print(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(summary)

    if missing:
        print(f"::error title=Slither canary::Detectors did not fire on known-vulnerable code: {', '.join(missing)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
