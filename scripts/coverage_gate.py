#!/usr/bin/env python3
"""Fail the build when production-contract coverage drops below a threshold.

Reads an LCOV file produced by `forge coverage --report lcov`, keeps only files under the
given source prefix, and enforces minimum line and branch coverage. Writes a Markdown table
to $GITHUB_STEP_SUMMARY when running in GitHub Actions.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass


@dataclass
class FileCoverage:
    path: str
    lines_found: int = 0
    lines_hit: int = 0
    branches_found: int = 0
    branches_hit: int = 0


def parse_lcov(path: str) -> list[FileCoverage]:
    files: list[FileCoverage] = []
    current: FileCoverage | None = None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith("SF:"):
                current = FileCoverage(path=line[3:])
            elif current is None:
                continue
            elif line.startswith("LF:"):
                current.lines_found = int(line[3:])
            elif line.startswith("LH:"):
                current.lines_hit = int(line[3:])
            elif line.startswith("BRF:"):
                current.branches_found = int(line[4:])
            elif line.startswith("BRH:"):
                current.branches_hit = int(line[4:])
            elif line == "end_of_record":
                files.append(current)
                current = None
    return files


def pct(hit: int, found: int) -> float:
    return 100.0 if found == 0 else 100.0 * hit / found


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lcov", help="Path to lcov.info")
    parser.add_argument("--source-prefix", default="src/", help="Only count files under this path")
    parser.add_argument("--min-lines", type=float, default=95.0)
    parser.add_argument("--min-branches", type=float, default=90.0)
    args = parser.parse_args()

    files = [f for f in parse_lcov(args.lcov) if f.path.startswith(args.source_prefix)]
    if not files:
        print(f"::error::No coverage data found for files under {args.source_prefix!r}")
        return 1

    lines_found = sum(f.lines_found for f in files)
    lines_hit = sum(f.lines_hit for f in files)
    branches_found = sum(f.branches_found for f in files)
    branches_hit = sum(f.branches_hit for f in files)
    line_pct = pct(lines_hit, lines_found)
    branch_pct = pct(branches_hit, branches_found)

    rows = [
        f"| `{f.path}` | {pct(f.lines_hit, f.lines_found):.2f}% ({f.lines_hit}/{f.lines_found}) "
        f"| {pct(f.branches_hit, f.branches_found):.2f}% ({f.branches_hit}/{f.branches_found}) |"
        for f in files
    ]
    passed = line_pct >= args.min_lines and branch_pct >= args.min_branches
    summary = "\n".join(
        [
            "### Coverage gate " + ("✅" if passed else "❌"),
            "",
            "| File | Lines | Branches |",
            "| --- | --- | --- |",
            *rows,
            f"| **Total** | **{line_pct:.2f}%** (min {args.min_lines}%) | **{branch_pct:.2f}%** (min {args.min_branches}%) |",
            "",
        ]
    )
    print(summary)
    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary + "\n")

    if not passed:
        print(
            f"::error title=Coverage gate::lines {line_pct:.2f}% (min {args.min_lines}%), "
            f"branches {branch_pct:.2f}% (min {args.min_branches}%)"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
