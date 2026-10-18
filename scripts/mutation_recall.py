#!/usr/bin/env python3
"""Mutation recall: delete one assertion at a time from correct circuits.

For every function that calls a hint (`unsafe { ... }`) and has no finding on
the unmodified package, each assertion line inside it is deleted in turn and
noirspect is run on the mutant. A mutant counts as detected when a new
finding (other than NUC-008) lands inside the mutated function.

Not every deletion makes a circuit under-constrained (some assertions are
redundant or only check outputs), so undetected mutants are listed for manual
triage: confirm each with a test or a solver before counting it as a miss.

Usage:
    scripts/mutation_recall.py [--noirspect PATH] PACKAGE_DIR...
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

FN_RE = re.compile(r"^\s*(pub(\(crate\))?\s+)?(unconstrained\s+)?fn\s+(\w+)")
ASSERT_RE = re.compile(r"^\s*(assert(_eq)?\(|[\w\[\]\.]+\.assert_max_bit_size)")


@dataclass
class Function:
    file: str
    name: str
    start: int  # 1-based, inclusive
    end: int  # 1-based, exclusive
    unconstrained: bool


def functions(file: str, lines: list[str]) -> list[Function]:
    found: list[Function] = []
    for i, line in enumerate(lines, start=1):
        match = FN_RE.match(line)
        if not match:
            continue
        if found:
            found[-1].end = i
        found.append(Function(file, match.group(4), i, len(lines) + 1, bool(match.group(3))))
    return found


def run(noirspect: str, package: Path) -> list[dict]:
    result = subprocess.run(
        [noirspect, "lint", "--program-dir", str(package), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.strip() or f"noirspect exited {result.returncode}")
    return json.loads(result.stdout)["findings"]


def in_function(finding: dict, func: Function) -> bool:
    return (
        finding["rule_id"] != "NUC-008"
        and finding["file"] == func.file
        and func.start <= finding["line"] < func.end
    )


def evaluate(noirspect: str, package: Path) -> tuple[int, int, list[str]]:
    sources = {
        str(path.relative_to(package)): path.read_text().splitlines()
        for path in sorted((package / "src").rglob("*.nr"))
    }
    baseline = run(noirspect, package)
    detected = total = 0
    missed: list[str] = []
    for file, lines in sources.items():
        for func in functions(file, lines):
            body = lines[func.start - 1 : func.end - 1]
            if func.unconstrained or not any("unsafe {" in line for line in body):
                continue
            if any(in_function(f, func) for f in baseline):
                continue  # already flagged: not a correct circuit
            for line_no in range(func.start, func.end):
                if not ASSERT_RE.match(lines[line_no - 1]):
                    continue
                total += 1
                with tempfile.TemporaryDirectory() as tmp:
                    mutant = Path(tmp) / package.name
                    shutil.copytree(package, mutant, ignore=shutil.ignore_patterns("target"))
                    mutated = list(lines)
                    mutated[line_no - 1] = "// mutant: assertion deleted"
                    (mutant / file).write_text("\n".join(mutated) + "\n")
                    try:
                        findings = run(noirspect, mutant)
                    except RuntimeError as exc:
                        total -= 1  # the mutant no longer compiles
                        print(f"  skip {file}:{line_no} ({exc.args[0].splitlines()[0]})", file=sys.stderr)
                        continue
                if any(in_function(f, func) for f in findings):
                    detected += 1
                else:
                    missed.append(f"{package.name}/{file}:{line_no} in {func.name}: {lines[line_no - 1].strip()}")
    return detected, total, missed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--noirspect", default="target/release/noirspect")
    parser.add_argument("packages", nargs="+", type=Path)
    args = parser.parse_args()

    all_detected = all_total = 0
    all_missed: list[str] = []
    for package in args.packages:
        detected, total, missed = evaluate(args.noirspect, package.resolve())
        print(f"{package.name}: {detected}/{total} mutants flagged")
        all_detected += detected
        all_total += total
        all_missed += missed
    share = 100 * all_detected / all_total if all_total else 0
    print(f"\ntotal: {all_detected}/{all_total} mutants flagged ({share:.0f}%)")
    if all_missed:
        print("\nnot flagged (triage: confirm with a test or a solver whether each is under-constrained):")
        for line in all_missed:
            print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
