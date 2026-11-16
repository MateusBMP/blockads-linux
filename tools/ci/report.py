#!/usr/bin/env python3
"""Turn test output into GitHub Actions feedback: annotations + job summary.

    report.py junit RESULTS.xml --title "Unit tests (3.12)"
    report.py lines LOG... --title "netns: fw_helper" [--no-skip]

``junit``  reads a pytest JUnit XML file (``-o junit_family=xunit1`` adds the
           file and line of each test).
``lines``  reads logs of the shell suites (tests/netns, tests/vm), whose
           result lines start with PASS / FAIL / SKIP / INFO, plus pytest's
           "N passed, M failed" lines and the VM runners' "exit=N" lines.

For every failure it prints an ``::error`` workflow command (shown on the run
page and on the PR), appends a Markdown section to ``$GITHUB_STEP_SUMMARY``
(or stdout outside Actions), and exits 1. A log with no result at all also
fails (for example a VM that never booted). ``--no-skip`` turns SKIP lines
into failures (the VMs must exercise every backend).

Stdlib only.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RESULT_RE = re.compile(r"^(PASS|FAIL|SKIP|INFO)\s+(.*?)\s{2,}(.*)$|^(PASS|FAIL|SKIP|INFO)\s+(.*)$")
PYTEST_RE = re.compile(r"\b(\d+) (passed|failed|errors?|skipped)\b")
EXIT_RE = re.compile(r"^exit=(\d+)\s*$")
MAX_ANNOTATIONS = 40


def escape(text: str) -> str:
    """Escape a workflow-command message (``%``, CR, LF)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_prop(text: str) -> str:
    return escape(text).replace(":", "%3A").replace(",", "%2C")


def annotate(level: str, title: str, message: str, file: str | None = None, line: int | None = None) -> None:
    props = [f"title={escape_prop(title)}"]
    if file:
        props.insert(0, f"file={escape_prop(file)}")
        if line:
            props.insert(1, f"line={line}")
    print(f"::{level} {','.join(props)}::{escape(message)}")


def md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()[:300]


def write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")


# --- junit -------------------------------------------------------------------

def cmd_junit(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        annotate("error", args.title, f"no test results ({path} missing): the run crashed before pytest finished")
        write_summary(f"### ❌ {args.title}\n\nNo results file: the job failed before pytest finished.\n")
        return 1
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        annotate("error", args.title, f"unreadable test results {path}: {exc}")
        write_summary(f"### ❌ {args.title}\n\nUnreadable results file: {exc}\n")
        return 1
    cases = root.iter("testcase")
    total = failed = skipped = 0
    failures: list[tuple[str, str, int | None, str]] = []
    for case in cases:
        total += 1
        name = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        if problem is not None:
            failed += 1
            message = (problem.get("message") or "").strip()
            detail = (problem.text or "").strip()
            failures.append((name, case.get("file") or "", int(case.get("line") or 0) + 1 if case.get("line") else None,
                             message or detail.splitlines()[-1] if (message or detail) else "failed"))
        elif case.find("skipped") is not None:
            skipped += 1
    passed = total - failed - skipped
    for name, file, line, message in failures[:MAX_ANNOTATIONS]:
        annotate("error", f"{args.title}: {name}", message, file or None, line)
    icon = "❌" if failed or not total else "✅"
    out = [f"### {icon} {args.title}", "", f"**{passed} passed**, {failed} failed, {skipped} skipped ({total} total)", ""]
    if failures:
        out += ["| Test | Error |", "|---|---|"]
        out += [f"| `{md(name)}` | {md(message)} |" for name, _, _, message in failures]
        out.append("")
    write_summary("\n".join(out))
    return 1 if failed or not total else 0


# --- PASS/FAIL logs ------------------------------------------------------------

def parse_log(path: Path) -> dict:
    result = {"pass": 0, "fail": [], "skip": [], "pytest_failed": 0, "pytest_passed": 0, "exits": [], "lines": 0}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result["fail"].append((path.name, f"cannot read log: {exc}"))
        return result
    for raw in text.splitlines():
        line = raw.rstrip()
        match = RESULT_RE.match(line)
        if match:
            status = match.group(1) or match.group(4)
            name = (match.group(2) or match.group(5) or "").strip()
            detail = (match.group(3) or "").strip()
            result["lines"] += 1
            if status == "PASS":
                result["pass"] += 1
            elif status == "FAIL":
                result["fail"].append((name, detail))
            elif status == "SKIP":
                result["skip"].append((name, detail))
            continue
        if re.search(r"\bin [\d.]+s\b", line):
            counts = {kind: int(n) for n, kind in PYTEST_RE.findall(line)}
            if counts:
                result["lines"] += 1
                result["pytest_passed"] += counts.get("passed", 0)
                result["pytest_failed"] += counts.get("failed", 0) + counts.get("error", 0) + counts.get("errors", 0)
                if result["pytest_failed"]:
                    result["fail"].append(("pytest", line.strip(" =")))
        exit_match = EXIT_RE.match(line)
        if exit_match:
            result["exits"].append(int(exit_match.group(1)))
    for code in result["exits"]:
        if code:
            result["fail"].append(("exit status", f"exit={code}"))
    return result


def cmd_lines(args: argparse.Namespace) -> int:
    bad = False
    out = []
    for name in args.logs:
        path = Path(name)
        res = parse_log(path)
        label = f"{args.title}: {path.name}" if len(args.logs) > 1 else args.title
        problems = list(res["fail"])
        if args.no_skip:
            problems += [(n, f"skipped: {d}") for n, d in res["skip"]]
        if res["lines"] == 0:
            problems.append(("no results", "the log has no PASS/FAIL lines (did the suite or VM start?)"))
        for test, detail in problems[:MAX_ANNOTATIONS]:
            annotate("error", label, f"{test}: {detail}" if detail else test)
        if not args.no_skip:
            for test, detail in res["skip"][:10]:
                annotate("warning", label, f"skipped: {test}: {detail}")
        bad = bad or bool(problems)
        icon = "❌" if problems else "✅"
        out += [f"### {icon} {label}", "",
                f"**{res['pass']} passed**, {len(res['fail'])} failed, {len(res['skip'])} skipped"
                + (f"; pytest {res['pytest_passed']} passed, {res['pytest_failed']} failed"
                   if res["pytest_passed"] or res["pytest_failed"] else ""), ""]
        if problems:
            out += ["| Check | Detail |", "|---|---|"]
            out += [f"| {md(test)} | {md(detail)} |" for test, detail in problems]
            out.append("")
        if res["skip"] and not args.no_skip:
            out += ["<details><summary>Skipped</summary>", ""]
            out += [f"- {md(test)}: {md(detail)}" for test, detail in res["skip"]]
            out += ["", "</details>", ""]
    write_summary("\n".join(out))
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    junit = sub.add_parser("junit")
    junit.add_argument("file")
    junit.add_argument("--title", required=True)
    lines = sub.add_parser("lines")
    lines.add_argument("logs", nargs="+")
    lines.add_argument("--title", required=True)
    lines.add_argument("--no-skip", action="store_true")
    args = parser.parse_args(argv)
    return cmd_junit(args) if args.command == "junit" else cmd_lines(args)


if __name__ == "__main__":
    sys.exit(main())
