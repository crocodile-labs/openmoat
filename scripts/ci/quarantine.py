#!/usr/bin/env python3
"""The quarantined tests of .config/nextest-quarantine.md as a nextest filter.

Usage: quarantine.py [--file <table>] [--today YYYY-MM-DD] (exclude | only)

`exclude` prints the filter of the tests to run: `not (<quarantined>)`, or
`all()` when the table is empty. `only` prints the filter of the quarantined
tests, or nothing when there are none (the weekly job then has nothing to run).
scripts/ci/quality-gate.sh passes the first to `cargo nextest run -E`.

The table is read strictly; the script fails (exit 1) on:
- a row that is not six cells, or has an empty binary id, test, signature,
  owner or issue, or a `first red` that is not a date;
- a test of the sandbox, a deny or a bypass (`SECURITY`): those are never
  retried (`.config/nextest.toml`) and never quarantined.
A row whose `first red` is more than 14 days before today warns (a GitHub
annotation on stderr): the rule is to fix or delete within 14 days.
"""

import argparse
import datetime
import re
import sys
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parents[2] / ".config" / "nextest-quarantine.md"
MAX_DAYS = 14

# The tests `profile.ci` never retries (.config/nextest.toml, the first
# override): whole binaries, and test-name prefixes within one binary.
# tests in test_ci_gates.py hold this list and that filter together.
SECURITY_BINARIES = ("openmoat-core::conformance", "openmoat-core::ir_never_widens")
SECURITY_PREFIXES = {
    "openmoat::bin/openmoat": ("sandbox::", "commands::run::"),
    "openmoat::e2e": ("sandbox::", "sandbox_exec::", "cursor_sandbox::", "run::", "run_guard::",
                      "differential::", "escapes::", "relay_token::", "hook_only::launch::",
                      "guard::", "blocks::", "secret::", "lock::", "injected::"),
}

ROW = re.compile(r"^\|(.*)\|\s*$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# What a binary id or a test name may hold: no filterset syntax.
NAME = re.compile(r"^[A-Za-z0-9_:/.\-]+$")


class Problem(Exception):
    pass


def rows(text):
    """[(binary id, test, signature, first red, owner, issue)] of the table."""
    found = []
    header_seen = False
    for n, line in enumerate(text.splitlines(), 1):
        m = ROW.match(line.strip())
        if not m:
            continue
        cells = [c.strip().strip("`") for c in m.group(1).split("|")]
        if not header_seen:
            header_seen = True  # the header row
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue  # the separator row
        if len(cells) != 6:
            raise Problem(f"line {n}: {len(cells)} cells, not 6")
        binary, test, signature, first_red, owner, issue = cells
        for what, value in (("binary id", binary), ("test", test), ("failure signature", signature),
                            ("owner", owner), ("issue", issue)):
            if not value:
                raise Problem(f"line {n}: no {what}")
        for what, value in (("binary id", binary), ("test", test)):
            if not NAME.match(value):
                raise Problem(f"line {n}: the {what} `{value}` is not a plain name")
        if not DATE.match(first_red):
            raise Problem(f"line {n}: first red `{first_red}` is not YYYY-MM-DD")
        found.append((binary, test, signature, first_red, owner, issue))
    return found


def is_security(binary, test):
    if binary in SECURITY_BINARIES:
        return True
    return any(test.startswith(p) for p in SECURITY_PREFIXES.get(binary, ()))


def check(found, today):
    """The warnings for `found`; raises Problem on a security test."""
    warnings = []
    for binary, test, _sig, first_red, _owner, issue in found:
        if is_security(binary, test):
            raise Problem(f"{binary} {test}: a sandbox, deny or bypass test is never quarantined")
        days = (today - datetime.date.fromisoformat(first_red)).days
        if days > MAX_DAYS:
            warnings.append(f"{binary} {test} has been quarantined {days} days (over {MAX_DAYS}); "
                            f"fix or delete it ({issue})")
    return warnings


def held(found):
    """The nextest filter of the quarantined tests; empty when none."""
    return " | ".join(f"(binary_id(={b}) & test(={t}))" for b, t, *_ in found)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE)
    parser.add_argument("--today", type=datetime.date.fromisoformat, default=datetime.date.today())
    parser.add_argument("mode", choices=("exclude", "only"))
    args = parser.parse_args(argv)
    try:
        found = rows(args.file.read_text(encoding="utf-8"))
        warnings = check(found, args.today)
    except (OSError, ValueError, Problem) as e:
        print(f"::error title=quarantine::{args.file.name}: {e}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"::warning title=quarantine::{warning}", file=sys.stderr)
    expr = held(found)
    if args.mode == "exclude":
        print(f"not ({expr})" if expr else "all()")
    elif expr:
        print(expr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
