#!/usr/bin/env python3
"""Fail when the release version strings of the repository disagree.

The version in `[workspace.package]` of Cargo.toml is the source of truth. Between
releases it is the latest release, and the release PR (CONTRIBUTING "Releasing")
changes every place below at once:

- each crate's `version` is `version.workspace = true` (or the same string);
- the `openmoat-*` entries of `[workspace.dependencies]` require that version;
- Cargo.lock and fuzz/Cargo.lock record it for every `openmoat*` package;
- sdk/js/package.json, the JavaScript SDK, has it as its `version` (ADR-046);
- README.md and docs/ROADMAP.md say "The latest release is `<version>`";
- CHANGELOG.md starts with `## [Unreleased]`, then `## [<version>] - YYYY-MM-DD`,
  names each release once and repeats no `###` heading inside one section.

    python3 scripts/ci/check-versions.py
"""

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LATEST = re.compile(r"The latest release is `([^`]+)`")
RELEASE = re.compile(r"^## \[([^\]]+)\](?: - (\d{4}-\d{2}-\d{2}))?\s*$")


def toml(path):
    return tomllib.loads((ROOT / path).read_text(encoding="utf-8"))


def check_manifests(version, problems):
    workspace = toml("Cargo.toml")["workspace"]
    for member in workspace["members"]:
        package = toml(f"{member}/Cargo.toml")["package"]
        own = package.get("version")
        if own != {"workspace": True} and own != version:
            problems.append(f"{member}/Cargo.toml: version {own!r}, workspace is {version}")
    for name, spec in workspace["dependencies"].items():
        if name.startswith("openmoat") and spec.get("version") != version:
            problems.append(
                f"Cargo.toml: [workspace.dependencies] {name} requires "
                f"{spec.get('version')!r}, workspace is {version}"
            )


def check_lockfiles(version, problems):
    for lock in ("Cargo.lock", "fuzz/Cargo.lock"):
        for package in toml(lock)["package"]:
            name = package["name"]
            if name.startswith("openmoat") and name != "openmoat-fuzz":
                if package["version"] != version:
                    problems.append(f"{lock}: {name} {package['version']}, workspace is {version}")


def check_packages(version, problems):
    package = json.loads((ROOT / "sdk/js/package.json").read_text(encoding="utf-8"))
    if package.get("version") != version:
        problems.append(f"sdk/js/package.json: version {package.get('version')!r}, workspace is {version}")


def check_docs(version, problems):
    for doc in ("README.md", "docs/ROADMAP.md"):
        found = LATEST.findall((ROOT / doc).read_text(encoding="utf-8"))
        if not found:
            problems.append(f"{doc}: no 'The latest release is `…`' line")
        for stated in found:
            if stated != version:
                problems.append(f"{doc}: says the latest release is {stated}, workspace is {version}")


def check_changelog(version, problems):
    releases, subsections, current = [], set(), None
    for number, line in enumerate((ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines(), 1):
        release = RELEASE.match(line)
        if release:
            name, date = release.groups()
            if name in (r for r, _ in releases):
                problems.append(f"CHANGELOG.md:{number}: [{name}] appears twice")
            if name != "Unreleased" and not date:
                problems.append(f"CHANGELOG.md:{number}: [{name}] has no ' - YYYY-MM-DD' date")
            releases.append((name, number))
            subsections, current = set(), name
        elif line.startswith("### "):
            if line in subsections:
                problems.append(f"CHANGELOG.md:{number}: '{line}' repeats inside [{current}]")
            subsections.add(line)
    names = [name for name, _ in releases]
    if names[:1] != ["Unreleased"]:
        problems.append("CHANGELOG.md: the first section is not ## [Unreleased]")
    if names[1:2] != [version]:
        problems.append(f"CHANGELOG.md: the newest release section is not ## [{version}]")


def main():
    version = toml("Cargo.toml")["workspace"]["package"]["version"]
    problems = []
    check_manifests(version, problems)
    check_lockfiles(version, problems)
    check_packages(version, problems)
    check_docs(version, problems)
    check_changelog(version, problems)
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} version mismatch(es); see CONTRIBUTING 'Releasing'", file=sys.stderr)
        return 1
    print(f"release version strings agree on {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
