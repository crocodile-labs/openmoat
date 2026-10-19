#!/usr/bin/env python3
"""Rebuild the bundled lists of popular package names (ADR-030).

The near-miss check (`package-near-miss`) compares an installed name with the
lists in crates/openmoat-core/data/top-packages/. OpenMoat never downloads them
at run time; a maintainer runs this script now and then, reviews the diff and
commits it with a CHANGELOG line.

    python3 scripts/refresh-top-packages.py [--limit N] [ECOSYSTEM ...]

Sources (public, no account needed):
  pypi      hugovk's top-pypi-packages dump of the last 30 days of downloads
  crates    the crates.io API, sorted by all-time downloads
  npm       api.npmjs.org last-month download counts for the names already on
            the list plus any in --candidates FILE (npm has no ranking API)
  rubygems  rubygems.org download counts, likewise for the listed names and
            the candidates
  go        no download counts exist; the file is kept as it is

Only the standard library is used. Each list keeps at most --limit names
(default 1000), most-downloaded first, under a header saying where and when
it came from.
"""

import argparse
import datetime
import json
import pathlib
import sys
import time
import urllib.parse
import urllib.request

DATA = pathlib.Path(__file__).resolve().parent.parent / "crates/openmoat-core/data/top-packages"
AGENT = "openmoat-refresh-top-packages (+https://github.com/crocodile-labs/openmoat)"

HEADER = """\
# Popular {what}, most-{how} first, one per line (ADR-030).
#
# Source: {source}, fetched on {date} by scripts/refresh-top-packages.py.
# A name is "popular" here only for the near-miss check: an install of a name
# that is not on this list but is one typo or a common trick away from one
# that is asks (`package-near-miss`).
"""


def get_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def listed(ecosystem):
    path = DATA / f"{ecosystem}.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def pypi(limit, _candidates):
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    rows = get_json(url)["rows"]
    names = [row["project"] for row in rows][:limit]
    return names, "hugovk/top-pypi-packages (PyPI downloads, last 30 days)"


def crates(limit, _candidates):
    names = []
    page = 1
    while len(names) < limit:
        url = f"https://crates.io/api/v1/crates?sort=downloads&per_page=100&page={page}"
        batch = get_json(url)["crates"]
        if not batch:
            break
        names += [c["id"] for c in batch]
        page += 1
        time.sleep(1)  # crates.io asks for at most one request a second
    return names[:limit], "the crates.io API (all-time downloads)"


def npm(limit, candidates):
    names = dict.fromkeys(listed("npm") + candidates)
    counts = {}
    unscoped = [n for n in names if not n.startswith("@")]
    for i in range(0, len(unscoped), 128):
        chunk = ",".join(unscoped[i : i + 128])
        result = get_json(f"https://api.npmjs.org/downloads/point/last-month/{chunk}")
        for name, entry in result.items():
            if entry:
                counts[name] = entry["downloads"]
    for name in (n for n in names if n.startswith("@")):
        quoted = urllib.parse.quote(name, safe="@")
        entry = get_json(f"https://api.npmjs.org/downloads/point/last-month/{quoted}")
        counts[name] = entry.get("downloads", 0)
    ranked = sorted(counts, key=counts.get, reverse=True)
    return ranked[:limit], "api.npmjs.org (downloads, last month) of the listed and candidate names"


def rubygems(limit, candidates):
    counts = {}
    for name in dict.fromkeys(listed("rubygems") + candidates):
        try:
            counts[name] = get_json(f"https://rubygems.org/api/v1/gems/{name}.json")["downloads"]
        except OSError:
            print(f"rubygems: {name} not found, dropped", file=sys.stderr)
        time.sleep(0.2)
    ranked = sorted(counts, key=counts.get, reverse=True)
    return ranked[:limit], "rubygems.org (all-time downloads) of the listed and candidate names"


SOURCES = {
    "npm": (npm, "npm package names", "downloaded"),
    "pypi": (pypi, "PyPI project names", "downloaded"),
    "crates": (crates, "crates.io crate names", "downloaded"),
    "rubygems": (rubygems, "RubyGems gem names", "downloaded"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ecosystems", nargs="*", default=sorted(SOURCES))
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--candidates", type=pathlib.Path, help="more names to rank, one per line")
    args = parser.parse_args()
    candidates = []
    if args.candidates:
        candidates = [line.strip() for line in args.candidates.read_text().splitlines() if line.strip()]
    today = datetime.date.today().isoformat()
    for ecosystem in args.ecosystems:
        if ecosystem == "go":
            print("go: no download counts exist; go.txt is kept as it is", file=sys.stderr)
            continue
        fetch, what, how = SOURCES[ecosystem]
        names, source = fetch(min(args.limit, 2000), candidates)
        if len(names) < 100:
            sys.exit(f"{ecosystem}: only {len(names)} names fetched; the file is kept")
        text = HEADER.format(what=what, how=how, source=source, date=today)
        (DATA / f"{ecosystem}.txt").write_text(text + "\n".join(names) + "\n", encoding="utf-8")
        print(f"{ecosystem}: {len(names)} names", file=sys.stderr)


if __name__ == "__main__":
    main()
