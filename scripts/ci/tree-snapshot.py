#!/usr/bin/env python3
"""Record every file and directory under a root, and later prove the tree is the
same again: each file byte for byte (sha256 and mode), nothing added, nothing
removed. Symbolic links are recorded by their target and never followed.

    tree-snapshot.py save <root> <snapshot.json> [--exclude <relative path>]...
    tree-snapshot.py compare <root> <snapshot.json> [--exclude <relative path>]...

An excluded path is left out with everything below it, on both sides (the
clean-install check excludes OpenMoat's state directory from the snapshot it
takes after OpenMoat has run, and `uninstall --purge` must then have deleted
it). `compare` prints each difference and exits 1 when there is one.
"""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path


def entries(root, excluded):
    found = {}
    for current, dirs, files in os.walk(root):
        here = Path(current)
        rel_dir = here.relative_to(root).as_posix()
        kept = []
        for name in sorted(dirs):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if rel in excluded:
                continue
            path = here / name
            if path.is_symlink():
                found[rel] = {"link": os.readlink(path)}
            else:
                found[rel] = {"dir": True, "mode": stat.S_IMODE(path.lstat().st_mode)}
                kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if rel in excluded:
                continue
            path = here / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                found[rel] = {"link": os.readlink(path)}
                continue
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1 << 16), b""):
                    digest.update(block)
            found[rel] = {"sha256": digest.hexdigest(), "mode": stat.S_IMODE(info.st_mode)}
    return found


def parse(argv):
    if len(argv) < 3 or argv[0] not in ("save", "compare"):
        print(__doc__, file=sys.stderr)
        sys.exit(64)
    action, root, snapshot, rest = argv[0], Path(argv[1]), Path(argv[2]), argv[3:]
    excluded = set()
    while rest:
        if rest[0] != "--exclude" or len(rest) < 2:
            print(f"tree-snapshot: unexpected argument {rest[0]!r}", file=sys.stderr)
            sys.exit(64)
        excluded.add(rest[1].strip("/"))
        rest = rest[2:]
    return action, root, snapshot, excluded


def main(argv):
    action, root, snapshot, excluded = parse(argv)
    if not root.is_dir():
        print(f"tree-snapshot: {root} is not a directory", file=sys.stderr)
        return 64
    now = entries(root, excluded)
    if action == "save":
        snapshot.write_text(json.dumps(now, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"tree-snapshot: {len(now)} entries under {root} saved to {snapshot}")
        return 0
    before = {k: v for k, v in json.loads(snapshot.read_text(encoding="utf-8")).items()
              if not any(k == e or k.startswith(e + "/") for e in excluded)}
    problems = []
    for rel in sorted(before.keys() | now.keys()):
        if rel not in now:
            problems.append(f"removed  {rel}")
        elif rel not in before:
            problems.append(f"added    {rel}")
        elif before[rel] != now[rel]:
            problems.append(f"changed  {rel}: {before[rel]} -> {now[rel]}")
    for line in problems:
        print(f"tree-snapshot: {line}")
    if problems:
        print(f"tree-snapshot: {len(problems)} difference(s) under {root}", file=sys.stderr)
        return 1
    print(f"tree-snapshot: {len(now)} entries under {root} are as they were")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
