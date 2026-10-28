#!/usr/bin/env python3
"""Fail on a relative Markdown link whose file or heading anchor does not exist.

Markdown links and images, reference definitions, and the `href`, `src` and
`srcset` of HTML tags (the README's banner and badges) are all checked.

Offline on purpose: links with a scheme (https:, mailto:) are not fetched, so a
remote site being down never fails a pull request. Checks every tracked `*.md`
file.

    python3 scripts/ci/check-links.py
    python3 scripts/ci/check-links.py --online README.md

`--online` checks the named files only, and also fetches every http(s) link and
image in them (the clean-install workflow, weekly, for the README a new user
reads). A link fails when it does not connect, or answers 404, 410 or a server
error after retries. A site that answers 401, 403 or 429 exists but refuses
automated requests (a forum, a badge service under load): it is listed as a
warning, not a failure, since a person's browser gets the page.
"""

import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"")
HTML_ATTRS = re.compile(r"\s(href|src|srcset)=\"([^\"]*)\"")
HTML_TAG = re.compile(r"<[a-zA-Z][^>]*>")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
FENCE = re.compile(r"^\s{0,3}(```|~~~)")
CODE_SPAN = re.compile(r"(`+).*?\1")


def prose_lines(text):
    """Yield (line number, line) for each line outside fenced code blocks."""
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if match:
            if fence is None:
                fence = match.group(1)
            elif match.group(1) == fence:
                fence = None
            continue
        if fence is None:
            yield number, line


def slug(heading):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


ANCHORS = {}


def anchors(path):
    """Every anchor a link into `path` may name."""
    if path not in ANCHORS:
        found, seen = set(), {}
        for _, line in prose_lines(path.read_text(encoding="utf-8")):
            found.update(HTML_ANCHOR.findall(line))
            match = HEADING.match(line)
            if match:
                base = slug(match.group(2))
                count = seen.get(base, 0)
                seen[base] = count + 1
                found.add(base if count == 0 else f"{base}-{count}")
        ANCHORS[path] = found
    return ANCHORS[path]


def broken(source, target):
    if SCHEME.match(target) or target.startswith("//"):
        return None
    file_part, _, anchor = target.partition("#")
    if file_part.startswith("/"):
        resolved = ROOT / file_part.lstrip("/")
    else:
        resolved = (source.parent / file_part) if file_part else source
    if not resolved.exists():
        return "no such file"
    if anchor and resolved.is_file() and resolved.suffix == ".md":
        if anchor.lower() not in anchors(resolved):
            return f"no heading #{anchor}"
    return None


def html_targets(line):
    """The href, src and each srcset candidate of every HTML tag on the line."""
    found = []
    for tag in HTML_TAG.findall(line):
        for attribute, value in HTML_ATTRS.findall(tag):
            if attribute == "srcset":
                found.extend(part.split()[0] for part in value.split(",") if part.split())
            elif value:
                found.append(value)
    return found


def targets_of(source):
    """(line number, target) for every link and image in one Markdown file."""
    for number, line in prose_lines(source.read_text(encoding="utf-8")):
        line = CODE_SPAN.sub("", line)
        targets = INLINE.findall(line) + html_targets(line)
        reference = REFERENCE.match(line)
        if reference:
            targets.append(reference.group(1))
        for target in targets:
            yield number, target


def probe(url):
    """The URL that shows whether `url` exists, for pages that answer an
    automated request 404 whatever the truth: a crate page (crates.io serves
    its HTML to browsers only) is its API record, a GitHub repository's
    stargazers page (sign-in only) is the repository's API record."""
    crate = re.fullmatch(r"https://crates\.io/crates/([A-Za-z0-9_-]+)/?", url)
    if crate:
        return f"https://crates.io/api/v1/crates/{crate.group(1)}"
    stars = re.fullmatch(r"https://github\.com/([\w.-]+)/([\w.-]+)/stargazers/?", url)
    if stars:
        return f"https://api.github.com/repos/{stars.group(1)}/{stars.group(2)}"
    return url


def fetch(url, attempts=3):
    """The HTTP status `url` finally answers with, or the error that stopped it."""
    url = probe(url)
    last = None
    for attempt in range(attempts):
        for method in ("HEAD", "GET"):
            request = urllib.request.Request(
                url, method=method, headers={"User-Agent": "openmoat-link-check"}
            )
            try:
                with urllib.request.urlopen(request, timeout=20) as answer:  # noqa: S310 (http and https only)
                    return answer.status, None
            except urllib.error.HTTPError as error:
                last = (error.code, None)
                # Some servers refuse HEAD; GET is tried before the answer counts.
                if method == "HEAD":
                    continue
                if error.code < 500 and error.code != 429:
                    return last
            except (urllib.error.URLError, OSError) as error:
                last = (None, str(getattr(error, "reason", error)))
        time.sleep(2 * (attempt + 1))
    return last


def online(names):
    """Fetch every http(s) target of the named files; relative ones as offline."""
    failures, warnings = 0, 0
    seen = {}
    for name in names:
        source = (ROOT / name).resolve()
        for number, target in targets_of(source):
            if not target.startswith(("http://", "https://")):
                reason = broken(source, target)
            else:
                url = target.partition("#")[0]
                if url not in seen:
                    seen[url] = fetch(url)
                status, error = seen[url]
                if error is not None:
                    reason = f"does not connect: {error}"
                elif status in (401, 403, 429):
                    warnings += 1
                    print(f"{name}:{number}: {target}: answered {status} to an automated request (warning)")
                    continue
                elif status >= 400:
                    reason = f"answered {status}"
                else:
                    reason = None
            if reason:
                failures += 1
                print(f"{name}:{number}: {target}: {reason}")
    if failures:
        print(f"{failures} broken link(s), {warnings} warning(s)", file=sys.stderr)
        return 1
    print(f"links ok in {', '.join(names)}: {len(seen)} remote, {warnings} warning(s)")
    return 0


def main(argv):
    if argv and argv[0] == "--online":
        if len(argv) < 2:
            print("usage: check-links.py [--online <file.md>...]", file=sys.stderr)
            return 64
        return online(argv[1:])
    listed = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.split()
    failures = 0
    for name in listed:
        source = ROOT / name
        for number, target in targets_of(source):
            reason = broken(source, target)
            if reason:
                failures += 1
                print(f"{name}:{number}: {target}: {reason}")
    if failures:
        print(f"{failures} broken relative link(s)", file=sys.stderr)
        return 1
    print(f"links ok in {len(listed)} Markdown files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
