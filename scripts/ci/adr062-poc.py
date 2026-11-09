#!/usr/bin/env python3
"""ADR-062 step 0: request rules on `openmoat run`'s terminating proxy, measured.

Usage: adr062-poc.py <openmoat binary> [runs]

Installs OpenMoat into a throwaway HOME (latency_ab.Guard) under $RUNNER_TEMP or
this checkout's `target/`, never the temp directory `openmoat run` grants
(home_parent), makes the proxy CA
there with the temporary `OPENMOAT_ADR062_POC=1` setting (a person's command,
so it is answered on a pseudo-terminal), and then, under `openmoat run` with
the setting on, has each client send

  (a) an allowed `GET https://api.github.com/rate_limit` (not counted against
      the unauthenticated rate limit), and
  (b) the denied `POST https://api.github.com/gists`, a dummy body and no
      credentials, in the spellings curl can send.

It records for each client whether (a) succeeded, whether (b) got OpenMoat's
refusal (its body names `proxy-request-rule`; a GitHub 401 or 422 would mean
the request reached GitHub), whether each refusal left an audit row, and that
no `POST` was recorded as passed. `git ls-remote` reaches github.com, which
has no rule: its tunnel is relayed as before. No token or secret is sent, and
no gist can be made: an unauthenticated POST would be refused by GitHub too,
and the point is that it never gets there.

Latency: `runs` curl GETs of the same URL directly, through `openmoat run`
with the setting off (an opaque tunnel), and with it on (terminated), in
three rotating batches; the added cost is terminated minus tunnel, median and
p95, against the 15 ms guard budget (latency_ab.BUDGET_MS). Latency over the
budget is a warning (shared runners and the network are noisy); a denied
request that was not refused, or a refusal with no audit row, fails the run.
"""

import os
import pty
import re
import shlex
import shutil
import sqlite3
import statistics
import subprocess
import sys
import time

import latency_ab

SETTING = {"OPENMOAT_ADR062_POC": "1"}
API = "https://api.github.com"
GET_URL = f"{API}/rate_limit"
MARKER = "proxy-request-rule"
BODY = '{"public":false,"files":{"poc.txt":{"content":"adr-062 step 0"}}}'
# The denied request as curl sends it, in the variants the rule must catch.
CURL_POSTS = [("POST", "/gists"), ("POST", "/gists/"), ("POST", "/GISTS"),
              ("POST", "/gists?per_page=1"), ("POST", "/gists/0/comments"), ("post", "/gists")]
BATCHES = 3
# The cells after each row's name, as an annotation names them.
CLIENT_COLUMNS = ("(a) allowed GET", "terminated", "(b) denied POST", "audit rows")
LATENCY_COLUMNS = ("median ms", "p95 ms")

NODE = f"""
const show = (what, r, body) => console.log(what, r.status, body.replace(/\\s+/g, " "));
(async () => {{
  try {{ const r = await fetch("{GET_URL}"); show("get", r, ""); }}
  catch (e) {{ console.log("get error", String(e.cause || e)); }}
  try {{
    const r = await fetch("{API}/gists", {{method: "POST", body: '{BODY}',
      headers: {{"content-type": "application/json"}}}});
    show("post", r, await r.text());
  }} catch (e) {{ console.log("post error", String(e.cause || e)); }}
}})();
"""

PYTHON = f"""
import requests
for what, call in (("get", lambda: requests.get("{GET_URL}", timeout=20)),
                   ("post", lambda: requests.post("{API}/gists", data='{BODY}', timeout=20))):
    try:
        r = call()
        print(what, r.status_code, " ".join(r.text.split()) if what == "post" else "")
    except Exception as e:
        print(what, "error", type(e).__name__, str(e).splitlines()[0][:200])
"""


def curl_probe():
    lines = [f"printf 'get %s\\n' \"$(curl -sS -o /dev/null -w '%{{http_code}}' {GET_URL} 2>&1)\""]
    for method, path in CURL_POSTS:
        lines.append(
            f"printf 'post %s\\n' \"$(curl -sS -w ' %{{http_code}}' -X {method} "
            f"-H 'Content-Type: application/json' -d '{BODY}' '{API}{path}' 2>&1 | tr '\\n' ' ')\"")
    return "\n".join(lines)


def ca_init(g):
    """`openmoat proxy ca init` with the setting, answered `y` on a terminal."""
    env = {**g.env, **SETTING}
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(g.home)
        os.execve(g.binary, [g.binary, "proxy", "ca", "init"], env)
    seen, answered = b"", False
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        seen += chunk
        if not answered and b"[y/N]" in seen:
            os.write(fd, b"y\n")
            answered = True
    _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0 or b"proxy CA made for api.github.com" not in seen:
        fail("openmoat proxy ca init failed", seen.decode(errors="replace"))


def one_line(text):
    """`text` for an annotation, which is one line: GitHub reads `%0A` as a line break in it."""
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def notice(name, columns, cells):
    """One table row as an annotation, which the Checks API shows without the job's log."""
    result = "; ".join(f"{column}: {cell}" for column, cell in zip(columns, cells) if cell)
    print(f"::notice title=adr-062 step 0::{one_line(name)}: {one_line(result)}")


def fail(what, detail=""):
    """Stop with `what` and `detail` as an annotation and in the job summary."""
    detail = detail.strip()
    escaped = one_line(detail)
    print(f"::error title=adr-062 step 0::{what}: {escaped}" if detail else f"::error::{what}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write(f"**adr-062 step 0 failed:** {what}\n\n```\n{detail}\n```\n")
    sys.exit(1)


def home_parent():
    """Where the throwaway HOME goes: not under the system's temp directory,
    which `openmoat run` grants its commands, so that on Linux (Landlock
    cannot deny inside a granted tree) it refuses to start with OpenMoat's
    state there. The runner's temp directory, or this checkout's `target/`."""
    parent = os.environ.get("RUNNER_TEMP") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "target")
    os.makedirs(parent, exist_ok=True)
    return parent


def run(g, script, setting=True, extra=None):
    """`openmoat run -- /bin/sh -c script` in the project: (stdout, session)."""
    env = {**g.env, **(SETTING if setting else {}), **(extra or {})}
    out = subprocess.run([g.binary, "run", "--", "/bin/sh", "-c", script], env=env,
                         cwd=g.project, capture_output=True, text=True, timeout=600)
    found = re.search(r"audit session (\S+)\)", out.stderr)
    if not found:
        fail(f"openmoat run did not start (exit {out.returncode})", out.stderr)
    return out.stdout, found.group(1)


def rows(g, session):
    """(refused by the rule, POSTs recorded as passed, terminated GETs) of `session`."""
    with sqlite3.connect(os.path.join(g.home, ".moat", "audit.db")) as db:
        def count(where, *args):
            return db.execute(f"SELECT COUNT(*) FROM events WHERE host = 'proxy' AND "
                              f"session_id = ? AND {where}", (session, *args)).fetchone()[0]
        api = f"%{API}%"
        return (count("verdict = 'deny' AND rules LIKE ?", f"%{MARKER}%"),
                count("verdict = 'allow' AND upper(tool) = 'POST' AND action LIKE ?", api),
                count("verdict = 'allow' AND tool = 'GET' AND action LIKE ?", api))


def classify_get(line):
    if line is None:
        return "no answer"
    rest = line.split(" ", 1)[1] if " " in line else ""
    return "ok" if rest.startswith("200") else f"fails closed: {rest[:120]}"


def classify_post(line):
    """`refused` (the rule's answer), `refused by OpenMoat: …` (another of
    the proxy's refusals), `fails closed: …` (no HTTP answer at all), or
    `REACHED GITHUB: …` (an HTTP status from anyone else: it got through).
    curl prints the status last (`000` without an answer), node and Python
    first; a client error starts with `error`."""
    text = line.split(" ", 1)[1] if " " in line else ""
    if MARKER in text:
        return "refused"
    if "moat proxy:" in text:
        return f"refused by OpenMoat: {text[:120]}"
    words = text.split()
    answered = any(re.fullmatch(r"[1-5]\d\d", w) for w in words[:1] + words[-1:])
    if answered and not text.startswith("error"):
        return f"REACHED GITHUB: {text[:120]}"
    return f"fails closed: {text[:120]}"


def clients():
    """(name, script, extra environment) of each client present, or (name, None, why)."""
    found = []
    found.append(("curl", curl_probe(), {}) if shutil.which("curl")
                 else ("curl", None, "curl is not installed"))
    if shutil.which("gh"):
        probe = subprocess.run(["gh", "api", "/rate_limit"], capture_output=True, text=True,
                               env={"PATH": os.environ.get("PATH", ""), "HOME": "/nonexistent"})
        if probe.returncode != 0 and re.search(r"auth login|GH_TOKEN", probe.stderr):
            found.append(("gh", None, "`gh api` asks for a token even for `/rate_limit`, and "
                          "this check sends none"))
        else:
            found.append(("gh", "printf 'get %s\\n' \"$(gh api /rate_limit >/dev/null 2>&1 && "
                          "echo 200 || echo error)\"", {}))
    else:
        found.append(("gh", None, "gh is not installed"))
    if shutil.which("node"):
        script = f"node -e {shlex.quote(NODE)}"
        found.append(("node fetch (NODE_USE_ENV_PROXY=1)", script, {"NODE_USE_ENV_PROXY": "1"}))
        found.append(("node fetch (default)", script, {}))
    else:
        found.append(("node fetch", None, "node is not installed"))
    has_requests = shutil.which("python3") and subprocess.run(
        ["python3", "-c", "import requests"], capture_output=True).returncode == 0
    found.append(("python requests", f"python3 -c {shlex.quote(PYTHON)}", {}) if has_requests
                 else ("python requests", None, "python3 has no `requests` module here"))
    return found


def correctness(g):
    """The client table and the errors it shows."""
    table = ["| client | (a) allowed GET | terminated | (b) denied POST | audit rows |",
             "|---|---|---|---|---|"]
    errors = []
    for name, script, extra in clients():
        if script is None:
            table.append(f"| {name} | skipped: {extra} | | | |")
            notice(name, CLIENT_COLUMNS, [f"skipped: {extra}"])
            continue
        out, session = run(g, script, extra=extra)
        lines = out.splitlines()
        get = next((line for line in lines if line.startswith("get ")), None)
        posts = [classify_post(line) for line in lines if line.startswith("post ")]
        refused, passed, terminated = rows(g, session)
        got = classify_get(get)
        if passed:
            errors.append(f"{name}: {passed} POST to {API} recorded as passed")
        errors += [f"{name}: {p}" for p in posts if p.startswith("REACHED")]
        if refused != sum(p == "refused" for p in posts):
            errors.append(f"{name}: {sum(p == 'refused' for p in posts)} refusals answered but "
                          f"{refused} `{MARKER}` audit rows")
        post_cell = "; ".join(sorted(set(posts))) or "not sent"
        if len(posts) > 1:
            post_cell = f"{sum(p == 'refused' for p in posts)}/{len(posts)} refused; {post_cell}"
        table.append(f"| {name} | {got} | {'yes' if terminated else 'no'} | {post_cell} | "
                     f"{refused} refused, {passed} POST passed |")
        notice(name, CLIENT_COLUMNS, [got, "yes" if terminated else "no", post_cell,
                                      f"{refused} refused, {passed} POST passed"])
    out, _ = run(g, "git ls-remote https://github.com/crocodile-labs/openmoat.git HEAD "
                    ">/dev/null 2>&1 && echo 'get 200' || echo 'get error'")
    table.append(f"| git ls-remote (github.com, no rule) | {classify_get(out.strip())} | no | "
                 f"n/a | |")
    notice("git ls-remote (github.com, no rule)", CLIENT_COLUMNS,
           [classify_get(out.strip()), "no", "n/a"])
    return table, errors


def times(g, mode, n):
    """`n` curl GET times in ms: `direct`, `tunnel` (setting off) or `terminated`."""
    loop = (f"i=0; while [ $i -lt {n} ]; do curl -sS -o /dev/null -w '%{{time_total}}\\n' "
            f"{GET_URL}; i=$((i+1)); done")
    if mode == "direct":
        out = subprocess.run(["/bin/sh", "-c", loop], capture_output=True, text=True).stdout
    else:
        out, _ = run(g, loop, setting=mode == "terminated")
    return [float(t) * 1000 for t in out.split() if re.fullmatch(r"[0-9.]+", t)]


def latency(g, runs):
    modes = ["direct", "tunnel", "terminated"]
    samples = {m: [] for m in modes}
    per_batch = max(1, runs // BATCHES)
    for batch in range(BATCHES):
        for mode in modes[batch:] + modes[:batch]:
            samples[mode] += times(g, mode, per_batch)
    short = [f"latency ({mode}): {len(got)} of {per_batch * BATCHES} curl requests answered"
             for mode, got in samples.items() if len(got) < per_batch * BATCHES]
    if short:
        # The client table is still reported; the run fails on these.
        return [f"latency not measured: {'; '.join(short)}"], short, []
    stat = {m: (statistics.median(s), latency_ab.percentile(s, 95)) for m, s in samples.items()}
    added = (stat["terminated"][0] - stat["tunnel"][0], stat["terminated"][1] - stat["tunnel"][1])
    table = [f"curl GET {GET_URL}, {per_batch * BATCHES} requests per path, ms "
             "(median / p95)", "", "| path | median | p95 |", "|---|---|---|"]
    table += [f"| {m} | {s[0]:.1f} | {s[1]:.1f} |" for m, s in stat.items()]
    table.append(f"| added by termination | {added[0]:.1f} | {added[1]:.1f} |")
    for name, (median, p95) in [*stat.items(), ("added by termination", added)]:
        notice(name, LATENCY_COLUMNS, [f"{median:.1f}", f"{p95:.1f}"])
    warnings = []
    if added[1] > latency_ab.BUDGET_MS:
        warnings.append(f"termination adds {added[1]:.1f} ms at p95, over the "
                        f"{latency_ab.BUDGET_MS:.0f} ms budget")
    return table, [], warnings


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    runs = int(sys.argv[2]) if len(sys.argv) == 3 else 30
    started = time.monotonic()
    try:
        g = latency_ab.Guard("poc", sys.argv[1], "moat-adr062-", parent=home_parent())
    except subprocess.CalledProcessError as error:
        fail("openmoat init failed in the throwaway HOME",
             (error.stderr or b"").decode(errors="replace"))
    print(f"throwaway HOME: {g.home}")
    ca_init(g)
    clients_table, errors = correctness(g)
    latency_table, slow, warnings = latency(g, runs)
    table = "\n".join([f"ADR-062 step 0 on {sys.platform} ({time.monotonic() - started:.0f} s)",
                       "", *clients_table, "", *latency_table])
    latency_ab.finish(table, [(errors + slow, warnings)], [g])
    print("✔ no denied request reached GitHub; every refusal has an audit row")


if __name__ == "__main__":
    main()
