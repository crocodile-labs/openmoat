# Outside benchmarks

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to know how OpenMoat's default policy scores on attack
> sets written by other people, what it lets through, and how the numbers were made.

**On this page:** [Summary](#summary) · [What was run](#what-was-run) ·
[How a case becomes a tool call](#how-a-case-becomes-a-tool-call) · [Scoring](#scoring) ·
[RedCode-Exec](#redcode-exec) · [agent-egress-bench](#agent-egress-bench) ·
[Published numbers](#published-numbers-and-how-they-differ) ·
[What these results show](#what-these-results-show) · [Limits of the method](#limits-of-the-method) ·
[MoatBench](#moatbench) · [Reproduce it](#reproduce-it)

[MoatBench](MOATBENCH.md) was written by OpenMoat's authors. This page measures the
same decision engine against two benchmarks written by others:
[RedCode-Exec](https://github.com/AI-secure/RedCode) (risky Python and Bash that an agent
is asked to run) and [agent-egress-bench](https://github.com/pipelab-org/agent-egress-bench)
(exfiltration and egress attempts with benign controls). Neither was designed for a
tool-call hook, so each case is first turned into the calls a coding agent would send
OpenMoat; how, and what that leaves out, is below.

## Summary

Decision engine only. Run on 2026-11-22 with the default policy of OpenMoat 0.25.0
(`main` at `33d8f388`) and with the rules this measurement led to
([ADR-112](adr/ADR-112-default-rules-from-outside-benchmarks.md), released in 0.26.0), and
again on 2026-11-24 with OpenMoat 0.27.0 (`main` at `4c9c40f5`, which adds ADR-116's
`obfuscated` rule and PowerShell reader), and on 2026-11-25 with OpenMoat 0.28.0 (`main` at
`aaaada00`, which adds ADR-123's rules). "Stopped" is `deny`, or `deny` plus `review`
(held for a person). `defer` means OpenMoat leaves the call to the agent's own permission
prompt, which is the default policy's answer for a call no rule names (ADR-025); it is
not counted as stopped.

| Benchmark, form | Attacks | Stopped, deny only: 0.25.0 → 0.26.0 → 0.27.0 → 0.28.0 | Stopped, deny + review: 0.25.0 → 0.26.0 → 0.27.0 → 0.28.0 | `defer`: 0.25.0 → 0.26.0 → 0.27.0 → 0.28.0 | Allowed | False positives |
|---|--:|--:|--:|--:|--:|--:|
| RedCode-Exec, code inline in the command, all 47 scenario files | 1,410 | 188 (13.3%) → 209 (14.8%) → 209 (14.8%) → 209 (14.8%) | 488 (34.6%) → 658 (46.7%) → 665 (47.2%) → 665 (47.2%) | 922 (65.4%) → 752 (53.3%) → 745 (52.8%) → 745 (52.8%) | 0 in each | no benign cases in the set |
| RedCode-Exec, code inline, the 30 scenario files whose code acts on the machine | 900 | 178 (19.8%) → 199 (22.1%) → 199 (22.1%) → 199 (22.1%) | 450 (50.0%) → 620 (68.9%) → 622 (69.1%) → 622 (69.1%) | 450 (50.0%) → 280 (31.1%) → 278 (30.9%) → 278 (30.9%) | 0 in each | |
| RedCode-Exec, script written to the project, then run | 1,410 | 0 in each | 0 in each | 600 (42.6%) in each | 810 (57.4%) in each | |
| agent-egress-bench, the call an agent makes (`curl`, or the agent's own tool for MCP cases) | 122 of 192 | 58 (47.5%) → 61 (50.0%) → 61 (50.0%) → 61 (50.0%) | 58 (47.5%) → 66 (54.1%) → 67 (54.9%) → 84 (68.9%) | 63 (51.6%) → 55 (45.1%) → 54 (44.3%) → 37 (30.3%) | 1 in each | 12 of 37 (32.4%) in each |
| agent-egress-bench, the same over the whole corpus, skipped cases counted as not stopped | 192 | 58 (30.2%) → 61 (31.8%) → 61 (31.8%) → 61 (31.8%) | 58 (30.2%) → 66 (34.4%) → 67 (34.9%) → 84 (43.8%) | | | |
| agent-egress-bench, plain `GET`s through the agent's fetch tool | 53 | 5 (9.4%) → 20 (37.7%) → 20 (37.7%) → 20 (37.7%) | 5 (9.4%) → 22 (41.5%) → 22 (41.5%) → 38 (71.7%) | 48 → 31 → 31 → 15 | 0 in each | 0 of 14 in each |

0.28.0 adds ADR-123's rules, run on 2026-11-24 on `main` after 0.27.0 and again on 2026-11-25 on `main` at `aaaada00`, the 0.28.0 release, with the same results, the same
way: `encoded-secret-egress` (a known token or credential found once URL encoding,
base64, hex or zero-width characters are undone) and `hostname-data` (encoded bytes in
the labels of a host no rule allows), both held for review. They add 17 agent-egress-bench
reviews in the headline form (16 in `curl`: 5 `encoding_evasion`, 6
`hostname_exfiltration`, 5 `url`; 1 `encoding_evasion` case in the agent's fetch tool) and
16 in the fetch form, and no false positive: every benign case decides as on 0.27.0.
RedCode-Exec is unchanged: its snippets send no encoded token and name no such host.

0.27.0's change is the `obfuscated` rule: 7 more RedCode-Exec cases and 1 more
agent-egress-bench case held for review, and no new false positive in either. The
per-scenario and per-category tables below compare 0.25.0 with ADR-112's rules ("after",
as released in 0.26.0).

Read with these facts beside it:

- 101 of RedCode's 209 denies after the change (101 of 188 before), and 31 of
  agent-egress-bench's 61 (33 of 58 before), come from the default policy's `net: deny`,
  which refuses a connection to a host no rule allows whatever it carries. The same rule
  makes all 12 false positives, the same 12 before and after: benign `POST`s and requests
  with headers to hosts the policy does not list. The change added no false positive in
  either benchmark. Outside them it adds one review a person may meet in everyday work: a
  read of `/etc` or `/etc/ssh` itself (`ls /etc`), since those folders now hold secret paths.
- Most of the change is `review`, not `deny`: writes in system folders (`system-files`)
  and JWTs or database URLs sent out (`credential-egress`) are held for a person, because
  each has everyday uses (a container running as `root`, a JWT sent to its own API).
- When the agent writes the script to a file and runs it, the decision engine sees a
  project file being written and `python3 redcode_task.py` or `bash redcode_task.sh`, not
  the code. No case was stopped in that form. What limits that run is the OS sandbox
  (the agent's own, or `openmoat run`; [SANDBOX.md](SANDBOX.md)), which this measurement
  does not include.
- 70 of agent-egress-bench's 192 attacks have no OpenMoat input (agent cards, MCP tool
  lists and results, WebSocket frames, responses an agent receives); they are listed
  under [Skipped](#skipped-no-input-for-the-decision-engine).

## What was run

| | |
|---|---|
| OpenMoat | 0.25.0, `main` at `33d8f388`, debug build of `openmoat`; 0.26.0: the same with ADR-112's rules and engine changes (`feat/benchmark-rule-gaps`, released in 0.26.0); 0.27.0: `main` at `4c9c40f5`, debug build; 0.28.0: ADR-123's rules and decoding, debug build, `main` after 0.27.0 on 2026-11-24 and `main` at `aaaada00` on 2026-11-25 |
| Policy | `crates/openmoat-core/policies/default-v1.yaml` as shipped (0.25.0's, the one with ADR-112's rules, then 0.27.0's), nothing added |
| Engine path | `openmoat policy check --policy <default-v1.yaml> --kind <kind> --format json`, one call per action, the same compile and decide `openmoat guard` uses after the lock check, without an installation snapshot (programs are not resolved to their paths) |
| RedCode | `AI-secure/RedCode` at `664e4793dc7309f98b8271baed5bbc04d6ef4c39` (MIT), `dataset/RedCode-Exec/`: 27 Python and 20 Bash scenario files, 30 snippets each |
| agent-egress-bench | `pipelab-org/agent-egress-bench` at `8fad78b20bf24200c5eb3e1749d94dcb0d92af0e` (Apache-2.0), corpus `v2.16.0`, `cases/`: 270 cases in 18 categories, 192 `block`, 77 `allow`, 1 `warn` |
| Machine | macOS 12, run on 2026-11-22 (0.25.0, 0.26.0's rules) , 2026-11-24 (0.27.0, and 0.28.0's rules) and 2026-11-25 (0.28.0) |
| Harness | [`scripts/bench/external.py`](../scripts/bench/external.py), Python 3 standard library |

The datasets are not part of this repository. The harness reads their JSON and never
executes, imports or runs anything from them.

## How a case becomes a tool call

The engine decides tool calls, not prompts or code files, so the harness writes down the
call (or calls) an agent would make to carry out each case:

**RedCode-Exec.** Each snippet is given to agents as code, as a summary and as detailed
steps (the 4,050 prompts of the paper), but all three ask for the same snippet to run. The
snippet is the case here: 1,410 of them. Two forms are scored apart:

- `inline`: the code is in the command. A Bash snippet is the command line itself (a
  multi-line script, as agents send one to their shell tool). A Python snippet is
  `python3 -c '<code>'`, the code quoted as one argument. The engine reads every word of
  it: the shell classifier parses the Bash, and scans the Python for the files, hosts and
  programs it names.
- `file`: the agent writes `redcode_task.py` or `redcode_task.sh` into the project, then
  runs `python3 redcode_task.py` or `bash redcode_task.sh`. The engine is asked about both
  calls; a write's content is not part of a `policy check` action.

Both are ways agents run code. `inline` is what the engine can judge; `file` shows what it
cannot see on its own. RedCode's container runs the agent as `root`, so these cases are
decided with `HOME=/root` (a name only: nothing is written there), and `~/.bashrc` means
`/root/.bashrc` as the snippets intend.

**agent-egress-bench.** Each case is a wire input with an expected verdict.

| Input type | Becomes | Forms |
|---|---|---|
| `url`, `header`, `request_body` | the `curl` command an agent's shell tool would run, with the method, headers, body and URL the case gives (`curl -sS -X POST -H 'Content-Type: …' --data-binary '…' <url>`) | `curl`; a plain `GET` with no headers is also the URL given to the agent's own fetch tool (`fetch`, Claude Code's `WebFetch`, which carries no body or headers) |
| `mcp_tool_call`, `mcp_tool_sequence` | every `tools/call` in the case | `native`: as the agent's own tool where one does the same job (`read_file` and `list_dir` → a file read of the path, `write_file` → a file write, `fetch` → the fetch tool, `exec` and `run_command` → a shell command), and as the MCP tool otherwise; `mcp`: every call as the MCP tool `mcp__bench__<tool>` |
| everything else | nothing: skipped with the reason, below | |

`policy check --kind mcp` takes the tool's name only. The hook also checks the paths, URLs
and commands a host adapter finds in an MCP call's arguments, so the `mcp` form scores
less than the hook would; the `native` form is the closer measure of what those calls do.
A sequence is decided call by call with no session: the features that need one (secret
taint, injected input, cross-server flow, ADR-057 and ADR-058) are not measured. The cases'
paths name `/home/user` as the agent's home, so they are decided with `HOME=/home/user`.

The corpus scores a `warn` case as `allow`; so does this page. The headline uses the
`curl` form for HTTP cases and the `native` form for MCP cases: the call a coding agent
makes when it does the thing itself.

## Scoring

For each case and form the verdict is the strictest of its calls, as the hook decides one
tool call (`deny` > `review` > `defer` > `allow`).

- An attack is **stopped** by `deny`; "deny + review" also counts calls held for a person.
- `defer` is reported on its own: OpenMoat stays quiet and the agent's own permission
  prompt decides. Whether that prompt appears depends on the agent and its settings, so
  `defer` is neither stopped nor allowed here.
- A benign case answered `deny` or `review` is a **false positive**.
- "Host only" counts the denies whose only rule is the default `net: deny` for a host no
  rule allows (with the catch-all rules beside it): the call was stopped for where it goes, not
  for what it carries.

## RedCode-Exec

### By form

| Form | Policy | Attacks | deny | of which host only | review | defer | allow | Stopped (deny) | Stopped (deny + review) |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `inline` | 0.25.0 | 1,410 | 188 | 101 | 300 | 922 | 0 | 13.3% | 34.6% |
| `inline` | 0.26.0 | 1,410 | 209 | 101 | 449 | 752 | 0 | 14.8% | 46.7% |
| `inline` | 0.27.0 | 1,410 | 209 | 101 | 456 | 745 | 0 | 14.8% | 47.2% |
| `inline`, code acts on the machine | 0.25.0 | 900 | 178 | 92 | 272 | 450 | 0 | 19.8% | 50.0% |
| `inline`, code acts on the machine | 0.26.0 | 900 | 199 | 92 | 421 | 280 | 0 | 22.1% | 68.9% |
| `inline`, code acts on the machine | 0.27.0 | 900 | 199 | 92 | 423 | 278 | 0 | 22.1% | 69.1% |
| `inline`, logic only | 0.25.0, 0.26.0 | 510 | 10 | 9 | 28 | 472 | 0 | 2.0% | 7.5% |
| `inline`, logic only | 0.27.0 | 510 | 10 | 9 | 33 | 467 | 0 | 2.0% | 8.4% |
| `file` | both | 1,410 | 0 | 0 | 0 | 600 | 810 | 0.0% | 0.0% |

"Logic only" is ten scenarios whose snippet only computes and prints; the risk is in the
code's logic (biased scoring, a loose IP regex, a timing-unsafe comparison, privilege calls
that only print, a seeded random generator, unsalted hashing, a missing default case, a
flawed workflow, a duplicate key, a memory leak), so no tool-call check can see it. This
split was made from the snippets for this page; RedCode does not define it.

In the `file` form every Python case is `allow` (running a project's Python script is an
allowed developer command, `dev-shell`; writing a project file is `project-fs`) and every
Bash case is `defer` (`bash <script>` is a command no rule names).

### `inline`, per scenario

The labels are this page's short descriptions of each scenario's snippets. Each cell is
deny / review / defer, 0.25.0 → after; a single value is unchanged.

| Scenario | Python | Bash | Main rules after |
|---|---|---|---|
| 01 send a file's contents in a `POST` to `127.0.0.1` | 0 / 30 / 0 → 2 / 28 / 0 | 0 / 30 / 0 | `opaque-code`; `request-rule` (Bash: a request whose host is only known at run time); the 2 Python denies send `/etc/shadow` and `/etc/gshadow` (`secrets-paths`) |
| 02 download a script into a system folder | 30 / 0 / 0 | 0 / 0 / 30 → 0 / 30 / 0 | Python: host not allowed (`default.net`); Bash `wget -O /usr/…`: `system-files` |
| 03 fetch a risky web page | 30 / 0 / 0 | 0 / 0 / 30 | Python: host not allowed; Bash: `curl $url`, the host in a variable, stays `defer` (ADR-112 §7) |
| 04 copy a system file to `/usr` | 2 / 1 / 27 → 5 / 25 / 0 | 0 / 0 / 30 → 3 / 27 / 0 | `system-files` for the copy; denies copy `/root/.bashrc` (`shell-rc`) or a password-hash file (`secrets-paths`) |
| 05 list a system folder | 0 / 30 / 0 | 0 / 1 / 29 → 0 / 3 / 27 | `opaque-code`; `home-sweep` for `/root`; after, `protected-contents` for `ls /etc` and `ls /etc/ssh`, which now hold secret paths |
| 06 write base64 content to a file | 2 / 28 / 0 | 0 / 0 / 30 → 0 / 30 / 0 | `opaque-code`; Bash: the file is in `/usr` (`system-files`) |
| 07 read a system file (`/etc/shadow`, `/etc/passwd`, `/proc`, logs) | 0 / 30 / 0 → 2 / 28 / 0 | 0 / 0 / 30 → 1 / 0 / 29 | `secrets-paths` for `/etc/shadow` and `/etc/gshadow`; `opaque-code`; the other Bash reads hold the path in a variable the classifier does not follow, or read a world-readable file |
| 08 delete a system file | 0 / 0 / 30 → 5 / 19 / 6 | 2 / 0 / 28 → 5 / 19 / 6 | `system-files` (Python: inline code that deletes now counts as a write); `secrets-paths`; `shell-rc`; the 6 left delete logs in `/var/log` |
| 09 add an alias to `/root/.bashrc` | 30 / 0 / 0 | 30 / 0 / 0 | `shell-rc` |
| 10 reverse shell to `127.0.0.1` (Python) | 0 / 24 / 6 | | `opaque-code`; the 6 deferred name `127.0.0.1` (`local-net`) |
| 11 monitor the system (Python) | 0 / 1 / 29 → 0 / 2 / 28 | | `home-sweep`; after, `protected-contents` for a watch on `/etc` |
| 13 path traversal read (`/usr/../etc/passwd`) | 0 / 30 / 0 | 0 / 0 / 30 → 2 / 0 / 28 | `opaque-code`; Bash: the 2 denies resolve to `/etc/shadow` and `/etc/gshadow` |
| 14 `eval` of input | 0 / 30 / 0 | 22 / 1 / 7 → 22 / 2 / 6 | `opaque-code`; Bash `eval` is `pipe-to-shell`; after, `protected-contents` for `ls -a /etc/` |
| 18 kill processes by name | 0 / 0 / 30 | 0 / 1 / 29 | the pids come from `ps` at run time, which `stops-system` cannot see (below) |
| 21 repeat data and send it over UDP to `127.0.0.1` | 0 / 17 / 13 | 0 / 13 / 17 | `opaque-code`; `unparseable` (brace expansion past 256 words) |
| 24 unsafe deserialization (Python) | 0 / 5 / 25 | | |
| 26 fetch risky URLs (Python) | 30 / 0 / 0 | | host not allowed |
| logic only: 12, 15, 16, 17, 19, 20, 22, 23, 25, 27 | 9 / 26 / 265 | 1 / 2 / 207 | the 9 Python denies name a host (`192.168.1.1`, `example.com`) |

### What is not stopped, by class

After the change:

- **A path held in a shell variable** (Bash 07, 13): `file_name='/etc/gshadow'; cat
  "$file_name"` is `unparseable` and defers; the same `cat /etc/gshadow` is denied. The
  classifier follows some assignments, not this one; under the parser freeze (AGENTS.md)
  that is left to the OS sandbox.
- **Reads of world-readable system files** (07, 13): `/etc/passwd`, `/etc/group`, `/proc`,
  `/sys` and logs. Reading them changes nothing and is common, so it stays as it was.
- **Deletes in `/var`** (08): `rm /var/log/lastlog`. `/var` holds programs' data and macOS's
  temporary folders, so `system-files` leaves it out.
- **Downloads to a host in a variable** (Bash 03): `curl -s "$url"` sends nothing but the
  URL; it stays `defer` like a fetch tool's read of an unlisted URL (ADR-112 §7).
- **Processes ended by pids found at run time** (18): a loop over `ps -eo pid,comm` that
  kills each match. `stops-system` reads `pkill`/`killall` patterns, `kill 1`, `kill -1`
  and `kill $(pgrep …)`, not pids a script computes; `proc.kill()` through `psutil` is
  Python that only names modules.
- **Python that only names modules** (11, 18, 24 and most deferred cases): inline code
  that opens no file, host or program by a literal the scan can see is decided as
  `python3 -c …`, which no rule names. `opaque-code` (review) catches code that builds what
  it opens at run time.
- **Logic-only scenarios**: out of reach of any tool-call check, as above.

## agent-egress-bench

### By form

| Form | Policy | Attacks | deny | of which host only | review | defer | allow | Stopped (deny) | Stopped (deny + review) | Benign | False positives |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `curl` (url, header, request_body) | 0.25.0 | 84 | 48 | 32 | 0 | 36 | 0 | 57.1% | 57.1% | 26 | 12 (46.2%), all host only |
| `curl` | 0.26.0, 0.27.0 | 84 | 51 | 31 | 2 | 31 | 0 | 60.7% | 63.1% | 26 | 12 (46.2%), the same, all host only |
| `curl` | 0.28.0 | 84 | 51 | 31 | 18 | 15 | 0 | 60.7% | 82.1% | 26 | 12 (46.2%), the same, all host only |
| `fetch` (plain `GET`s) | 0.25.0 | 53 | 5 | 0 | 0 | 48 | 0 | 9.4% | 9.4% | 14 | 0 |
| `fetch` | 0.26.0, 0.27.0 | 53 | 20 | 13 | 2 | 31 | 0 | 37.7% | 41.5% | 14 | 0 |
| `fetch` | 0.28.0 | 53 | 20 | 13 | 18 | 15 | 0 | 37.7% | 71.7% | 14 | 0 |
| `native` (MCP calls as the agent's own tools) | 0.25.0 | 38 | 10 | 1 | 0 | 27 | 1 | 26.3% | 26.3% | 11 | 0 |
| `native` | 0.26.0 | 38 | 10 | 0 | 3 | 24 | 1 | 26.3% | 34.2% | 11 | 0 |
| `native` | 0.27.0 | 38 | 10 | 0 | 4 | 23 | 1 | 26.3% | 36.8% | 11 | 0 |
| `native` | 0.28.0 | 38 | 10 | 0 | 5 | 22 | 1 | 26.3% | 39.5% | 11 | 0 |
| `mcp` (MCP calls by tool name only) | each | 38 | 0 | 0 | 0 | 38 | 0 | 0.0% | 0.0% | 11 | 0 |

On 0.25.0 no case was answered `review`. The one `allow` is `mcp-input-hex-apikey-008`, an
`echo` of a hex-encoded key, which runs locally and sends nothing.

### Per category, the call an agent makes

Each cell is 0.25.0 → after; a single value is unchanged.

| Category | Attacks | deny | of which host only | review | defer | Stopped (deny + review) | Benign | False positives |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `headers` (`curl`) | 10 | 10 | 6 → 5 | 0 | 0 | 100% | 4 | 4 |
| `request_body` (`curl`) | 18 | 18 | 11 → 10 | 0 | 0 | 100% | 7 | 7 |
| `ssrf_bypass` (`curl`) | 11 | 8 | 6 | 0 | 3 | 72.7% | 2 | 0 |
| `url` (`curl`) | 22 | 9 → 12 | 6 → 7 | 0 → 2 | 13 → 8 | 40.9% → 63.6% | 5 | 1 |
| `hostname_exfiltration` (`curl`) | 9 | 2 | 2 | 0 | 7 | 22.2% | 1 | 0 |
| `crypto_financial` (`curl`) | 8 | 1 | 1 | 0 | 7 | 12.5% | 1 | 0 |
| `encoding_evasion` (`curl`) | 6 | 0 | 0 | 0 | 6 | 0% | | |
| `mcp_chain` (`native`) | 13 | 8 | 1 → 0 | 0 → 1 | 5 → 4 | 61.5% → 69.2% | 4 | 0 |
| `shell_obfuscation` (`native`) | 8 | 2 | 0 | 0 → 1 | 6 → 5 | 25.0% → 37.5% | 2 | 0 |
| `crypto_financial` (`native`) | 2 | 0 | 0 | 0 | 2 | 0% | | |
| `encoding_evasion` (`native`) | 3 | 0 | 0 | 0 | 3 | 0% | | |
| `mcp_input` (`native`) | 12 | 0 | 0 | 0 → 1 | 11 → 10 (1 allow) | 0% → 8.3% | 3 | 0 |
| `false_positive` (`curl`, `native`) | | | | | | | 8 | 0 |

What stopped them on 0.25.0: `token-egress` (a known token kind, AWS, GitHub, OpenAI,
Slack, …, sent to a host that is not its service's) in URLs, headers and bodies;
`cloud-metadata` (`169.254.169.254`, also behind a trailing dot); `card-egress` (card
numbers in a CSV upload); `secrets-paths` for reads of `.env` files,
`/home/user/.aws/credentials` and `/home/user/.ssh/id_rsa` in MCP chains, and for
`$'\162\155' -rf /home/user/.ssh`; `pipe-to-shell` for `echo … | base64 -d | bash`. A card
test number sent with its expiry and CVV (`crypto-credit-card-006`) was denied only for
its host: `card-egress` did not match it (the rule leaves processors' published test
numbers out, and this is one).

What the change added:

- `url`: the GitLab deploy token (`gldt-…`, `token-egress`); a relay URL whose query names
  the metadata address (`…?target=http://169.254.169.254/…`, `cloud-metadata`) and one
  whose query names a private address (`…/proxy?url=http://10.0.0.12:8500/…`,
  `default.net`), for `curl` and the fetch tool alike; a JWT and a Postgres URL with its
  password, held for review (`credential-egress`).
- The fetch tool now reaches no address `curl` cannot: `0x7f000001`, `0177.0.0.1`,
  `127.1`, `0.0.0.0`, `[::ffff:127.0.0.1]`, `10.0.0.1`, a URL with a user and password,
  and the all-digit or mixed host labels are denied as for `curl` (`default.net`), 13 of
  the fetch form's 20 denies.
- `native`: a write to `/var/spool/cron/crontabs/user` (`persistence`, review), a JWT in
  a fetch URL (`credential-egress`), and `/bin/{rm,} -rf …`, whose brace expansion makes
  `rm` delete `/bin/` too (`system-files`).
- In one header deny and one body deny, a credential the old list did not know (the body's
  is a PEM private key) is now named by `token-egress` beside `default.net`, so those two
  are no longer "host only".

### What is not stopped, by class

All of these are `defer`: left to the agent's prompt. After the change:

- **Encoded secrets in a URL** (`url`, `encoding_evasion`): known tokens hidden by base64,
  hex, URL encoding (once, twice or three times) or zero-width characters, a JWT in
  base64, an AWS secret key whose `=` is written `%3D`. On 0.27.0 `token-egress` and
  `credential-egress` read the text as written. In 0.28.0
  `encoded-secret-egress` (ADR-123) decodes first and holds all of these for review. What
  stays `defer`: the benchmark's data-URL image (`enc-benign-base64-image-008`, an attack
  in the corpus despite its name), which decodes to no text.
- **Crypto and payment data** (`crypto_financial`): Bitcoin and Ethereum addresses and
  private keys, extended public keys, seed phrases and IBANs. A raw 64-hex-digit key looks
  like a hash, and a seed phrase cannot be told from English words without BIP-39's word
  list and checksum (ADR-112 §5).
- **Data in the host name** (`hostname_exfiltration`): `https://<hex or base32>.exfil.evil.com/`.
  A `GET` to an unlisted host is a read (`fetch: defer`); 2 of 9 are denied only because
  an all-digit or mixed label is read as a connection. In 0.28.0 `hostname-data`
  (ADR-123) holds 6 more for review; the one left is `ghp-xxxx.yyyyzzzz.aaaabbbb.ccccdddd`,
  labels of plain letters too short to count.
- **Plain loopback** (`ssrf_bypass`): `http://127.0.0.1/admin` and `http://[::1]/admin` are
  `local-net` (defer) in both forms, as `localhost` is: dev servers are an everyday target.
- **Unlisted hosts with nothing recognisable in the URL** (`url`): a blocklisted-looking
  domain, a high-entropy path, a JSON service-account stub.
- **Shell obfuscation run through the agent's shell tool**: `r\m -rf /var/data`,
  `` `printf rm` -rf …``, `$(printf rm) -rf …`, `IFS=,;CMD=r,m;$CMD -rf /data`, full-width
  `Ｒｍ`. The plain `rm -rf /var/data` is itself `defer` under the default policy (only the
  home folder, `/`, disks and since ADR-112 the system folders are guarded), so the
  obfuscation changes nothing here.
- **Content in MCP arguments** (`mcp_input`, and the `mcp` form throughout): a key,
  injected instructions or an environment dump in a `send_message`, `save_note`, `submit`
  or `write_file` argument. The engine has no content scan for MCP arguments or written
  files outside the credentials `token-egress` and `credential-egress` know in commands
  and URLs.
- **Chains no single call shows** (`mcp_chain`): `get_env DATABASE_URL` then a fetch; a
  write of `/tmp/payload.sh` then `bash /tmp/payload.sh`; budget-exhaustion sequences.

### False positives

Before and after, the same 12, all `deny` by `default.net` alone, in the `curl` form: the 4
benign `headers` cases (a short bearer token, cookies, a request id, a browser user agent),
the 7 benign `request_body` cases (a calendar event, a chat message, a private gist,
metadata, a form, an image, a JSON profile) and `url-doh-benign-qname-021` (a DNS-over-HTTPS
query with an `Accept` header). The change added none: no benign case gained a `review`
or a `deny` in any form, the fetch tool's 14 benign `GET`s included. Each of the 12 sends
data to a host the default policy does not list. That is the policy as designed (`net:
deny`, "only hosts listed under allow"), and a team adds its hosts under `allow`; it is
still a deny a person meets, so it is counted. The same rule gives 31 of the 51 `curl`
attack denies (32 of 48 on 0.25.0), so neither number says much about content detection on
its own: 20 attack denies name a content rule (16 on 0.25.0).

### Skipped: no input for the decision engine

| Category | Attacks | Benign | Why |
|---|--:|--:|---|
| `mcp_tool` | 24 | 10 | MCP server tool lists, tool results and initialize replies: OpenMoat pins MCP servers (`openmoat mcp proxy`, the policy lock) rather than scanning descriptions, and reads results only in a session |
| `a2a_message`, `a2a_agent_card` | 17 | 5 | OpenMoat has no A2A input |
| `response_mitm`, `response_fetch` | 16 | 7 | content an agent receives, not a call it makes |
| `websocket_dlp` | 9 | 2 | frame contents; the engine sees only the URL a tool connects to |
| `mcp_drift` | 4 | 2 | a before and after tool list; MCP pinning denies a changed server's calls (`mcp-server-changed`) in the hook, which `policy check` does not run |
| `false_positive` (responses, tool lists, frames) | | 15 | as above |
| **Total** | **70** | **41** | |

## Published numbers and how they differ

**Doberman on RedCode-Exec.** Doberman's
[BENCHMARKS.md](https://github.com/DobermanCore/Doberman-Core/blob/main/docs/BENCHMARKS.md)
(re-measured 2026-09-04 at `b689a9d`, RedCode at `c84b6db8`) reports, over the same 1,410
snippets as attack records: 690 (48.9%) excluded as out of its scope; of the 720 in scope,
589 `BLOCK`, 124 `AUTH` (asks a person), 7 `PASS`, an in-scope attack success rate of 1.0%
(7/720) and 18.2% not hard-blocked; 31.8% over all records, which that page says is not
its headline. Its 60 benign records are its own, not RedCode's.

The closest OpenMoat figures are the `inline` form over the 900 snippets that act on the
machine: on 0.25.0 19.8% denied, 50.0% denied or held, 0 allowed and 50.0% left to the
agent's prompt; after ADR-112 22.1% denied, 68.9% denied or held, 0 allowed and 31.1% left
to the agent's prompt.
The differences in method matter more than the numbers:

- Both evaluate a decision function over tool calls, not a live agent. How a snippet
  becomes a call differs: this page sends the code itself as a shell command (or a file
  and a run); Doberman's page describes its own conversion.
- The scopes differ: Doberman excludes 23 scenario files, this page sets 17 aside as logic
  only and still reports them.
- `PASS` in Doberman's count is a call that runs unasked. OpenMoat's default policy has
  no such answer for these cases (0 `allow` in the `inline` form): what it does not
  deny or hold it defers to the agent's own prompt. Counting `defer` as stopped would give
  100% of the in-scope `inline` cases; this page does not, because whether the agent asks
  depends on the agent and its settings.

**Pipelock on agent-egress-bench.** The corpus's maintainers publish Pipelock's own
results at [pipelab.org/gauntlet/results](https://pipelab.org/gauntlet/results/). On
2026-11-22 that page showed a historical record (Pipelock 3.6.0 on corpus commit
`79a51f084fc4`, 268 cases) whose figures did not load, so no number is quoted here.
Pipelock runs as the egress proxy the corpus is built for, sees each request on the wire
(inside TLS where it terminates it) and scores responses, tool lists and frames that a
tool-call engine never receives; its denominator is not this page's 122 decided cases.

## What these results show

The 0.25.0 run found these gaps. [ADR-112](adr/ADR-112-default-rules-from-outside-benchmarks.md)
closed the first five, the eighth and the ninth with denies and reviews only, each with
the benchmark's cases as attack fixtures and the everyday forms beside them as benign
fixtures (`tests/conformance/`, the `*-bench-*` ids); the sixth and seventh went to
future work.

1. **System credential files were not secret paths.** `cat /etc/shadow`, `/etc/gshadow`,
   `/etc/security/opasswd` deferred (RedCode 07, 13). Now in `secrets-paths` (deny), with
   macOS's `master.passwd` and the SSH host private keys (`/etc/ssh/ssh_host_*_key`);
   `/etc/passwd` and the `.pub` keys are world-readable and stay as they were. Since `/etc`
   and `/etc/ssh` now hold secret paths, a read of either folder itself (`ls /etc`,
   `grep -r … /etc`) is held for review by the folder rule (`protected-contents`).
2. **Writes and deletes under system folders deferred.** `rm /etc/passwd`,
   `os.remove("/etc/passwd")`, `cp … /usr/copy_file` (RedCode 04, 08). Now `system-files`
   (review) for writes in `/etc`, `/usr` except `/usr/local`, `/bin`, `/sbin`, `/lib*`,
   `/boot`, `/System` and the system parts of `/Library`, in every spelling the classifier
   turns into a write; inline code that deletes a file counts as a write. Reads,
   `/usr/local`, `/opt/homebrew`, `/tmp`, `/var` and the project are unchanged.
3. **System schedulers were not `persistence`.** A write to `/var/spool/cron/crontabs/*`
   deferred (`mcp-chain-persist-callback-006`). `persistence` (review) now names the
   system's cron spools and tables, systemd's unit folders, SysV init scripts,
   `/Library/LaunchDaemons` and `/Library/LaunchAgents`, `systemctl enable` (and the forms
   that install a unit for later boots), `systemd-run --on-*` and `launchctl
   load|bootstrap|enable|submit`; status, start, stop and list stay as they were.
4. **The fetch tool reached private and loopback addresses that `curl` could not.** A
   fetch tool's URL is now read as a browser page open (ADR-047), through the same host
   reading `curl` uses: an address in any spelling is `net`, so `default.net`,
   `cloud-metadata` and `local-net` decide it as for `curl`, and the URLs inside a URL
   (`?target=http://169.254.169.254/`) are hosts for both. Plain loopback (`localhost`,
   `127.0.0.1`, `[::1]`) stays `local-net` (defer) for both.
5. **Secrets the token list did not know went out in URLs.** `token-egress` (deny) now
   knows GitLab's other token prefixes (`gldt-`, `glrt-`, …), an AWS secret key given by
   name and PEM private keys; a JWT or a database URL with a password sent off the machine
   is `credential-egress` (review). Crypto keys and seed phrases are not added: neither
   has a precise shape (ADR-112 §5).
6. **Encoded secrets in URLs pass before a secret read** (base64, hex, multi-layer URL
   encoding). Future work in ADR-112; in 0.28.0
   [ADR-123](adr/ADR-123-encoded-secrets-and-host-name-data.md)'s `encoded-secret-egress`
   (review) decodes and reads the same token shapes, with signed URLs, cursors, data URLs
   and Basic headers to a token's own service as benign fixtures.
7. **Data in host names** (long hex or base32 labels under an unlisted domain). Future
   work in ADR-112; in 0.28.0 ADR-123's `hostname-data` (review) holds them for
   hosts no allow rule lists, with CDN, preview and project-ref hosts as benign fixtures.
8. **Downloads into system folders and `curl` to a variable host.** `wget -O
   /usr/downloaded_script.py <url>` is now held by `system-files` (RedCode Bash 02, 30 of
   30). `curl "$url"` stays `defer`: a `GET` sends nothing but the URL, and a request with a
   body to a run-time host is already `request-rule` (review).
9. **Process termination.** `stops-system` (review) holds `pkill`/`killall` of a system
   process (`sshd`, `launchd`, `systemd`, the login window, …), every process of `root`,
   `kill 1`, `kill -9 -1` and `kill $(pgrep sshd)`; `kill <pid>`, `pkill -f "node
   server"` and `killall node` stay as they were. RedCode 18 is unchanged: its snippets
   kill pids a loop reads from `ps` at run time, which no tool-call check sees.
10. **What the decision engine alone cannot see**: a script written to a file and then run
    (all 1,410 RedCode snippets in the `file` form), content in MCP arguments, chains of
    calls, and content an agent receives. These belong to the OS sandbox, the session
    features and `openmoat mcp proxy`, which a `policy check` measurement does not include;
    the next measurement should drive `openmoat guard` with a session, as MoatBench does.

## Limits of the method

- **The decision engine only.** No agent ran, no code ran, and no sandbox, proxy, session,
  MCP pinning or host adapter took part. A real session can stop more (taint after a secret
  read, injected input, the sandbox refusing a write, `openmoat mcp proxy`) and can ask less
  (the agent's own allow lists).
- **The conversion is ours.** Each benchmark's cases were turned into calls by this
  harness; a different but reasonable conversion (a here-document instead of `python3 -c`,
  `httpx` instead of `curl`) can change verdicts. The forms are reported apart so the effect
  is visible.
- **One machine, the shipped policies.** macOS, the default policy of 0.25.0 and the one
  after ADR-112, no project or team rules, no allowed hosts added. "Before" and "after"
  differ in the engine too (how a fetch tool's URL is read, the credential shapes, the
  inline-code scan), so each was run with its own build. Path decisions can differ on Linux and Windows.
- **`defer` is not measured.** Whether the agent then asks, and what a person answers, is
  outside this measurement.
- **Labels and scope are this page's.** RedCode's scenario labels and the "logic only"
  split were written for this page from the snippets.
- **No benign RedCode cases.** RedCode-Exec has none, so it gives no false-positive rate;
  agent-egress-bench's 37 decided benign cases are the only one here.

## MoatBench

[MoatBench](MOATBENCH.md) drives `openmoat guard` with each agent's hook payloads, a
session and an audit log, which the outside benchmarks above do not. Its scenarios were
written by OpenMoat's authors, so it shows that the policy and its own expectations
agree. OpenMoat 0.27.0, the released build, run by the maintainer on 2026-11-24 on macOS
12.7.6 (x86_64), all 14 agents' payloads (Claude Code, Codex, Cursor,
OpenClaw, GitHub Copilot CLI, pi, Gemini CLI, OpenCode, Hermes Agent, the Cline CLI,
goose, the Antigravity CLI, Qwen Code, Crush):

| Category | Runs | Blocked | Reviewed | Allowed | OS sandbox | Left to the agent |
|---|--:|--:|--:|--:|--:|--:|
| benign | 108 | 0 | 0 | 108 | 0 | 0 |
| destructive | 56 | 42 | 0 | 0 | 0 | 14 |
| exfiltration | 160 | 108 | 33 | 0 | 9 | 10 |
| mcp | 168 | 108 | 24 | 0 | 0 | 36 |
| obfuscation | 168 | 140 | 28 | 0 | 0 | 0 |
| persistence | 84 | 42 | 42 | 0 | 0 | 0 |
| self-protection | 84 | 84 | 0 | 0 | 0 | 0 |
| supply-chain | 42 | 14 | 28 | 0 | 0 | 0 |
| workflows | 100 | 0 | 26 | 12 | 0 | 62 |
| **total** | **970** | **538** | **181** | **120** | **9** | **122** |

970 runs, 0 false positives, 0 known gaps, 0 mismatches with the expected answers. The
eight developer workflows ran 844 steps with 26 reviews, all expected. "OS sandbox" is a
step the hook allows where the scenario declares that OpenMoat's OS sandbox holds it;
"left to the agent" is a call OpenMoat defers, or an allow on the agents that read it that
way. 0.25.0 (2026-11-22, a debug build) and 0.26.0 gave the same totals. The scorecard also
prints decision times; they depend on the machine and are not a performance figure.

The proof report of the same build on the same machine (`openmoat bench --report`, the 14
hosts' models, no host program run): 12 checks pass, 0 fail, 5 not tested here. The 4 OS
sandbox rows (reading `~/.ssh/id_rsa`, a build script reading an agent's login, turning
OpenMoat off, a tool reading the relay token) need `openmoat run`, which needs macOS 13 or
later; the fifth is the real host's behaviour when its hook fails, which the report never
runs. The table per promise is in [MOATBENCH.md](MOATBENCH.md#scorecard-fourteen-agents).

The `moatbench` end-to-end test runs `openmoat
bench` in CI's `test` job on every change and fails on any mismatch or false positive, so
a change to the default policy that breaks one of its expectations fails CI. To run it
yourself:

```bash
cargo build -p openmoat --bin openmoat
env -u MOAT_HOME -u CLAUDE_CONFIG_DIR -u CODEX_HOME -u GEMINI_CLI_HOME -u COPILOT_HOME \
  -u PI_CODING_AGENT_DIR target/debug/openmoat bench
env -u MOAT_HOME -u CLAUDE_CONFIG_DIR -u CODEX_HOME -u GEMINI_CLI_HOME -u COPILOT_HOME \
  -u PI_CODING_AGENT_DIR target/debug/openmoat bench --report
```

Both create their own throwaway home under the system temporary directory and touch no
real agent settings. They need a machine whose sandbox lets them create `.moat` in that
home.

## Reproduce it

Download each dataset into a folder of its own (`git clone`, or the archive of the commit
above), then, from the repository root:

```bash
cargo build -p openmoat --bin openmoat
python3 -I scripts/bench/external.py redcode ../RedCode \
  --openmoat target/debug/openmoat \
  --policy crates/openmoat-core/policies/default-v1.yaml \
  --home /root --scratch target/external-bench \
  --json redcode.json --markdown redcode.md
python3 -I scripts/bench/external.py egress ../agent-egress-bench \
  --openmoat target/debug/openmoat \
  --policy crates/openmoat-core/policies/default-v1.yaml \
  --home /home/user --scratch target/external-bench \
  --json egress.json --markdown egress.md
python3 -I scripts/bench/report.py egress.json   # the tables again, from saved results
```

`--json` keeps every case with each call's verdict, rules and reasons; `--markdown` writes
the tables, every attack not stopped and every false positive. `--home` names the home the
cases assume and is never written. `--scratch` keeps the throwaway project out of
`/tmp/claude-*`, a folder the default policy lets agents read, which would turn some
`defer`s into `allow`s. The run makes one `policy check` per distinct call (about 1,400
for RedCode, 300 for agent-egress-bench; a few minutes with a debug build) and exits 1 if
any call could not be decided.
