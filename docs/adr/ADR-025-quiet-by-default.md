# ADR-025: Quiet by default: OpenMoat blocks what must never happen and leaves every other decision to the agent

Status: accepted · Date: 2026-10-12 · Decided by the owner (0.5.0-rc.1 dogfood week)

## Context

The default policy asked whenever no rule matched (`defaults: "*": ask`). On the first
dogfood day, Claude Code with the default policy recorded **395 decisions in 4 active
hours: 193 allowed, 191 asked (47.75 asks per hour) and 11 denied**. Among the 191 asks:

| asked because no rule matched | calls |
|---|---|
| a read or write outside the session's git root (a sibling repository, the agent's memory folder, its task output) | ~110 |
| `python3 -I script.py` (an option before the script, so `dev-shell` did not match) | 57 |
| inline code (`python3 -c`, `python3 -`) | 20 |
| shell syntax read as actions: loop variables (`$sha`) as `env.read`, `x=…` as `env.set`, `for`/`do`/`done`, `{`/`}` | ~25 |
| `git rebase`, `git -c`, `gh api`, `sed`, `mktemp`, … | ~20 |
| `WebFetch` of documentation (`default.fetch`) | 6 |

None of the 191 asks stopped an attack. The four denies that stopped something real came
from deny rules: `kernel-self`, `env-dump` and `env-secrets`. Each ask repeated a question
the agent itself would put to the person, through Claude Code's permission prompt, auto
mode, or Codex's approval policy. Hosts that cannot ask (Codex, the Continue CLI, Cursor's
file tools) received every ask as a deny. In the owner's words, users would uninstall.

The protection does not depend on those asks:

- deny rules stop secret reads, environment dumps, guard tampering and irreversible
  damage, and the person cannot approve them away;
- the OS sandboxes and `moat proxy` (ADR-018, ADR-020) confine whatever runs, whatever
  the hook said;
- session taint asks when the session has read a secret or untrusted content.

## Decision

1. **New verdict `defer`** (`Verdict::Defer`; `Verdict` is `#[non_exhaustive]`). It means
   that OpenMoat has no objection and does not vouch for the call either, so the agent's
   own permission flow decides. Strictness: `allow < defer < ask < deny`. When the atoms
   of one call are combined, the strictest still wins (ADR-002 is unchanged).
2. **The default policy defers what it does not know.** It sets `defaults: "*": defer`,
   and also `fetch: defer` and `tool.unknown: defer`. `net: deny` stays: an unlisted host
   is still denied. The `installs`, `push` and `local-net` ask groups are removed, so
   those calls fall to `defer`. `ask` stays valid everywhere. A policy that wants the old
   behaviour writes `defaults: "*": ask`.
3. **`unparseable` follows the policy.** Input that cannot be classified gets the
   policy's catch-all default, raised to `defer` if it is `allow`. It is never `allow`, and
   it is `ask` again under a policy whose default is `ask`.
4. **A word that only looks like a host is not network evidence.** A host found in a
   shell word with no scheme, outside the arguments of a program that names hosts
   (`curl`, `wget`, `ssh`, `scp`, `sftp`, `rsync`, `nc`, `ncat`, `netcat`, `telnet`, `ftp`,
   `ping`, `dig`, `nslookup`, `host`, `git clone`/`fetch`/`pull`/`push`/`ls-remote`), is a
   new atom, `AtomicAction::NetWord { host }`.
   - `net` rules match it like `net`, so a host the policy denies or allows is still
     denied or allowed.
   - When no rule matches, it gets the catch-all default (`defer`), not `defaults.net`.
   - Session taint treats it as `net`.
   - The hook alone decides it: no OS layer receives it, and those layers deny unlisted
     hosts when a program connects.

   This replaces the case-by-case patches (`FILE_EXTENSIONS`, the `_` rule, #495's call
   rule), which stay in place to decide whether a word is a host at all.
5. **What each host receives for `defer`:**

   | host | output |
   |---|---|
   | Claude Code, Codex, Continue CLI | no decision: exit 0, empty stdout, so the host's normal permission flow runs |
   | Cursor `beforeShellExecution`, `beforeMCPExecution` | `ask` (Cursor's own prompt) |
   | Cursor `preToolUse`, `beforeReadFile` | `allow`: these events have no "no decision" and cannot prompt; Cursor's own settings and sandbox still apply |

6. **OS layers treat `defer` as not allowed**, exactly as they treat `ask` (ADR-019,
   lowering never widens). The generated sandboxes do not change.
7. **Audit and approvals.** A deferred call is recorded with verdict `defer` (audit
   schema version 3 widens the `verdict` check). `moat`, `moat allow --last` and the
   home screen's pending list show only `ask`: a deferred call was answered by the
   agent's own prompt. `moat report` counts `deferred` apart from `asked`. The dogfood
   metric becomes the number of asks per active hour, with a target of 0 in normal work.

## Consequences

- With the default policy, OpenMoat shows no prompt of its own in normal coding work.
  The agent asks as it would without OpenMoat. OpenMoat's `allow` still answers for the
  calls it knows are safe, so with OpenMoat installed the agent prompts **less** than
  without it.
- `ask` now means "OpenMoat itself needs the person": session taint, or a rule the user
  wrote. Each one is rare, so each one is read.
- Hosts that cannot prompt no longer turn every unknown command into a deny.
- Security: every deny rule, the sandboxes, the proxy and session taint are unchanged.
  The only calls that used to be held and now are not are those that matched no rule.
  The agent's permission flow sees them, and the OS layers confine them when they run.
  In auto mode that flow is a model classifier, not a person. The deny rules and the OS
  layers are what OpenMoat guarantees; they were never the asks.
- Breaking for policy files: none fails to load, and an older policy keeps its own
  `ask` defaults. `moat policy upgrade` offers the new defaults like any other
  default-policy change. Library users who match on `Verdict` already need a wildcard
  arm (`#[non_exhaustive]`).
- Conformance fixtures whose expected verdict was `ask` with rule `default`, `default.*`
  or `unparseable` move to `defer`, and those for `installs`, `push` and `local-net`
  move to `defer` with rule `default`. Attacks and denies do not change.

## Not decided here

- Widening `dev-shell` so that more safe calls are `allow` (options before a script,
  shell variables, loops) is a separate change. It reduces the agent's own prompts too.
- Reads and writes outside the git root (sibling repositories, the agent's own folders)
  defer under this ADR. Whether to allow some of them is open.
