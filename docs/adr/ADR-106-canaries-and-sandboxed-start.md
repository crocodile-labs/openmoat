# ADR-106: Decoy keys and sandboxed start, two opt-in choices of `openmoat init`

Status: accepted · Date: 2026-11-20 · Builds on ADR-008 (program pins), ADR-020 (the
proxy's secret broker), ADR-034 (hook-only deny groups), ADR-059 (block messages),
ADR-076 (the `openmoat run` command for hook-only agents) · Numbered 106: 104 and 105
are taken by changes open at the time of writing

## Context

Two protections were within reach of every install but asked a person to do something by
hand, so few would:

- **Detection.** OpenMoat denies reads of the credential files it knows
  (`secrets-paths`), but a denied read tells little: an agent may have asked by mistake.
  Nothing told a person that something in a session *went looking for keys*, and a key
  read some way the hook did not see (a process the agent started, a sweep of the home
  directory with `grep -r`) was caught only if its file was a known one. Decoy
  credentials are the usual answer: no real work touches them, so any touch is a signal.
- **Enforcement.** For the agents OpenMoat writes no OS sandbox for (hook-only agents:
  Gemini CLI, OpenCode, Hermes Agent and the others with `RunFacts::Known`), ADR-076 has
  `openmoat status` print the exact `openmoat run` command, and the person has to type it
  every time. Typing the agent's own name starts it with the hook only.

Both touch a person's files outside OpenMoat's directory, and both could disturb normal
work if done carelessly: a fake key where a tool loads keys changes what that tool does,
and a silent `PATH` change changes how every program by that name starts. The product
rules apply: simple setup, ask before any change, show the diff, everything undoable by
`openmoat uninstall`, quiet by default, never silently change how a person's tools start.

## Decision

### 1. Both are questions of `openmoat init`, default no

After the agents' questions, `init` asks each one once, only of a person at a terminal
(`terminal::person_for`): never with `--yes`, in a dry run, without a terminal or with no
person over an existing lock (ADR-102's unattended runs). Enter, the end of input and any
answer but `y`/`yes` are no; `d` shows every file the yes would write, whole. A question
is asked only while there is something to do: a decoy that can be planted, an agent that
can get a shim. A no is not recorded; the next `init` asks again.

```
  Decoy keys       plant 3 fake key file(s) (~/.aws/credentials.bak, ~/.git-credentials.bak, ~/.npmrc.bak) so that any attempt to read or send them is caught? No real file is touched  [y/N/d]
  Sandboxed start  make typing gemini, opencode start it in `openmoat run`'s sandbox? It writes 2 shim(s) to ~/.moat/bin and 2 lines to ~/.zshrc  [y/N/d]
```

### 2. Decoys go beside the real files, at names no program loads

Three targets, a table in `crates/openmoat-cli/src/canary/decoys.rs`:
`~/.aws/credentials.bak` (an AWS access key id and secret), `~/.git-credentials.bak` (a
GitHub token in a git credential URL) and `~/.npmrc.bak` (an npm token). A decoy is
planted only when its folder exists (no folder is made: `~/.aws` is not created for a
person without AWS) and nothing is at its name: the file is created with `O_EXCL`,
owner-only, so it never replaces, appends to or follows a link to anything.

The standard paths themselves (`~/.aws/credentials`, `~/.git-credentials`, `~/.npmrc`)
were rejected even where absent: the AWS tools, git's store helper and npm load them on
their own, so a fake key there changes what a person's tools do (a sign-in that used to
fall through to SSO or instance metadata would fail on the fake). A `.bak` beside the
real file is what a person or a key scanner sweeping a home directory finds, and what an
agent told to "find credentials" lists, and no program reads it unasked. The standard
paths stay covered by `secrets-paths`.

Each value has the shape key scanners look for (`AKIA` and sixteen capitals, `ghp_` and
thirty-six letters, `npm_` and thirty-six) and holds `OpenMoatDecoy` (`OPENMOATDECOY` in
the AWS key id, which allows capitals only) and the git login `openmoat-decoy`, so a
person who finds one knows whose it is; the rest is random per install, so a value seen
on the wire is this machine's. No comment in the files says "decoy": the value says it to
a person, and a file that announced itself would be skipped by what it is there to catch.

The record is `~/.moat/canaries.json` (paths, each file's SHA-256, values): pinned by the
lock as every state file is, and added to `kernel-self`'s `fs.read`, since which files are
decoys is the first thing a key hunter would read.

### 3. Any touch is a deny with rule `canary`

- **Paths.** The guard puts a `deny` group with the decoys' paths (`fs.read` and
  `fs.write`, `hook_only`) first in the policy it decides with
  (`openmoat_core::canary::Decoys::guard`). Every way the engine finds a path finds a
  decoy: a file tool, a shell word, a copy, a link, an MCP argument. First, so a decoy in
  `~/.aws` is reported as `canary`, not `secrets-paths`. Deny is absolute: the group only
  tightens, and a call that names no decoy is decided exactly as before (unit test, and
  the conformance suite decides every fixture again with decoys planted and fails if one
  verdict loosens).
- **Values.** Last in the guard, the whole hook payload (command, URL, file content
  written, MCP arguments) and the action's own texts are searched for every decoy value in
  any letter case (`Decoys::checked_text`, `Decoys::checked`): a value read where the hook
  did not see it is caught when it is sent or written. The proxy refuses any request that
  carries one, to any host, head or body, split across reads or not
  (`Broker::with_decoys`, the same watch as brokered secrets, ADR-020), with rule `canary`.
- **Words and the log.** `canary` is one of OpenMoat's own worded rules (ADR-059): "touching
  a decoy key OpenMoat planted", "no real work reads or sends a decoy, so whatever asked for
  it was looking for keys to take". The values are masked in the audit log as brokered
  secrets are. `openmoat status` and `openmoat doctor` raise the calls of the last week
  that touched a decoy first among what needs attention, naming the latest; `openmoat
  report` counts them; `openmoat watch` shows them as every deny, with those words.

`canary` decides, so it is in `rule_id::BUILTIN_RULES`; the group is never in the policy
file (the paths are this machine's), so `openmoat-core` takes the decoys from the CLI
as it takes every other fact (invariant 7), and adds no dependency.

### 4. Sandboxed start is a shim in OpenMoat's directory and a `PATH` line the person approves

For each agent set up by this `init` whose spec says how to start it in `openmoat run`
(`RunFacts::Known`, ADR-076; the hosts with an OS sandbox of their own have none) and
where `openmoat run` works (macOS 13 and later, Linux; `run_unavailable`,
`run_port_only_network` for a host that needs a `--write` path), `init` writes
`~/.moat/bin/<program>`:

```sh
#!/bin/sh
# OpenMoat: `gemini` starts Gemini CLI in `openmoat run`'s sandbox (ADR-106).
# Written by `openmoat init`; `openmoat uninstall` removes it.
exec '/opt/homebrew/bin/openmoat' run --write '/Users/me/.gemini' -- '/opt/homebrew/bin/gemini' "$@"
```

Both programs are absolute paths found once by `init`: the real agent on the search path
with the shim directory left out, so a shim never finds itself, however `PATH` is ordered
later. The shim is the command ADR-076 prints, nothing more. It cannot be replaced by an
agent: `~/.moat/**` is in `kernel-self`'s `fs.write`, the lock pins every shim the record
(`~/.moat/start.json`) lists, so a changed shim is drift and every call is denied
(`kernel-integrity`), and `status`/`doctor` name a shim that is not what `init` wrote. The
real program's own folder is the agent's to write only where no rule says otherwise; the
usual install folders (`~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`,
`~/.cargo/bin`) are `persistence`'s (ADR-008's reasoning for pins).

The shims change nothing until their folder is first on `PATH`. Rejected: changing `PATH`
silently, a shell function or alias (per shell, invisible in `which`), and replacing the
agent's own program (an update would overwrite it, or it would overwrite the update).
`init` names the start-up file of the person's shell (`$SHELL`: zsh `~/.zshrc`; bash
`~/.bash_profile` on macOS, `~/.bashrc` elsewhere), and on the same yes appends two
lines, after backing the file up as every host file is (`<file>.moat-backup`, recorded as
OpenMoat's):

```sh
# Added by `openmoat init` (sandboxed start); `openmoat uninstall` removes these two lines.
export PATH="$HOME/.moat/bin:$PATH"
```

For another shell it writes the shims and prints the line for the person to add. The
default policy's `shell-rc` rule keeps agents from writing these files; `init` run by the
person, after the question, may. `openmoat status` and `openmoat doctor` say per agent
whether typing its command starts it sandboxed from this shell, or what the shell finds
first.

Only hook-only agents get a shim. Claude Code, Codex and Cursor get their own OS sandbox
from OpenMoat (ADR-018); starting them in `openmoat run` as well needs each one's write
facts, which their specs do not hold yet. That is a later decision, not this one.

### 5. `openmoat uninstall` removes exactly what was written

Each uninstalled agent's shim is deleted while it is what `init` wrote (else kept and
named); with the last shim the two lines go, the file given back from its backup when the
rest is as it was, deleted when `init` created it and nothing else is in it, and otherwise
only the two lines taken out. Uninstalling every agent deletes every decoy that still holds
what was planted (one written to since is kept and named). The records stay, emptied, so
the lock keeps pinning them; `--purge` deletes them with the state directory.

## Consequences

- A person can turn both on with one keypress each, see every byte first and take them
  back with the command they already know. Nothing changes for anyone who says no.
- A decoy touched is the clearest signal OpenMoat gives that a session went hunting for
  keys, and it costs no prompt: the call is denied as a read of any key file is.
- The value check is exact text: a value encoded or split across calls before it is sent
  is not seen (`docs/LIMITS.md`), as for brokered secrets. A read the hook does not see
  (a program the agent started) is caught only when the value is sent or written through
  a checked call or the proxy.
- Inside `openmoat run` the OS sandbox does not deny the decoys' paths (the group is
  hook-only): a process there that reads one is caught when it sends the value through the
  proxy, which is the run's only network.
- The shims carry the paths `init` found: an agent moved or a configuration directory
  changed (`GEMINI_CLI_HOME`) needs `openmoat init` again, which `status` says. An agent's
  own commands that start the same agent inside its sandbox find the shim there, which
  cannot reach OpenMoat's directory from inside, and fail to start.
- `openmoat run` refuses to start outside a project, as before: typing the agent's name in
  the home directory says so; the real program's path is in the shim.
