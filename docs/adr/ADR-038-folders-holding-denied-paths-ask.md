# ADR-038: Reading or writing a folder that holds denied paths asks (`protected-contents`)

Status: accepted · Date: 2026-10-26 · Refines ADR-002 and ADR-013

## Context

The shell classifier has no notion of "recursive". `ls D`, `cp -r D x`, `grep -r . D`,
`tar czf a.tgz D`, `zip -r a.zip D` and `rsync -a D x` all become one `fs.read` of `D`,
and a rule matches only when one of its patterns matches `D` itself. A pattern ending in
`/**` matches its folder too (`~/.ssh/**` matches `~/.ssh`), but many deny patterns name
files: `agent-credentials` lists `~/.codex/{auth.json,.credentials.json}`, the Gemini
CLI, GitHub Copilot CLI, pi, Hermes Agent, OpenCode and OpenClaw logins in the same way,
and `secrets-paths` lists `~/.docker/config.json`, `~/.config/containers/auth.json` and
`~/.config/doctl/config.yaml`. A review run against the default policy observed
`cp -r ~/.codex /p/x`, `grep -r token ~/.gemini`, `tar czf a.tgz ~/.hermes`,
`rsync -a ~/.local/share/opencode /tmp/o`, `cp -r ~/.pi/agent /p/p`,
`zip -r a.zip ~/.copilot`, `cp -r ~/.openclaw /p/o`, `cp -r ~/.docker /p/d` and
`grep -r x ~/.config/containers` all **defer** (`default`): one command copies out the
very files the deny names. For the agents that only have the hook (OpenClaw, GitHub
Copilot CLI, pi, Gemini CLI, OpenCode, Hermes Agent) that is the whole check.

The same shape held for writes: an extraction (`tar xf e.tar -C DIR`, `unzip e.zip -d
DIR`) writes files whose names are inside the archive, into a folder whose own deny,
if any, names files below it.

## Decision

- When the policy is compiled, the engine collects for every **deny** group, `hook_only`
  ones included, the literal folder of each non-negated `fs.read` pattern and, separately,
  of each `fs.write` pattern, in every spelling the group's globs are compiled with (both
  home spellings, moved host directories, ASCII-lowercased when paths compare without
  case). The literal folder is the pattern's text before its first glob character (`*`,
  `?`, `[`, `{`, `\`, or a non-ASCII character), cut back to the last `/`. A pattern with
  no such folder, or only a filesystem root (`**/.env`, `**/.claude/settings.json`, `/`),
  adds nothing.
- An `fs.read` of a folder that is one of those read folders or an ancestor of one, and
  an `fs.write` of a folder that is or holds one of the write folders, adds an **ask**
  with the engine rule id `protected-contents` and a reason naming the folder and the
  rules (`reads a folder that holds paths `agent-credentials` denies: /Users/me/.codex`).
  It is merged like every other atom's decision: strictest wins, so a deny on the folder
  itself stays a deny, and it never allows anything.
- The ask is added whatever allows the folder: a user rule allowing `~` or `~/**` no
  longer allows `cp -r ~ /backup` silently.
- The classifier also models destinations it used to read: `tar -x … -C DIR` and `unzip
  … -d DIR` write `DIR` (the working directory without one), and `git checkout
  [<tree-ish>] [--] <path>…` writes each path, as `git restore` already did. These are
  plain `fs.write` atoms the existing rules (`kernel-self`, `git-internals`,
  `runs-later`) decide.

Ask, not deny. Copying `~/.codex` to a backup disk, or listing `~/.gemini` to see which
version is installed, is a legitimate thing for a person to do; the person sees the
whole command and answers it, and `openmoat allow --last` answers it for the session.
A host that cannot ask (Codex, OpenCode 1) already turns an ask into a deny that names
`openmoat allow --last` (ADR-025), so there the copy is refused until a person approves
it. The files themselves stay denied whatever the answer: `cat ~/.codex/auth.json` is
still `agent-credentials`.

## Alternatives

- **List each folder in the deny rules** (`~/.codex`, `~/.gemini`, …). Closes the
  observed commands only for the folders someone remembered, makes `ls ~/.codex` a deny
  no person can approve, and every new agent or secret file needs the same care.
- **Deny instead of ask.** Strictest, but a person's backup or inspection of an agent
  folder would have no way through but editing the policy.
- **A recursive flag in the classifier**, so only `cp -r`/`grep -r`/`tar c` of the
  folder would count. Tells `ls ~/.codex` from `cp -r ~/.codex`, but it needs a new atom
  field and per-program option tables for every recursive reader (`rsync -a`, `zip -r`,
  `rg`, `find`, `du -a`, `tar` without `-r`, …), which the parser freeze (ADR-013) rules
  out; a missed program would be a bypass, while the folder rule has none to miss.

## Consequences

- Every command above asks, in every spelling of the folder (`~/.CODEX` on macOS, a
  moved `CODEX_HOME`). `tar xf e.tar -C ~/.claude` and `unzip e.zip -d ~/.moat` are
  denied by `kernel-self`; `git checkout main -- .github/workflows/ci.yml` asks
  (`runs-later`).
- Common commands that now ask: `ls ~/.codex`, `ls ~/.claude`, `ls ~/.gemini`,
  `ls ~/Library` (`~/Library/Keychains/**`), `ls ~/.cargo` and `du -sh ~/.cargo`
  (`~/.cargo/credentials`) and `ls ~/.m2`. The home folder and the folders above it
  (`/`, `/Users`) are left out: they hold every protected path, so `ls /`,
  `find / -name x` and a word that is the bare path `/` (`tr '/' '_'`) keep their
  verdict, a read of `~` still asks (`home-sweep`) and a write of it is still denied
  (`destructive`). `tar xf e.tar` run in `~` and
  `tar xf e.tar -C ~` are denied by `destructive`, which denies writing `~` itself.
  Folders below the literal one (`ls ~/.codex/sessions`, `ls ~/.cargo/registry`) keep
  their verdict.
- Inside a project nothing changes with the default policy: its deny rules name project
  files only through `**` patterns, so `grep -r TODO .` stays allowed even when the
  project holds a `.env`. A repository policy's deny on `${project}/secrets/**` makes a
  recursive read of the project ask, which is what it asks for.
- `openmoat allow --always` does not answer this ask: the permanent rule it writes is an
  allow, and the ask is added whatever allows the folder. A session grant does.
- Performance: the folders are collected once per compiled policy (a few hundred short
  strings for the default policy); an `fs` atom is a prefix scan over them. Compile time
  (about 6.4 ms) and the decision time of a mixed set of commands were unchanged within
  noise in a release build.
- OS layers are unchanged: they already deny or allow the files themselves.
