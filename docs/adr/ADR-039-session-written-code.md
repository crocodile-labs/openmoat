# ADR-039: Running code the session wrote asks where no OS sandbox holds the command (`session-written-code`)

Status: accepted · Date: 2026-10-27 · Refines ADR-013, ADR-018 and ADR-029

## Context

The hook decides a call from what its command line shows. An agent can write a script
and run it: `Write /p/x.py` is allowed (`project-fs`), and `python3 x.py`, `node x.js`
and `go run x.go` are allowed (`dev-shell`) while `bash x.sh`, `ruby x.rb` and `perl
x.pl` defer. A review against the default policy confirmed that `x.py` can build the
path of `~/.ssh/id_rsa` from pieces (`"~/.s" + "sh/id_rsa"`), read it and send it to an
allowed host. Nothing on the command line names the key, so no deny rule can match.

Where OpenMoat's OS sandbox holds the agent's commands, that does not matter: Claude
Code's `Bash`, every Codex command and Cursor's sandboxed terminal on macOS and Linux run
inside the sandbox `openmoat init` writes from the policy, and `openmoat run` holds the
whole agent; the read of the key is refused by the operating system whatever the script
does (ADR-018). OpenClaw, GitHub Copilot CLI, pi, Gemini CLI, OpenCode and Hermes Agent
have no such sandbox, nor do Claude Code and Cursor on native Windows. There the hook is
the only check, and the write-then-run step is a bypass of every path rule.

The same holds for inline code. `python3 -c 'print(open(os.path.expanduser("~/.s" +
"sh/id_rsa")).read())'`, the `node -e` and `perl -e` equivalents defer: the payload scan
(`shell/commands/payload.rs`) finds no path in them. A built variable name and a built
URL are already denied (`env-dump`, `default.net`), because the scan reads them anyway.

ADR-029 records the files a session writes only when the session read untrusted content,
to follow taint into other sessions. Nothing records what a clean session wrote, and
nothing distinguishes running a file from reading it: `python x.py` and `cat x.py` are
both one `fs.read` of `x.py`.

## Decision

1. **The core knows which files a command runs as code** (`CompiledPolicy::executed`,
   `shell/executes.rs`). The classifier notes, for each simple command it reads, through
   every wrapper and nested shell it already unwraps and in every directory `cd` may
   have moved to: an interpreter's program operand, read with that interpreter's options
   so a value is never the program (`python`/`python3` with `-u`, `-W x`, `-X x`, option
   clusters, `-m <module>` as the working directory's `module.py` and
   `module/__main__.py`; `node`, `-r`/`--import` preloads; `deno run`, Deno 2's `deno
   FILE`; `bun`/`bun run FILE`; `ruby`, `-r ./file`; `perl`; `php`, `-f`; `pwsh -File`;
   `tsx`, `ts-node`; `lua`; `Rscript`; `osascript`; `go run a.go b.go`); a shell's script
   operand and `source`/`.`; the file a shell or interpreter reads its program from (`sh
   < x.sh`); a program named by a path (`./x`, `bin/x`, `/p/bin/x`) or a bare script name a
   runner hands on (`uv run x.py`); and, in inline code, the working directory's modules
   it imports and program files it names (`python3 -c 'import tool'`, `node -e
   "require('./tool')"`, `ruby -e "require_relative 'tool'"`). The engine resolves them
   like every path atom: a glob as the files it names, a `..` where the OS lands, and a
   symlink also as its target (`PathResolver`). It is a side list beside the atoms, as
   `pushes` is, not a new atom kind: no rule matches it and no OS layer is compiled from
   it, so the policy language does not change.
2. **Every session's writes are recorded** (`session_writes`, audit schema 5). For each
   call that may have run, each file it writes by a literal path (`Write`, `Edit`,
   `apply_patch`, an MCP tool's file argument, a shell write: `>`, `tee`, `cp`, `mv`
   destinations, patches, and inline code that writes: code using a write API writes
   every file name it shows as literal text, since the scan cannot bind which one is
   written; conservative, and the same writes then meet `shell-rc`, `kernel-self` and
   `runs-later`; a name it shows only where it writes it is not also code it runs, a
   name it shows anywhere else still is): host, session, path in the lookup form ADR-029 uses (one
   spelling where paths compare without case), the event, and for `Write` the content's
   SHA-256. One row per file, host and session, replaced by a newer write. The rows are
   a lookup, not a record of events: adding one removes rows older than 30 days and all
   but the newest 100 000, so the table stays small.
3. **The guard tightens** (`session_code.rs`), after the session grant and taint and
   before the push check: when the decision is `allow` or `defer` and the call runs a
   file the same host session wrote (recorded, or written by the same command line), and
   no OS sandbox from OpenMoat holds the call, the verdict becomes `ask` with rule
   `session-written-code` and a reason naming the files. "Holds the call" means the call
   came through `openmoat run` (its relay starts the deciding guard with `--relayed`, an
   argument, so no host setting can claim it for a hook outside the run), or the host's
   spec has an OpenMoat sandbox, it applies on this OS, and its settings are in place and
   match the policy and the lock: exactly what `openmoat status` reports as `hook + OS
   sandbox` (`protection::os_sandboxed`). No `Host::<Variant>` branch is involved, and
   the sandbox state is read only when such a file runs. A host that cannot ask denies
   with the `openmoat allow --last` hint, as for every ask (ADR-025).
4. **A session grant answers it** for the exact call, when it was made after the
   session last wrote each file (by audit row, else by time): a rewrite after the grant
   asks again, since the person approved other code. A file written by the same command
   line is shown by it, so a grant for that line answers it. A permanent rule does not:
   the check applies whatever allows the command, and `openmoat allow --last --always`
   says so instead of writing a rule that would change nothing.
5. **Inline code whose names are built is opaque** (`payload/opaque.rs`): code that uses
   a file, network, environment or process API and builds the text it hands them (strings
   joined, interpolated, decoded or formatted, or such a call given a variable) is the
   atom `@opaque-code <interpreter>`, which the default `opaque-code` group asks for. It
   is in the core, not the session-code step: like the other `opaque-code` atoms it is
   about what the classifier cannot read, whatever runs below it, and a here-document fed
   to an interpreter is scanned the same way as `-c`, so the respelling does not escape.

Ask, not deny: writing a helper script and running it is ordinary work, and a person can
see the script before approving it. A file the session did not write keeps its verdict:
`python manage.py`, a checked-out tool, a file a person wrote. Test runners, build tools
and package scripts (`pytest`, `npm test`, `cargo test`, `make`, `go run .`) run the
project's code by design and are not files the command names; they keep their verdict
too.

## Alternatives

- **Extend ADR-029's `provenance` table with a "written" kind.** Its rows are
  append-only by trigger, so the table would grow by one row for every write of every
  session for ever; an older build reads an unknown kind as tainted, so after a
  downgrade every file any session wrote would taint its readers; and a clean session
  would lose ADR-029's "no rows, no lookup" shortcut. A table of its own keeps provenance
  unchanged and is bounded.
- **A new atom kind (`exec`) the policy can name.** It would let a person write rules on
  executed files, but every rule list, the policy compiler and the OS layers would have
  to learn it, which the parser freeze (ADR-013) rules out for a check that only
  tightens.
- **Ask on every host.** Where the OS sandbox holds the command it already refuses what
  the script could do beyond the policy; an ask there adds prompts to the most common
  workflow (write a helper, run it) without adding protection, against ADR-025.
- **Deny.** No way through but editing the policy, for work a person often wants.
- **Read the script and classify it.** A script is a program in any language; reading
  it is the same scan the inline check does, and it would miss what it does not
  recognise. The session-code ask does not depend on understanding the script.

## Consequences

- On hook-only hosts: `write x.py` then `python3 x.py`, `python x.py`, `python3 -u
  x.py`, `node x.js`/`x.mjs`, `go run x.go` (allowed before) and `bash x.sh`, `sh x.sh`,
  `ruby x.rb`, `perl x.pl` (deferred before) ask; `echo … > x.sh` then `bash x.sh` asks;
  `cat > y.sh <<EOF … EOF; sh y.sh` asks; OpenCode 1 denies them with the hint. On
  Claude Code, Codex and Cursor with their sandbox in place on macOS and Linux, and inside
  `openmoat run`, nothing changes. On native Windows Claude Code and Cursor ask, as
  hook-only hosts.
- The three inline commands of the review ask (`opaque-code`); `python3 -c
  'print(1+1)'`, `node -e 'console.log(2)'`, `python3 -c 'import json,sys;
  json.load(sys.stdin)'` and code that hands those APIs literal text keep their verdict.
  A here-document script that opens files through variables now asks too, on every host;
  `openmoat allow --last` answers it for the session.
- Not covered (THREAT_MODEL.md §5): test runners, build tools and package scripts
  running files the session wrote; files another session or a person wrote; files
  written where the hook does not see it (a build's output, a script that writes
  another script, an extracted archive, a download saved under a name the command does
  not show); a module a pre-existing program imports on its own; a program named through
  a variable whose value the line does not show; shells OpenMoat does not parse; a host
  flag that turns its sandbox off at start, which the settings do not show.
- The audit schema moves to 5; a schema-5 log is refused by older builds
  (`SchemaTooNew`), so going back to an older OpenMoat needs a new log, as for ADR-029.
- Performance: each call classifies its command once more for the files it runs (the
  same cost as the push lookup), and a call that runs a file probes one unique index per
  file; the sandbox state is read only when a file the session wrote runs. A call that
  writes files adds one small transaction to the record. The numbers measured for this
  change are in the PR; `scripts/ci/guard-session-latency.py` keeps the budget.
