# ADR-071: the guard trusts its command line and its own binary

Status: accepted · Date: 2026-11-08 · Amends ADR-028, ADR-070

## Context

`openmoat guard` is started by each agent with an environment the agent builds. Until
now that environment chose who decides:

- `MOAT_HOME` picked the state directory, and with it the policy and the lock the call
  is checked against. ADR-070 left this open: a host that builds its hooks'
  environment from a file or setting OpenMoat does not guard could point the guard at
  a directory of anyone's choosing, whose lock is then that person's too.

## Decision

### 1. The state directory comes from the hook's command line

`openmoat init` writes the state directory into every hook it installs, as
`--home <state directory>` after `guard --host <id>`. The lock pins every hook file,
so the argument is pinned with it: changing it is drift.

- **One place.** Every layout builds its command from `openmoat_hosts::GuardCommand`
  (`wire/guard_command.rs`) and recognises one of OpenMoat's by the same function:
  the shell-string layouts (Codex, Cursor, GitHub Copilot CLI, Gemini CLI, Hermes
  Agent, goose), Claude Code's exec form (`args`), the plugins (OpenClaw, OpenCode,
  pi, through a `MOAT_HOME` constant the owned file fills in) and Cline's script
  (`MOAT_STATE`). The CLI builds the command in one method, `HostConfig::guard`, from
  the state directory of the command that located the host.
- **One word, no quoting.** The directory is written as one word no shell changes
  (`sh`, `bash`, PowerShell, `cmd`): ASCII letters, digits and `/ . _ - :` as they
  are, every other byte as `+` and two hex digits (a space is `+20`), with `/`
  separators on Windows too. A plain path such as `/Users/me/.moat` is its own word.
- **The argument wins.** A guard given `--home` takes its state directory from it for
  everything it does (the decision, the record, the budget's deny, the heartbeat),
  whatever `MOAT_HOME` says. A `MOAT_HOME` that names another directory is refused:
  the guard denies the call (exit 2) without opening either directory, and says which
  variable it refused. The same directory spelled with a trailing `/`, or reached
  through a link, is the same directory. A word `init` never writes, or a relative
  path, is refused too.
- **Relayed calls.** `openmoat run` passes its own state directory as `--home` to the
  guard that decides a relayed call outside the sandbox.
- **Existing installs.** A hook written by an earlier release has no `--home`; its
  guard still reads `MOAT_HOME` as before. `openmoat status` and `openmoat doctor`
  report such a hook as out of date until `openmoat init` rewrites it. A hook written
  for another state directory (an `init` under another `MOAT_HOME`) is out of date the
  same way. `openmoat policy upgrade` and `openmoat sandbox sync`, which already
  refresh Codex's entries, write the new form there too.
- **Tests and development homes.** `init` writes whatever state directory it ran
  with, `MOAT_HOME` included, so a test home works as before. A guard started by hand
  without `--home` reads `MOAT_HOME` as before.

### 2. `doctor` shows who may change the state files

The lock pins what the state files hold, not who may change them. `openmoat doctor`
reads the mode and owner of the state directory and of each file in it that decides
or records a call: the lock, the policy and its base, the approvals and allow rules,
the trust, host and environment records, the signers and packs, the audit log, the
proxy key and the proxy CA's key (`commands/doctor/state_files.rs`).

- A file other users may write, or one another user owns, is a problem (exit 64),
  with the `chmod` or `chown` that fixes it: such a file can be replaced under the
  lock by someone who is not the person.
- A file other users may only read is a warning: it gives away the policy or the log.
  So is a symbolic link: whoever may re-point it chooses the file (the lock's digests
  hash the link's target too, so a new target is drift).
  The keys' own refusal rows (`key_file`, ADR-044, ADR-043) already cover readable
  keys, so they get no second warning.
- `--verbose` lists every file's mode and owner (`you`, or the other user's id).
- On Windows the files have access control lists, not Unix modes: one note says the
  check does not run there.

The user the process runs as is the owner of a file it creates in the temp directory
(std has no `getuid`, and the crate forbids `unsafe`).

### 3. The guard checks its own binary

Every re-pin by a person (`init`, `doctor --accept`, `allow`, …) records in the lock
the SHA-256 of the binary the hooks run (`binary_sha256`) and the release it reports
(`binary_version`). The guard compares the file it runs from with that record on every
call, inside the lock check (`integrity/binary.rs`), where it runs the very file the
lock names:

- **Same release, other bytes:** the file was changed in place (patched, truncated,
  replaced by another build of the same version). Every call is denied
  (`kernel-integrity`), and `status` and `doctor` show it with the fix,
  `openmoat init`.
- **Another release:** an upgrade in place. The hooks keep working, as ADR-016
  promises, and `status` and `doctor` say to run `openmoat init` to record it.
- **Not judged:** a lock from before this ADR (reported until `init`), a lock that
  names another file than the one running (a versioned path a package manager is
  replacing, a copy; the existing path checks report those), and a running file that
  no longer resolves (replaced while it started).
- **Latency.** The digest is kept in `binary-hash.json` beside the lock, keyed by the
  file's size, modification time and, on Unix, device and inode; the binary is hashed
  again only when one of those changes. The cache is not pinned: it only saves work,
  and whoever can write the state directory can rewrite the lock too. Debug builds
  compile `sha2` optimised so a test home does not pay seconds per hash.

What this cannot do: a binary changed to skip the check skips it, and a binary
replaced by an older genuine release has no such check. It catches a file changed in
place by something other than a release, and tells a person who upgraded to record the
new binary.

### 4. The relay capability (ADR-070) stays a bearer token

The relay token of `openmoat run` is in the environment of every process in the run's
sandbox, not only the agent's hooks. Binding it to the hook process would need
something the host gives its hooks and not its other children. No supported host does:

- **An inherited descriptor.** Every host starts hooks and tool commands the same way
  (Node's `child_process`, Python's `subprocess`, Rust's `Command`), so a descriptor
  the run passes to the agent reaches both or neither.
- **The peer process.** The run could find which process opened the connection (on
  Linux by the socket's inode under `/proc`; on macOS only through `libproc`, which
  needs `unsafe`). It would learn little: a script can `exec openmoat guard` with a
  payload of its choosing, and is then the same program, with the same parent, as a
  hook the host runs through `sh -c`.
- **A per-call nonce in the hook command.** Hook commands are written by `init` into
  pinned files, not per run; one passed on the command line is readable by every
  process of the same user in the sandbox.

So on every OS the run keeps the bindings of ADR-070 and fails closed outside them:
only the run's own agent and its own sessions are decided, a relayed call leaves no
MCP ticket and no proxy credential, and a guard relays only from the run's sandbox.
What code in the sandbox can still do is add rows to the run's own sessions, each
decided by the policy as the agent's call would be. The run's link row for each agent
session now says so, so a person reading the log knows those rows show what was asked
from inside the run, not that the agent asked it.

## Consequences

- A host's hook environment no longer picks the state directory of an installed
  hook. What is left of ADR-070's last consequence: a hook in the old form, until
  `init` runs.
- The plugins' files and every hook entry change once, so after upgrading, `status`
  shows each agent's hook as out of date until `openmoat init` runs.
- After an upgrade in place, `status` and `doctor` show one note until `openmoat init`
  records the new binary; a binary changed under its own release denies every call
  until then.
- A person who moves the state directory (`MOAT_HOME`) runs `openmoat init` with the
  new one; the hooks name the directory they were installed for.
