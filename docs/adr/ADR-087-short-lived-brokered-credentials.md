# ADR-087: Short-lived brokered credentials: a `command` source with a lifetime

Status: accepted (the feature is a preview: no cloud CLI has been run through it in a real
session yet) · Date: 2026-11-11 · Builds on ADR-020 (egress proxy and secrets broker),
ADR-027 (run proxy credentials), ADR-043 (TLS termination for brokered secrets), ADR-044
(standalone proxy sessions)

## Context

OpenMoat's broker keeps secrets out of the agent's reach and injects them only into
requests to their host (and, with `allow` rules, only into named requests). Its sources
are `env`, `file` and `keychain`, read once when `openmoat proxy` starts; a source that
cannot be read stops the proxy (POLICY.md §2.1). The values are usually long-lived tokens,
so a leak through an allowed path (the broker's leak and echo checks notwithstanding)
stays useful for as long as the token lives.

Vercel issues "short-lived, non-persistent tokens" and lets a process point at a rotating
token file (`VERCEL_OIDC_TOKEN_FILE`) that is re-read on each call, where "An unreadable or
empty configured file causes an error rather than a fallback" (https://vercel.com/docs/oidc).
Its sandbox firewall injects credentials at the boundary so "The secrets never enter the
sandbox" (https://vercel.com/docs/sandbox/concepts/firewall). OpenMoat already does the
second part; short lifetimes are the gap.

A source that runs a program is a new kind of power: the program runs as the person,
outside every sandbox, and what it prints goes into requests. Whoever can change the
program, or name it, runs code as the person.

## Decision

1. **`source: command`.** A secret may name a program and arguments the person chose:

   ```yaml
   secrets:
     - id: vault
       host: vault.example.com
       header: X-Vault-Token
       tls: terminate
       source:
         command:
           run: ["/usr/local/bin/vault", "token", "create",
                 "-address=https://vault.example.com", "-ttl=15m", "-field=token"]
           lifetime: 15m          # the longest one value is used, 1m to 12h
           refresh_before: 3m     # optional: a fifth of lifetime, at least 10s
           home: user             # optional: the person's HOME, not an empty one
   ```

   - `run` is the program, absolute or under `~/`, then its arguments; no shell. A bare
     name (looked up in a search path the agent may change), `.` or `..`, and the shared
     temp folders (`/tmp`, `/var/tmp`, `/dev/shm` and their `/private` forms) do not load.
   - **The agent must not be able to change the program.** `openmoat proxy` runs it only
     when the path in `run`, the file it resolves to and every folder above that file, up
     to the person's home (on Windows, up to the drive's root), are each covered by a deny
     `fs.write` rule of the person's policy (a folder together with anything put in it),
     or only an administrator can change them (Unix: owned by root, writable by no group
     or other user). The folders count because the agent could put a file beside the
     program, or rename a folder and put another in its place. `openmoat policy lint`
     warns when no deny rule covers the program.
   - **Scripts.** A file that starts with `#!` names its interpreter, which must pass the
     same check, must not be a script itself, and is pinned with the program; an
     interpreter that is not an absolute path, or is `env` (which searches `PATH`), is
     refused.
   - **What is not pinned.** Files the program loads or reads once it runs: a script's
     modules, a program's libraries and plug-ins, its configuration. A tool made of many
     files the person can write (Google Cloud's `gcloud`, a shell script that starts
     Python, which loads the SDK's modules) is outside what this check can hold, so the
     example is a tool that is one program file.
   - **A deny rule is proof only outside what a sandbox grants.** Landlock cannot hold a
     deny inside a folder it grants for writing, so a deny rule counts only for a path
     outside the project and outside `openmoat run`'s write roots (its temp folder and
     `--write` folders); inside them only root ownership counts. The standalone
     `openmoat proxy` knows the project of the folder it was started in.
   - **Pinned by digest, and the hashed bytes are what runs.** At start the proxy reads
     the program once, hashes those bytes and writes them to a private copy in
     `secret-programs/` under its state directory (an owner-only folder and file, which
     `kernel-self` keeps from the agent); it runs that copy, never the file at the path,
     which could be swapped between the hash and the start. Before every run it checks the
     copy's digest, the program's at its path and the interpreter's; any change stops the
     runs and the value is not renewed. The copy is removed when the proxy ends. A program
     that finds its own files beside its executable (not by its path in `run`, which is
     its `argv[0]`) does not find them from the copy.
   - **Where it starts.** In `/` (Windows: `%SystemRoot%`), not in the proxy's working
     folder, which is the agent's project: Git, tool shims and per-folder configuration
     there would let the agent run code through the program.
   - **Its home.** `HOME` is an empty owner-only folder of its own under OpenMoat's state
     directory (`secret-homes/<id>`), which `kernel-self` keeps from the agent, so no
     dotfile is read. `home: user` gives it the person's home instead, for a tool that keeps
     its login there; it then reads files the agent may be able to change unless deny
     rules cover them.
   - **How it runs.** As the person's user, with that `HOME`, a
     fixed `PATH` (the system's folders only: the program's own folder would find a
     `python3` planted beside it before the system's) and a short list of variables
     (`USER`, `LOGNAME`, `LANG`, `LC_ALL`, `TMPDIR`, `TZ`; the profile and system folders on
     Windows), no input, error output dropped, in its own process group on Unix (no
     terminal), a 30-second limit and at most 64 KiB of output.
   - **Output.** The value alone, or `{"value": …}` with `expires_in` (seconds) or
     `expires_at` (Unix seconds); unknown keys, an empty value, a control character and
     an answer that expires within 10 seconds are refused. The shorter of that expiry and
     `lifetime` wins. No error quotes the output.
   - Values are held in memory only (zeroized on drop), never written to disk or to the
     audit log.
2. **Refresh outside the request path.** A thread of the proxy runs each program once the
   value is within `refresh_before` of its deadline, and again every 15 seconds after a
   failure, which it reports on standard error with the secret's id and the reason. Before
   a renewed value is used, the audit writer is given masks for it (the last five values
   of each secret, and the fixed ones). The broker keeps the four values a secret replaced
   for its leak and echo checks: a replaced token may still be valid.
3. **Fail closed at the deadline.** A value has a deadline on the monotonic clock and on
   the wall clock, and is past it when either says so (a machine's sleep does not count on
   the monotonic clock everywhere; the wall clock can be set back). A request that would
   get a value past its deadline is refused before anything is sent, with a deny row
   `proxy-secret-expired` naming the secret, never the value. A value that expires between
   that check and the injection is left out, not put in.
4. **Start-up.** A `command` source that fails at start stops the proxy, as other sources
   do.
5. **Agents cannot add or run sources.** `secrets:` is read from the person's policy only:
   a repository policy and a signed pack cannot declare one (their schema has no
   `secrets:`), `kernel-self` denies the agent writing the policy, and the lock check stops
   the proxy if the policy changed. `openmoat guard` never runs a `command` source and does
   not mask its value; audit delivery refuses one as a key source; Claude Code's broker is
   never given one (`sandbox show` and `doctor` list it as handled by `openmoat proxy`).

## What this must never do

- Run a source command from `openmoat guard` or block a hook decision on it (R1).
- Run a command named by a repository policy or a pack.
- Run a program the agent can change, by the policy's rules or by the system's.
- Fall back to an expired or previous value.
- Log, print or store the value, or quote the program's output in an error.

## Corrections to the draft

- **Shape.** A source is one key (`env`, `file`, `keychain`), so the draft's
  `source: { command: [...], lifetime: … }` cannot be read; the command's settings sit
  under `command:` with the argument list as `run`.
- **The example.** The draft's AWS example could not work: a secret's host is one exact
  name (`*.amazonaws.com` does not load), and AWS signs each request (Signature Version 4)
  rather than sending a bearer token, so a value in one header is not enough. A first
  revision used `gcloud auth print-access-token`; a security review found that `gcloud`
  is a script whose Python and modules load from folders the person can write, which the
  pin does not hold, so the example is now Vault's CLI, one program file, making a child
  token with a 15-minute lifetime.
- **Pinning.** ADR-008 pins programs by path, not content, and `policy.lock` pins files the
  guard checks on every call; a changed cloud CLI there would deny every call until
  re-pinned. The proxy pins the digest itself, for its own life, and the rule that the
  agent must not be able to change the program covers the time between proxy runs.
- **Who may change the program.** The draft did not say. This was the main attack: a
  policy pointing at a file the agent can write. Added: the deny `fs.write` or
  administrator-only rule, the shared-temp refusal, the link and resolved-file check.
- **Placeholder on expiry.** The draft sent the request with the placeholder. It is refused
  instead: the server would answer to a credential it does not have, and the person would
  not see why; the refusal is recorded.
- **Output contract.** AWS's `credential_process` JSON holds several values and is not a
  header value, so it is not followed; the contract is `value` with `expires_in` or
  `expires_at`.
- **Upper bound.** `lifetime` is bounded, 1 minute to 12 hours, rather than defaulting to
  an upper bound.
- **Rotated `file` source** (draft step 2) is not built here: a `command` source covers a
  tool that prints a token, and `file` re-reading needs its own checks (a file the agent
  can replace between reads). The export mapping (draft step 4) waits for ADR-086.

## Consequences

- A token from a cloud CLI can be brokered with a lifetime of minutes. When the CLI fails,
  requests that need the token are refused once it expires, and the audit log says so.
- The person must add a deny `fs.write` rule for a program they installed themselves
  (Homebrew, a home folder), covering its folders up to their home (`/opt/homebrew/**`,
  which also stops the agent installing with Homebrew); the default policy only asks
  before writes there (`persistence`). The proxy's refusal names the rule to add.
- Files the program reads or loads (a script's modules, a program's libraries, its
  configuration) are not checked or pinned; they need deny rules too (LIMITS.md). The
  default `secrets-paths` rule covers `~/.aws`, `~/.config/gcloud` and `~/.vault-token`.
  Tools made of many such files are poor sources.
- On macOS and Linux the program's whole process group is killed when the run ends,
  at the time limit or after it answered, so a child it left behind does not outlive the
  run; its output is read on the calling thread with a deadline (`poll`), so no thread
  waits on a pipe such a child holds (`rustix`, no `unsafe`). A child that leaves the
  group (`setsid`) is not ended. On Windows only the program is killed, and a child that
  holds its output keeps one thread of the proxy waiting until it ends (LIMITS.md).
- Updating the program means restarting `openmoat proxy` (or `openmoat run`).
- Proof: unit tests run stand-in programs (an answer, a bare environment, a failure, a
  hang, a flood of output, a control character, a program changed after start, a program
  the agent could change, a link to one), the broker's renewal and expiry, the masks, and
  the refusal of the source by a repository policy; attack fixtures cover the agent
  appending a source to the policy and changing a credential program or its
  configuration. The deadline refusal at a live proxy and a real cloud CLI are not run
  here.
