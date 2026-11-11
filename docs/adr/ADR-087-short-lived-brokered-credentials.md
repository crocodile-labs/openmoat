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
     - id: gcloud
       host: storage.googleapis.com
       header: Authorization
       tls: terminate
       source:
         command:
           run: ["/opt/homebrew/bin/gcloud", "auth", "print-access-token"]
           lifetime: 30m          # the longest one value is used, 1m to 12h
           refresh_before: 5m     # optional: a fifth of lifetime, at least 10s
   ```

   - `run` is the program, absolute or under `~/`, then its arguments; no shell. A bare
     name (looked up in a search path the agent may change), `.` or `..`, and the shared
     temp folders (`/tmp`, `/var/tmp`, `/dev/shm` and their `/private` forms) do not load.
   - **The agent must not be able to change the program.** `openmoat proxy` runs it only
     when both the path in `run` and the file it resolves to are covered by a deny
     `fs.write` rule of the person's policy, or are files only an administrator can change
     (Unix: the file and every folder above it owned by root, writable by no group or other
     user). `openmoat policy lint` warns when no deny rule covers the program.
   - **Pinned by digest.** The proxy takes the program's SHA-256 at start and compares it
     before every run; a changed program is not run and the value is not renewed. It runs
     the resolved file, so re-pointing a link does nothing.
   - **How it runs.** In the proxy's process context (the person's user), with `HOME`, a
     fixed `PATH` (the program's folder, then the system's) and a short list of variables
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
  rather than sending a bearer token, so a value in one header is not enough. The example
  is a bearer token from `gcloud auth print-access-token`, marked as an example.
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
  (Homebrew, a home folder); the default policy only asks before writes there
  (`persistence`). The proxy's refusal names the rule to add.
- Files the program reads or loads (a script's libraries, its configuration) are not
  checked; they need deny rules too (LIMITS.md). The default `secrets-paths` rule covers
  `~/.aws` and `~/.config/gcloud`.
- A program that leaves a child running past its time limit keeps that child, and one
  thread of the proxy waiting on its output, until the child ends: killing the process
  group needs a call the CLI does not make without `unsafe`.
- Updating the program means restarting `openmoat proxy` (or `openmoat run`).
- Proof: unit tests run stand-in programs (an answer, a bare environment, a failure, a
  hang, a flood of output, a control character, a program changed after start, a program
  the agent could change, a link to one), the broker's renewal and expiry, the masks, and
  the refusal of the source by a repository policy; attack fixtures cover the agent
  appending a source to the policy and changing a credential program or its
  configuration. The deadline refusal at a live proxy and a real cloud CLI are not run
  here.
