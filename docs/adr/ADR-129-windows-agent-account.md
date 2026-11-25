# ADR-129: Windows `openmoat run` as a dedicated local account: the network and reads held

Status: proposed · Date: 2026-11-25 · Builds on ADR-115 (the write-restricted Windows
tier), ADR-124 (why the network and reads waited for this), ADR-083 (the state directory's
access list), ADR-089 (the run's boundary record), ADR-108 (protection score), ADR-117 (the
code gate) · Extends ADR-124 §Decision 2 and 3

## Context

ADR-115's Windows tier holds writes and the process tree and scores 55: `wfp_network` (30)
and `windows_read_deny` (15) are missing. ADR-124 found why both need an account that is not
the person's:

- A Windows Filtering Platform (WFP) filter can match a process only by its executable, its
  package or its *user*: `FWPM_CONDITION_ALE_USER_ID` checks the connecting process's token
  against a security descriptor. The run's write-restricted token is the person's own user,
  so a user condition would match the person's every program, or nothing.
- A write-restricted token is checked on writes only, so it can deny no read; a deny entry
  for the person's own SID denies the person's own programs too.

Both work as soon as the agent runs as a different user, which is the shape Codex's elevated
Windows sandbox ships. Creating that user and adding a persistent WFP filter need
administrator rights once; starting a process as that user afterwards needs only its
password (`CreateProcessWithLogonW`, the Secondary Logon service), not elevation.

## Decision

### 1. A setup, once, by an administrator

`openmoat agent-account setup`: refused unless run by a person from an interactive terminal
and elevated (it says to run it from an administrator terminal), behind the code gate when
one is set up (ADR-117), recorded in the policy-change ledger. On other systems it exits 64
and says that `openmoat run` there needs no account. It:

1. Creates a local account `openmoat-<person>` (`NetUserAdd`, `USER_PRIV_USER`) with a random
   password of 32 bytes from the system's generator, which no one is shown, and takes it
   out of `Users`, so it holds only what is granted to `Authenticated Users` and `Everyone`
   and to it by name. Logon rights (`LsaAddAccountRights`): interactive logon only, which the
   Secondary Logon service needs; network, remote-desktop and service logon denied. The
   account is hidden from the sign-in screen.
2. Keeps the password encrypted with DPAPI for the person (`CryptProtectData`, user scope) in
   `~/.moat/agent-account/`, a folder of the state directory, so only the person's own
   logon can decrypt it and `kernel-self` already denies an agent's call that reads it.
3. Grants the account read and run (inherited) on the person's profile folder, and an
   explicit deny of every access on `~/.moat`. Windows sets the inherited entry on every file
   of the profile once, which takes time in a large profile; the setup says so and shows
   progress.
4. Installs a persistent WFP provider and sublayer owned by OpenMoat and, at
   `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`_V6`, `ALE_AUTH_LISTEN_V4`/`_V6` and
   `ALE_AUTH_RECV_ACCEPT_V4`/`_V6`, block filters whose `FWPM_CONDITION_ALE_USER_ID` names
   the account, with one permit: a connection to `127.0.0.1` or `::1` on a port of a fixed
   range of eight that setup chooses and records, where runs place their proxy. Raw sockets
   already need administrator rights.
5. Writes `agent-account.json` in the state directory: the account's SID, the port range,
   the provider's and filters' keys and the profile entries added, so `remove` undoes
   exactly them.

`openmoat agent-account status` reads the record back against the system (account,
rights, filters present and enabled, profile entries) and exits 1 on drift.
`openmoat agent-account remove` (elevated, person-only, gated) deletes the filters, sublayer
and provider, the profile entries, every per-run entry the record names, the account and
its profile folder, then the record.

### 2. A run under the account

When `agent-account.json` is present and `status` finds no drift, `openmoat run` on Windows
starts the agent as the account instead of under ADR-115's restricted token. Without it the
run is ADR-115's, as now, and its record and `--print-boundary` name the setup command as
what would hold the network and reads.

- **Start.** `CreateProcessWithLogonW` with the decrypted password, `LOGON_WITH_PROFILE`,
  `CREATE_SUSPENDED`, the command line built as in ADR-115 §8 (no batch files). The process
  is put in the run's job object, and the launch check reads back its token's user (the
  account's SID) and its job membership before it runs an instruction; anything not
  confirmed ends it. The password is cleared from memory once the call returns.
- **Environment.** ADR-105's scrubbed environment, keeping the person's `USERPROFILE`,
  `HOME`, `APPDATA` and `LOCALAPPDATA`, so the agent finds its settings where they are, and
  `safe.directory` for the project in the git variables the run already sets (the project is
  owned by another user, which git otherwise refuses).
- **Writes.** The write roots of ADR-115 §2 (the policy's literal write trees, the run's temp
  directory, `--write` paths, the agent's own state folder from its host spec) get one
  inherited allow entry for the account; the write denies of ADR-115 §3 get deny entries for
  it. Everything else in the profile is read-only to the account; outside the profile the
  system's own access lists apply, as for any standard user.
- **Reads.** The policy's read denies that name a literal place (`~/.ssh`, `~/.aws`, other
  agents' credentials, the person's browser profiles) get a deny entry for the account on
  that place, except the running agent's own folder, as the Linux and macOS profiles except
  it. A glob no single place stands for stays the hook's, and the record names it. The run
  reconciles these entries: the ones for the account that the current run does not need
  are removed first, so a run for another agent does not inherit the last one's.
- **Network.** The proxy listens on the first free port of the recorded range and checks it
  bound that port itself; the proxy variables point at it. Every other connection the
  account's processes make, and every listen, is refused by the filters, whether or not a
  program honours the variables. The record's network mode is `wfp_account`.
- **What it does not hold, stated.** Name lookups go through the system's DNS Client service,
  which resolves under its own account, so a lookup an agent asks for leaves the machine
  (the same gap the macOS profile has through `mDNSResponder`); the record names it as a
  `dns` downgrade. Secrets the person keeps in Windows Credential Manager are not the
  account's, so an agent that keeps its login there signs in again inside the run. Another
  local user's processes on the permitted ports are reachable; the range is outside the
  ports common servers use.
- **The hook.** A hook the agent runs, runs as the account and cannot write the audit log;
  the guard relays its call to the run (ADR-115 §9) when its token's user is the account's
  SID recorded at setup, a fact a variable or setting cannot fake.

### 3. Score and claims

`wfp_network` and `windows_read_deny` count only after the launch check confirms the account
and `status` confirms the filters; then a Windows run scores 100 less its named downgrades
(`dns`). `sandbox.strict: true` and `require.run: full-boundary` accept such a run.
`docs/PROTECTION.md`'s Windows rows stay *preview* until a test runs a real agent under the
account.

### 4. Tests

CI's `windows-latest` runner is elevated, so its end-to-end tests run `setup`, then a run
whose program tries a connection to an outside address (refused), a fetch through the proxy
(allowed), a listen (refused), a read of a denied file in the profile (refused), a read of
an allowed one (works), a write outside the roots (refused), and `remove`, after which
`status` finds nothing. A test from an unelevated token checks that `setup` refuses and
says how to run it, and that a run without the account is ADR-115's with the setup named.

## Consequences

- Windows gets the network and reads held by the system, on the person's opt-in, with one
  elevated step; the everyday `openmoat run` stays unelevated.
- The machine changes in named, undoable ways: one hidden local account, its profile, a
  persistent OpenMoat WFP provider, an inherited read entry on the person's profile, and
  entries on the project and the denied places. `remove` takes them out; `status` shows them.
- Files the agent creates are owned by the account; the person keeps full access through the
  project's inherited entries.
- Built in two steps, each its own change: (1) setup, status, remove and runs as the account
  (writes and reads); (2) the WFP filters and `wfp_account` network mode.
