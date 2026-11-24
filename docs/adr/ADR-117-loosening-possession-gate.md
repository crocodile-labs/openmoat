# ADR-117: A possession factor on every loosening, and a policy-change ledger

Status: proposed · Date: 2026-11-23 · Builds on ADR-022 (repository policy), ADR-101
(keyed audit chain), ADR-110 (signed audit checkpoints), ADR-111 (never-widen check)

## Context

Every command that widens or re-pins the protection (`openmoat allow`, `trust`,
`edit`, `doctor --accept`, `mcp accept`, `hooks accept`, `policy upgrade
--accept-widening`, `policy install`, `uninstall`, …) refuses to run without a
terminal and when an agent host is among its parent processes (`terminal.rs`,
AGENTS.md §7). That check answers "is there a terminal, and did no agent start this",
not "is the person here". A process that gets a line typed into the person's own
terminal, or that starts the command detached from the agent under a
pseudo-terminal (so its parent is `launchd` or `init`, not the agent), passes it. So
does malware running as the user. Once past it, one command loosens the policy, and
the audit log shows the change only as a re-pin.

Other tools gate loosening on something the person holds: Doberman keeps a
raise-only rule ledger whose every lowering needs a TOTP code. A code from a phone
is a second factor an agent that only controls the terminal does not have.

`ring`, already in the build for TLS and the audit checkpoints, has HMAC-SHA-1
(`HMAC_SHA1_FOR_LEGACY_USE_ONLY`), which RFC 4226/6238 codes need. No crate in the
build reaches macOS `LocalAuthentication` (Touch ID): `security-framework` is in the
lock only through `rustls-native-certs` and wraps the Keychain, whose biometric
access control needs the data-protection keychain and a signed binary with a
keychain entitlement, which `cargo install` builds do not have.

## Decision

1. **An opt-in TOTP factor, enrolled by a person.** `openmoat gate setup`
   (person-only, as every command in AGENTS.md §7) makes a 160-bit random secret,
   shows it once as an `otpauth://totp/OpenMoat:policy-changes?…` URI and as base32
   text in groups of four, and writes it only after the person types a code their
   authenticator app gives for it, so a mistyped key never locks them out. RFC 6238
   with the defaults every app takes: HMAC-SHA-1, 30-second steps, six digits,
   `T0` = 0; codes of the step before and after now are taken too. It never prints
   the secret again. `openmoat gate status` says whether the gate is on;
   `openmoat gate remove` asks for a code, then removes it. Setting up over an
   existing secret is refused: moving to another app is `remove` (with a code of the
   old one) then `setup`.

2. **Where the secret is.** `~/.moat/audit.key.gate`, kept as the audit signing key
   is (ADR-110): written once and owner-only through a temporary file
   (`home::write_private_new`), refused when others may read or replace it
   (`key_file::read`; `openmoat doctor` names it), and named under the audit key so
   `kernel-self`'s `fs.read: ~/.moat/audit.key*` denies it to agents with no change
   to the default policy (the conformance fixtures `T9-read-the-gate-secret`,
   `T9-cat-the-gate-secret`, `T9-remove-the-gate-secret` and
   `T9-reset-the-gate-state` hold that), as do the host sandboxes generated from it.
   The gate's state, `~/.moat/gate.json`, holds the last step a code was taken for
   and the times of recent wrong codes; `kernel-self`'s `~/.moat/**` keeps agents
   from writing it. A state file that does not parse is refused, not read as empty.

3. **Every loosening asks, once enrolled.** `gate::pass(home, command)` runs after
   the existing terminal check, and after the command's own questions so the code
   confirms what the person just agreed to. Without enrolment it lets the command
   through at once, as before. With enrolment it reads a code from the controlling
   terminal (`terminal::read_answer`: `/dev/tty`, never a piped stdin; on Windows the
   console's input, as every other answer there), and refuses (exit 64, nothing
   written) a missing, malformed or wrong code, a code of a step already used or of
   one before it (replay), and any attempt after five wrong codes within 15 minutes
   (it then asks nothing until the oldest leaves the window). `--yes` never skips
   it. One process asks once: `doctor --accept`, which may also accept hooks and MCP
   servers, would otherwise ask for a second code in the same step and refuse it as
   replayed. The commands that ask:
   - always: `allow` (a session grant, a permanent rule, `--site`, `--dir`; not
     `--remove` or `--prune`, which only narrow), `trust` (not `--revoke`),
     `doctor --accept` when it re-pins over drift, `hooks accept` and `mcp accept`
     when something new or changed is accepted, `mcp unwrap`, `policy trust-key`,
     `policy upgrade --undo`, `audit checkpoint --new-key`, `uninstall`,
     `proxy uninstall`, `approvals connect`, `approvals allow`, and `gate remove`;
   - when ADR-111's check says the change widens or changes a setting it does not
     rank: `edit` and `secret add` (the policy file before and after), `policy
     upgrade` (only with `--accept-widening`, which it already needed), `policy
     install` and `policy remove` (the policy with and without the pack);
   - `init` when it re-pins over drift, or makes a lock again while the gate is on
     (a deleted lock would otherwise be a way around it).

   Commands that only narrow ask nothing: `mcp wrap`, `sandbox sync`, `secret add` of
   a secret that adds deny rules only, `proxy install`, `audit anchor`, a plain
   `audit checkpoint`, `snapshot`, `restore` (it changes project files, not
   protection) and the first `init`. So do the guard and every unattended path: a
   hook never reads a code. Answering one call while it is held (`approvals wait`,
   an approver on a connected channel) is not a policy change and is not gated;
   a session grant or a rule, from `openmoat allow --last` or the home screen's
   "once" and "always" answers, is. `policy migrate` rewrites
   the same rules in the current schema (ADR-103) and is not gated.

4. **The policy-change ledger.** Every gated command, enrolled or not, writes one
   audit row once its change is made: host `openmoat`, session `policy-changes`,
   tool the command, rule `policy-change`, verdict `allow`, and reasons naming what
   changed, the account it ran under (`USER`), whether the factor was asked (and the
   step its code was taken for) and, for a change ADR-111 compares, each widened
   case and setting (up to 40, then a count). Each refusal at the gate writes a
   `gate-refused` row (`deny`) with why. They are ordinary events: hash-chained,
   keyed with the audit key (ADR-101) and covered by the signed checkpoints
   (ADR-110), so a row taken out or changed no longer verifies. `openmoat show
   --session policy-changes` lists them. A log that cannot take the row is said on
   stderr and the change stands (as `snapshot::record`); before `openmoat init` there
   is no log and nothing is written.

5. **Repository policy stays raise-only until trusted** (ADR-022, unchanged): a
   `.moat/policy.yaml` adds deny and review rules and `require:` levels only; its
   allow rules apply after `openmoat trust` of that exact digest, which is gated. A
   test decides the default policy against it merged untrusted (no widening even
   with `allow: shell: ['*']`) and merged trusted (widening).

6. **Debug-only test hook.** End-to-end tests type the code on stdin under
   `MOAT_ASSUME_TTY=1`, as they type every answer, and fix the clock with
   `MOAT_GATE_NOW` (Unix seconds), which only debug builds read
   (`#[cfg(debug_assertions)]`, as `MOAT_ASSUME_TTY`). Release builds contain neither.

## Consequences

- An agent that gets one loosening command run in the person's terminal, or detached
  under a pseudo-terminal, without also reading a file `kernel-self` denies, cannot
  loosen anything: it has no code. A person tricked into pasting a loosening command
  is asked for a code and sees the command it is for.
- It does not stop a process with the person's full access outside every hook and
  sandbox: such a process reads `~/.moat/audit.key.gate` (the same limit as the audit
  key, ADR-101, and the signing key, ADR-110), or removes it and the state directory
  and starts over with `openmoat init`. Removing the secret turns the gate off; the
  next loosening's ledger row then says "not enrolled", and `openmoat gate status`
  says the gate is off. An agent that can type arbitrary lines into the person's
  terminal while the person is away is such a process: it can run `cat` there too.
  THREAT_MODEL and LIMITS say so.
- Losing the phone means losing the factor: the person removes
  `~/.moat/audit.key.gate` and `gate.json` by hand in their own terminal, which an
  agent's hook-checked calls cannot do (`kernel-self`), then runs `openmoat gate
  setup` again. That is the recovery path and the limit above at once.
- Touch ID through `LocalAuthentication`, or a Keychain item with a biometric access
  control, would hold the secret where a process running as the user cannot read it
  without the person's finger. It needs a crate not in the build and a signed binary
  with a keychain entitlement; it is future work, as is a FIDO2 key.
- One more audit row per loosening, enrolled or not. `openmoat show --recent` and
  `audit stats` count them as events of host `openmoat`, as they count snapshots.
