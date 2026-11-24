# ADR-119: Team mode without a hosted service: signed bundles, inventory and drift

Status: proposed · Date: 2026-11-23 · Builds on ADR-022 (repository policy), ADR-031
(signed policy and packs), ADR-064 (required protection level), ADR-081 (live audit
delivery), ADR-104 (hook liveness), ADR-108 (protection score), ADR-109 (foreign-hook
ledger), ADR-110 (signed checkpoints), ADR-111 (never-widen check), ADR-114 (MCP package
releases)

## Context

A team that uses OpenMoat on many machines has two questions OpenMoat could not
answer: how does every machine get the team's rules, and how does the team know that
every machine still has them. Hosted products answer both with a service: Runlayer's
AI Watch inventories the agents and MCP servers of each device from an MDM-installed
agent (<https://docs.runlayer.com/shadow-ai>), Snyk's background mode scans on a
schedule and reports to its platform. OpenMoat is local-first and quiet: nothing leaves
the machine unless a person configured it, and there is no OpenMoat service to report
to.

What exists already: signed packs (ADR-031) a person installs one by one, a repository
policy that only narrows unless trusted (ADR-022), `init --managed` for the hook in the
administrator's place (ADR-098), `audit report` over exports of several machines, live
delivery of the audit log to OTLP or a signed webhook (ADR-081), and `status --format
json`. None of them carries the settings a team cares about (`sandbox.strict`,
`hooks.foreign`), none says what a machine has as one document a fleet tool can read,
and none tells a script that a machine drifted from what the team requires.

## Decision

1. **A team bundle is a folder with one signed manifest.** `openmoat-team.yaml`
   (`format: openmoat-team-bundle-v1`, `name`, `serial`, `policy:` and `packs:` rule
   files each with its SHA-256, `settings:`, `require_hooks:`) and its OpenSSH signature
   `openmoat-team.yaml.sig` in a new namespace, `openmoat-team-bundle`, so the key a
   team signs bundles with signs no pack or repository policy here (ADR-036, ADR-037).
   One signature covers every file through its digest. The folder is a clone of a team
   repository or a path an MDM tool keeps; OpenMoat fetches nothing and refuses a URL.
   Files are read only as regular files inside the folder (no link out, no FIFO, 1 MiB
   at most each, 32 rule files at most).

2. **The bundle is a managed layer that only narrows.** Its rule files have a
   repository policy's shape (ADR-022) *without allow rules*: a file with one does not
   parse. Deny rules join the person's (absolute, ADR-002); review rules are tried
   before the person's allow rules, `openmoat allow` rules and directory grants
   included; `require:` levels only raise (ADR-064); `requests:` deny lists only narrow
   (ADR-062). Rule ids are `team:<team>:<file>:<id>`. Its `settings:` name only the
   stricter value of six settings (`sandbox.strict: true`,
   `sandbox.package_min_release_age_days: <n>`, `hooks.foreign: hold`, `unattended:
   review`, `mcp.trust_first_sight: false`, `mcp.allow_sampling: false`); the weaker
   value does not parse, and each is applied over the person's own as the strictest of
   the two. So the person's policy can make the team's layer stricter and never wider,
   and the team can make the person's machine stricter and never wider. The layer is
   merged where packs are (`Home::load_policy`), so the guard, `openmoat run`, the MCP
   gateway and every report decide by it.

3. **Person-only install, with the never-widen check.** `openmoat team join <folder>
   --signer <allowed-signers entry>` trusts the given key for the team namespace only,
   verifies the manifest and every file, shows what joining changes with ADR-111's
   check, and installs a copy of the exact bytes that verified under `~/.moat/team/`
   with the record `~/.moat/team.json`. `openmoat team update [<folder>]` verifies the
   new bundle against the pinned team key, refuses another team's bundle and a serial
   not above the installed one (no replay of an older bundle), and shows the change: one
   that widens (a rule removed, a setting dropped) or that the check cannot rank waits
   for the person's `y`. `openmoat team leave` shows what leaving widens and asks.
   All three refuse without a terminal, with an agent among their parents, or over a
   drifted lock, as `openmoat policy install` does; the default policy denies them to
   agents (`kernel-self`). A later proof of presence (ADR-117's possession gate) has
   one place to go, the commands' shared check.

4. **Pinned like packs.** The record, the manifest, its signature, the team key and
   each rule file are pinned by the lock; the guard reads them from the bytes its lock
   check kept and checks each digest against the record and the manifest. A change
   after `join`/`update` is drift and the guard denies; `team.json` is pinned while
   absent, so one that appears later is drift too. Only a person's `team update`
   re-pins, so an MDM tool that drops a newer bundle into the folder changes nothing
   until the person accepts it; `inventory --check` reports that it waits.

5. **`openmoat inventory [--format json|ocsf]`.** One machine's state, from the same
   checks `status` and `doctor` make: each agent (present, version its program reports,
   hook installed, liveness per ADR-104, level, tier and score per ADR-108, whether it
   meets the required level), the run tiers' scores, the foreign-hook ledger as counts
   (ADR-109), MCP servers with their pins and recorded package releases (ADR-114) and
   proxied tools as counts, the policy's SHA-256, schema version, source (`team` with
   the team's name, serial, signer and manifest digest, or `local`), packs and rule
   counts, lock integrity, audit event count, signing key fingerprint and whether the
   latest checkpoint holds (ADR-110). Redacted: no file contents, no command lines, no
   secret; the person's home is written `~`, and every text passes the audit log's
   redaction. The host name is never read; the machine is named by the `machine:` of an
   accepted delivery configuration, if any. `--format ocsf` maps it to OCSF 1.3.0:
   Software Inventory Info (class 5020) per agent present and Device Config State
   (class 5002) for the machine, both in the Discovery category with activity `Collect`
   (2), OpenMoat's own facts under `unmapped.openmoat`
   (<https://schema.ocsf.io/1.3.0/classes/software_info>,
   <https://schema.ocsf.io/1.3.0/classes/config_state>). The Device Inventory Info
   class (5001) describes the device itself, which OpenMoat does not inventory.

6. **Drift: `openmoat inventory --check <folder>`.** It verifies the bundle against
   the joined team's pinned key (an unverified bundle is a usage error, 64), then lists
   each difference: no team joined, another team, a newer or different bundle than the
   installed one, lock drift, a policy that does not load, a required setting not in
   force, a team rule not in force, an agent of `require_hooks` without its hook or whose
   hook did not run (liveness `missing` or `unchecked`), an agent below its required
   level. Any difference exits 1; none exits 0. Exit 1 already means "the thing this
   command checks failed" for `openmoat run` and `bench --report`; drift is that for
   `inventory --check`, and the deny and review codes stay the guard's (ADR-004).

7. **Export through the existing sinks, off by default.** `openmoat inventory
   --deliver` sends the OCSF events to each sink of the accepted `~/.moat/delivery.yaml`
   (ADR-081) that says `inventory: true`, in its format: one OTLP/HTTP logs request
   (scope `openmoat.inventory`, one record per event) or one signed webhook body
   (`format: openmoat-inventory-delivery-v1`). The events are masked as delivered audit
   events are: the policy's brokered secrets and the sink's own key and header values.
   A sink without `inventory: true` gets nothing; without such a sink nothing is sent.
   Scheduling is the person's or the MDM tool's (cron, launchd, a scheduled task); the
   guard never sends an inventory. A file is the inventory's own output, redirected.

## Consequences

- A team gets one signed source of rules and settings without a server, and a fleet
  tool gets one JSON or OCSF document per machine and an exit code it can alert on.
- A bundle cannot widen a machine: a team that wants an allow rule ships a pack the
  person installs (ADR-031) or puts it in the person's policy. A bundle's deny rules
  are lowered to the OS layers like a pack's.
- Updates wait for a person. An MDM tool can place the bundle and run `inventory
  --check`, not accept it; `docs/LIMITS.md` says so.
- The signer is trusted as the person gives it: a wrong key in `--signer` trusts the
  wrong team. Joining shows the signer's name and the rules it brings.
- Exit code 1 gains one meaning, for `inventory --check` only.

## Tests

- `team/tests.rs`: a manifest with an allow rule, a weaker setting, a path out of the
  folder, an unknown agent or a reused name is refused; merging a bundle into the
  default policy widens nothing (ADR-111's check), its review rule holds what the
  person's own allow rule allows, its settings raise the person's and never lower
  them; signature verification accepts the team key and refuses another key, a pack
  namespace signature and a changed rule file.
- `commands/inventory/tests.rs`: the document's keys (schema snapshot), the OCSF
  classes, `type_uid` and required attributes, `~` for the home, masking of a sink's
  header value and a brokered secret in every event.
- `tests/architecture.rs`: the team and inventory modules name no agent; their facts
  come from the host specs.
- Conformance: `openmoat team join|update|leave` by an agent is `kernel-self`, by name
  and by path; `openmoat inventory` is left to the agent.
- End-to-end (`tests/e2e/team_mode.rs`, compiled here, run in CI): join, update with a
  narrowing and a widening bundle, refused replay, `inventory --check` exit codes,
  `inventory --format ocsf`.
