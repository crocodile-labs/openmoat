# ADR-031: Audit anchors kept by the person, and policy signed with OpenSSH keys

Status: accepted · Date: 2026-10-18 · Builds on ADR-006 (policy lock) and ADR-022
(repository policy and trust)

## Context

The audit log's hash chain shows an edit in the middle of the log, but whoever can
write `~/.moat/audit.db` can delete the newest events and leave a valid, shorter chain
(THREAT_MODEL.md §5). Catching that needs the head recorded somewhere the same writer
cannot reach. Until now OpenMoat printed the head (`moat doctor`) and checked an export
against a hash passed by hand (`moat audit verify --anchor`), and left recording it to
the person. OpenMoat keeps data on the machine unless the person runs a command that
sends it, so it must not send the head anywhere itself.

Teams also want to hand out rules. A repository policy (ADR-022) reaches only the
project it is committed in, and its allow rules wait for `moat trust` per checkout and
per change. There was no way to install a team's rules once for every project, or to
know that the rules came from the team. Issue #136 asked for signed policy.

The agent could also read the state beside the policy (`policy.lock`, `audit.db`,
`trust.json`): `kernel-self` denied writes only, and reads were blocked inside `moat run`
only by the profile's default deny, so a `MOAT_HOME` inside a read root was readable.

## Decision

**Reads.** `kernel-self` also denies reading `~/.moat/audit.db*`, `policy.lock`,
`hosts.json`, `approvals.json`, `trust.json`, `allowed_signers` and `mcp/`, and
`audit.db*` and `policy.lock` in any `.moat/`. `policy.yaml` stays readable. The host
sandboxes and `moat run` carry the same denies. Nothing that decides needs those reads
from inside a sandbox: host hooks run outside the host's sandbox, and a guard inside
`moat run` relays to the run's own process (ADR-028).

**Anchors.** `moat audit anchor` (person-only) records the head after the chain
verifies: event id, its time, its hash and the time of anchoring, as one JSON line
(`moat-audit-anchor-v1`). `--file <path>` appends the line to a file the person keeps.
`--git <repo>` commits it on `refs/moat/anchors` in a repository the person names,
appending to `anchors.jsonl` in that ref's tree, with git plumbing only (`hash-object`,
`mktree`, `commit-tree`, `update-ref` against the old tip) and a `Signed-off-by`
trailer from git's committer identity. The working tree, index, `HEAD` and branches are
not touched. Nothing is pushed or fetched; the output says how to push the ref.
`moat audit verify --against <repo|file>` reads every anchor back and fails (exit 64),
naming the first anchor whose event is gone, has another hash, or sits at or after a
break in the chain. `moat doctor` notes when the last anchor was made
(`~/.moat/anchor.json`, information only, not pinned).

**Signed policy.** Signatures are OpenSSH signatures made and checked by the system
`ssh-keygen -Y sign/verify` in the namespace `openmoat-policy`. `ssh-keygen` is found
through the environment snapshot (`environment.json`, now also pinning `ssh-keygen`),
like every program the kernel relies on. OpenMoat adds no signature code and no
dependency.

- `moat policy trust-key <key.pub> --name <principal>` (person-only) adds the key to
  `~/.moat/allowed_signers`, restricted to that namespace.
- `moat policy install <pack> [--sig …] [--name …]` (person-only) verifies the pack's
  detached signature over the bytes it then copies to `~/.moat/policy.d/packs/`, and
  records the pack's SHA-256 and signer in `~/.moat/packs.json`. A pack has a repository
  policy's shape and merges like a trusted one, under `pack:<name>:` ids: deny rules join
  the user's, ask rules are tried before the user's allow rules, allow rules come after
  the user's. `moat policy remove <name>` takes one out.
- `allowed_signers`, `packs.json` and the installed packs are pinned by the lock, so a
  pack changed after install is drift. Only those three commands add these pins; every
  other re-pin keeps them and never adds them, so a file planted there is never pinned
  by a re-pin made for something else. An unpinned `allowed_signers` or `packs.json` is
  ignored. The loader also checks each pack against its recorded digest.
- When the user's policy sets `require_signed_repo_policy: true`, a repository policy
  is trusted only when its detached signature `policy.yaml.sig` verifies against a
  trusted key, without `moat trust`. An unsigned one, or one signed by another key, is
  not trusted even when `moat trust` recorded it: its allow rules are ignored, as for an
  untrusted repository policy. The setting asks for signatures, so a `trust.json` record
  alone must not satisfy it. Without it, the default, nothing changes.
- Without `ssh-keygen`, the signing commands refuse with a message; nothing else changes.

## Consequences

- Truncating or rewriting the newest events is caught once the person has anchored
  and kept the anchor beyond the attacker's reach. An anchor kept only on the same
  machine can be rewritten by the same writer; events after the newest anchor are not
  covered. OpenMoat cannot make the person push the ref.
- A team can distribute rules with the key infrastructure it already has (SSH keys)
  and no new trust root. A stolen signing key signs packs people will install; trust
  is per key and revoked by editing `allowed_signers` and re-pinning (`moat doctor
  --accept`).
- A signed repository policy costs an `ssh-keygen` run per trusted signer on each call
  in that project, and only where `require_signed_repo_policy` is on.
- `require_signed_repo_policy` is a new top-level policy key, so `openmoat-core`'s
  `Policy` gains a boolean; the core stays pure (the CLI runs `ssh-keygen`).
- Landlock cannot deny a path inside a granted tree, so on Linux a state directory
  inside a read root stays readable to commands under `moat run`; the hook still denies
  the agent's own reads.
