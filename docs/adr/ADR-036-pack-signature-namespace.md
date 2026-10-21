# ADR-036: Policy packs are signed in their own namespace

Status: accepted · Date: 2026-10-21 · Amends ADR-031

## Context

ADR-031 signs repository policies (`.moat/policy.yaml.sig`, checked when
`require_signed_repo_policy` is on) and policy packs (`openmoat policy install`) in one
`ssh-keygen` namespace, `openmoat-policy`. A pack has a repository policy's shape (only
`version`, `deny`, `ask` and `allow`), so a pack and its signature, copied into a
project's `.moat/` as `policy.yaml` and `policy.yaml.sig`, verify as a signed repository
policy: its allow rules then apply in that project, although its signer published it as
a pack and the person may never have installed it. The reverse also held: a signed
repository policy installed as a pack.

## Decision

- Each kind of signature has its own namespace (`signing::Signed`): repository policies
  keep `openmoat-policy`, packs use `openmoat-pack`. `openmoat policy install` verifies in
  `openmoat-pack` only; the repository policy check verifies in `openmoat-policy` only.
- `openmoat policy trust-key` writes `namespaces="openmoat-policy,openmoat-pack"`. A line
  an earlier release wrote for `openmoat-policy` alone stays valid for repository
  policies; running `trust-key` for the same key and name again replaces it.
- Repository policies keep the old namespace because their signatures are checked on
  every call in every checkout that carries one; a pack's signature is checked once, at
  install, and an installed pack is re-checked by its SHA-256 only.

## Consequences

- A repository policy signature made before this change stays valid.
- A pack signed in `openmoat-policy` no longer installs: its maintainer signs it again
  with `-n openmoat-pack`, and a key trusted before this change is trusted again with
  `openmoat policy trust-key`. Packs already installed keep working.
- A signature never proves more than its kind: a signed pack is never a signed
  repository policy, and the reverse.
