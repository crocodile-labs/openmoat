# ADR-037: Repository policies are signed in a namespace of their own

Status: accepted · Date: 2026-10-21 · Amends ADR-036

## Context

ADR-036 gave policy packs the namespace `openmoat-pack` and kept `openmoat-policy` for
repository policies, so that repository policy signatures made before it stayed valid.
But earlier releases signed packs in `openmoat-policy` too. A pack signed then, copied
into a project's `.moat/` as `policy.yaml` and `policy.yaml.sig`, still verifies as a
signed repository policy where `require_signed_repo_policy` is on, and its allow rules
apply in that project although its signer published it as a pack.

## Decision

- Repository policy signatures are made and checked in `openmoat-repo-policy`
  (`signing::NAMESPACE`). Nothing verifies in `openmoat-policy` any more.
- `openmoat policy trust-key` writes `namespaces="openmoat-repo-policy,openmoat-pack"`.
  Running it again for a key trusted by an earlier release replaces that key's line.

## Consequences

- Every repository policy signature made before this change stops verifying: with
  `require_signed_repo_policy: true` the file's allow rules are ignored until it is
  signed again with `ssh-keygen -Y sign -n openmoat-repo-policy`, and a key trusted
  before this change is trusted again with `openmoat policy trust-key`.
- A signature in `openmoat-policy` proves nothing to OpenMoat, so no pack or repository
  policy signed by an earlier release is taken for the other kind.
- Installed packs keep working: they are re-checked by their SHA-256 only.
