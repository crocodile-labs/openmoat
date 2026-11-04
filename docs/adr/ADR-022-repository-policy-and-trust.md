# ADR-022: Repository policy tightens by itself and widens only when trusted

Status: accepted · Date: 2026-10-06 (#128)

## Context

A team wants to commit its rules once, in the repository, and have every member's
agent follow them whatever agent they use (#128). A repository is input the person
did not write: a cloned project, a pull request branch or a dependency can carry a
`.moat/policy.yaml`. An agent working in the repository is the attacker moat is built
against, and a file it could write, or a file a stranger committed, must never be
able to loosen the person's own policy. The issue says the repository policy "can
only tighten the user policy unless the user trusts it". The evaluation order is
`deny → allow → review` (ADR-002), so a `review` rule merged into the user's `review` list
could never tighten an action the user allows.

## Decision

- The repository policy is `<project>/.moat/policy.yaml`, where the project is the
  git root `${project}` names. It may hold `version`, `deny`, `review` and `allow`
  rule groups, nothing else: `defaults`, `executables` and `sandbox` stay the
  user's, and any other key is a parse error.
- Without trust it only tightens. Its `deny` groups join the user's deny list. Its
  `review` groups are tried after the user's deny rules and before the user's allow
  rules, so they make an action the user allows need review but never soften a user deny.
  Its `allow` groups are ignored. The result is the strictest of the two policies
  for every atom, and no repository content can produce a wider verdict.
- `moat trust [<repo>]` lets its `allow` groups in. It records the SHA-256 of the
  file's bytes together with the canonical project root in `~/.moat/trust.json`,
  which the policy lock pins (ADR-006). Trust is bound to that exact file in that
  exact place: any change to the file, or the same file in another checkout path,
  is untrusted again and applies in its tightening-only form until a person runs
  `moat trust` again. Trusted allow groups are appended after the user's allow
  groups, so the user's deny rules, `kernel-self` included, still win (ADR-002).
- `moat trust` is a person-only command like `moat allow` (ADR-007): it refuses to
  run without a terminal, refuses over a drifted lock, re-pins only the files
  already pinned, and the default policy's `kernel-self` group denies it to agents,
  also under the pseudo-terminal wrappers (ADR-011, ADR-014). The record lives in
  moat's state, never in the repository.
- Every rule a repository contributes gets the id prefix `repo:`, so decisions and
  the audit log name the source, and a repository rule cannot pose as `kernel-self`
  or collide with a user rule id.
- Merging is a pure function in `moat-core` (`RepoPolicy::merge`) over parsed
  policies. Finding, reading and hashing the file, and the trust record, stay in
  `moat-cli`.
- A repository policy that cannot be read or parsed is not ignored: `moat guard`
  denies every call in that project with `kernel-error` and the parse error as the
  reason. Ignoring it would let a typo, or an attacker, turn the team's denies off.
- Repository rules apply in the hook only. The OS layers (Standard tier host
  sandboxes, the egress proxy) are generated from the user policy per user, not per
  repository (ADR-018, ADR-019): a repository deny is not enforced there, and a
  trusted repository allow does not widen them.

## Consequences

- A team can deny anything or hold it for review in its repository without any member doing
  more than cloning it. Turning that off means editing a file in the repository,
  which `kernel-self` denies to agents (`**/.moat/**`).
- Allowing something on top of a person's policy takes one deliberate step per file
  version, and a later commit that edits the file silently drops back to
  tightening-only, never the reverse. `moat status` and `moat doctor` say which form
  applies.
- A malformed repository policy blocks the agent in that repository until it is
  fixed. That is a denial of service a repository could always cause with a deny
  rule, and it fails closed.
- The OS layers do not carry repository rules. Under the Standard tier a trusted
  repository allow for a host or a path outside the user policy still meets the
  sandbox's deny; a repository deny is a hook-only rule, listed in POLICY.md.
