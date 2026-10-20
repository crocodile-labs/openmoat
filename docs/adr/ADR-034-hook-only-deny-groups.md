# ADR-034: Deny groups the hook applies and OS layers leave out (`hook_only`)

Status: accepted · Date: 2026-10-19 · Refines ADR-019 and ADR-021

## Context

`~/.m2/settings.xml`, `~/.m2/settings-security.xml` and `~/.gradle/gradle.properties`
often hold repository passwords, signing keys and tokens, and nothing stopped an agent
reading them. Adding them to `secrets-paths` would close that, but every deny rule is
also lowered to every OS layer (ADR-019): the host sandboxes and `moat run` would then
deny them to `mvn` and `gradle` too, which must read them to build. An OS layer sees
only which process opens a file, not whether the agent asked for its contents, so it
cannot tell the build tool's read from a script's.

## Decision

- A `deny` group may say **`hook_only: true`** (additive to schema v1; `version` stays
  1). The hook applies it like any deny rule: deny is absolute (ADR-002), for shell
  commands, file tools and MCP arguments alike.
- Lowering leaves the group's `fs.read` and `fs.write` lists out of the IR's rules and
  lists the group under `decide_only` for those kinds. Every backend is generated from
  the IR, so none denies the paths; OS layers treat them as if the group were absent
  (the default, read roots and allow rules decide).
- `policy lint` rejects `hook_only` on `allow`, `ask` and `defer` groups, with `net` or
  `fetch` patterns (sandboxed commands would reach hosts the hook denies), and on a
  group without file patterns.
- The default policy adds the group `build-credentials` with the three files, read and
  write. `moat policy upgrade` offers it to existing policies.

This is a second, listed way an OS layer may be wider than the hook beside ADR-021's
allowances. It is not an allowance: it grants nothing, it only leaves a deny out, and
`policy compile` prints it under `decide-only`.

## Consequences

- The agent cannot read or plant these files through any tool call the hook sees, and
  Maven and Gradle builds behave inside the sandboxes as before.
- Where a policy lets sandboxed commands read `~/.m2` or `~/.gradle` (a read root or an
  allow rule), any program they run can read the files, not only the build tools. The
  default policy grants neither, so there the sandboxes still deny them by default.
- The IR's own verdicts may be wider than the hook's on these paths only.
  `ir_consistency` still holds for the default policy, and the never-widens property
  test does not generate `hook_only` groups.
- Session taint (§4.1 of POLICY.md) keys on `secrets-paths`; a `hook_only` group always
  denies, so its reads never run and never need to taint.
