# ADR-103: Policy schema versions and `openmoat policy migrate`

Status: accepted · Date: 2026-11-19 · Builds on ADR-013 (what 1.0 needs: a stable policy
schema with `openmoat policy migrate`, #136), ADR-024 (strict YAML), ADR-053 (`ask` is now
`review`)

## Context

Every policy file starts with `version:`. OpenMoat has read only `version: 1` since its
first release, and `openmoat init` has always written it, so every policy a release made
says `version: 1`. But the number promised nothing: keys were added in most minor
releases, one was renamed (`ask:` became `review:` in 0.14.0, ADR-053), and nothing said
which changes may happen under the same number or what a person does when a file is for
another one. The messages showed it: a file for a later schema failed on its first key
this build did not know (`unknown field …`), with no word about the version, and a file
without `version:` failed with `missing field version`.

Two commands already change a person's policy: `openmoat policy upgrade` merges what a
new default adds (new rules) and renames `ask`; `openmoat edit` changes it by hand. A
change of schema is neither: it changes how the policy is written, not what it decides.

## Decision 1: `version:` is the policy schema version, and version 1 is stable

`version:` names the schema the file is written in. Within one schema version:

- a new key may be added, optional, with a default that keeps every older file's meaning;
- a key, a value or a rule field is never renamed, removed or given another meaning;
- a spelling a version once had stays readable (schema 1 still reads `ask`).

Anything else is a new schema version, which ships with its migration step (decision 3)
and is read beside the old one for at least one minor release. Schema 1 is today's: the
keys `docs/POLICY.md` §1 lists. This applies to the person's policy, repository policies
and packs alike, since they share the schema.

## Decision 2: the version is read first, and errors name it

The parser reads `version:` before anything else:

- another version than this build's: refused as that version, before any key is read. A
  newer one says it needs a newer OpenMoat; an older one (0) points at `openmoat policy
  migrate`. The message keeps its old start, `unsupported policy version N`, which scripts
  and the JavaScript SDK's tests match.
- no `version:`: refused (`MissingVersion`), with the line to add and `openmoat policy
  migrate`, which adds it.
- a key or value that does not fit the schema: the field, as before, now with the schema
  version it was read against (`policy parse error (policy schema version 1): unknown field …`).

A file without `version:` stays an error rather than being read as version 1. No release
wrote one, so no installed policy is affected, and a policy that does not load makes every
guard call a deny (invariant 4); reading a file that names no schema as if it named one
would guess at what its author meant, which a security policy does not do. The error says
the one line that fixes it.

## Decision 3: `openmoat policy migrate` rewrites the schema, never a rule

`openmoat policy migrate [--file PATH] [--dry-run] [--yes]` rewrites a policy in the
current schema, on its text (comments, order and rules stay as written):

- the steps run oldest first, each from version N to N + 1; with one schema there is no
  such step yet. The rewrites within schema 1 run too: `version:` added to a file without
  it, and `ask` renamed `review` (the rename `policy upgrade` also makes, ADR-053);
- the result must load and, for the rename, mean exactly what the file meant; otherwise
  nothing is written;
- it shows what it does and the full diff, and `--dry-run` stops there, anywhere;
- applying it follows the rules of every command that changes trust (AGENTS §7): refused
  without a terminal or with an agent among its parent processes; the installed policy is
  pinned, so it is refused over drift, the lock is checked again after the question, and
  re-pinned after the write; `kernel-self` denies the command to agents, as every
  `openmoat policy` command but `lint` and `check`;
- the previous file is kept beside it as `<file>.before-migrate`;
- it never adds a default rule: that stays `openmoat policy upgrade`'s, which a person may
  run after it.

## Consequences

- A file for a newer OpenMoat now says so; one without `version:` says how to fix it.
- Breaking the schema now has a cost written down: a new version, a migration step and a
  release that reads both. That is the stability 1.0 needs from ADR-013.
- What is left for #136: a machine-readable schema (JSON Schema) generated from the
  model and checked against `docs/POLICY.md` §1, so editors can validate a policy; and the
  first real version step, which will come with schema 2.
