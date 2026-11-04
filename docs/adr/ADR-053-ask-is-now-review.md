# ADR-053: The `ask` verdict is now `review`

Status: accepted · Date: 2026-11-04

## Context

OpenMoat's four verdicts were `allow`, `defer`, `ask` and `deny`. "Ask" was also
the word several hosts use in their hook protocols (Claude Code's
`permissionDecision: "ask"`, Cursor's `"permission": "ask"`, Gemini CLI's
`"decision": "ask"`, OpenCode's `ask` effect), and the English verb for a host or
`openmoat init` putting a question to a person. One word for three things made code,
output and docs hard to read: "Codex cannot ask, so an ask is a deny" names a host
capability and OpenMoat's verdict in one breath. Contributors kept meeting both
`ask` and the idea of a person reviewing the call for the same thing.

## Decision

1. **The verdict is `review`.** OpenMoat's own name for "a person must approve
   this exact call" is `review` everywhere OpenMoat owns the word: `Verdict::Review`
   in `openmoat-core` and `openmoat-sdk`, `Code::Review` (exit code 3, number
   unchanged, ADR-004), MoatBench's `Answer::Review`, the policy's `review:` rule
   list and `review` default, the audit log, every CLI output and JSON field
   (`"verdict": "review"`, `reviewed` counts, `top_reviews`), the SDKs and the docs.
   A host's ability to put a question to a person is "prompt" (`HookEvent::PreToolUseNoPrompt`,
   `Reviews::on_no_prompt`), and `contract/asks.rs` is `contract/reviews.rs`.
2. **The host boundary keeps each host's word.** Every adapter in
   `openmoat-hosts` renders the verdict through one function, `wire::host_verdict`,
   which sends `review` as `"ask"`; `Verdict::as_str` is never used for a host
   reply. That includes the JSON `openmoat guard --host openclaw|opencode|pi` gives
   OpenMoat's own plugins: a plugin an older release installed reads
   `{"decision": "ask"}`, and an unknown word there must never be what decides a
   call. The plugins' JavaScript keeps the word where it reads it.
3. **Old policies still load and mean the same.** `ask:` is read as `review:`
   and a `defaults` verdict `ask` as `review` (serde aliases). `Policy::parse` also
   records where the old names were used (`OldNames`), so `openmoat policy lint`
   (and every command that prints lint warnings) says so, and `openmoat policy
   upgrade` renames them in the diff it shows and asks about, as it applies the
   default's own changes. The rename is on the text, keeps comments and order, and
   is kept only if the result parses to exactly the same policy with no old name
   left; otherwise the text is left for the person and the warning stays.
   Repository policies and policy packs read `ask:` the same way; a signed pack is
   never rewritten, since its signature covers its bytes.
4. **A file with both `ask:` and `review:` is an error**, not a merge.
   Merging would decide calls from two lists the author may have meant as old and
   new halves of an edit, and hide that the file is inconsistent; an error says
   exactly what to do. It cannot appear unseen: `openmoat edit` lints its draft
   before writing, `policy upgrade` never writes both, and a hand edit of the
   pinned policy is drift that `guard` denies on anyway (invariant 9).
5. **Audit rows are never rewritten.** The hash chain covers each row's stored
   text (`moat-audit-chain-v1`), so a row written as `ask` keeps `ask`. Schema
   version 8 rebuilds `events` and `mcp_tickets` with a `CHECK` that accepts
   `review` as well as `ask`, copying every row with its id and hashes, as version 3
   did for `defer`. New rows record `review`. Every reader maps at read time:
   `Verdict` parses `ask` as `Review` (`FromStr` and serde), so `show`, `report`,
   `team`, evidence, `allow --last` and taint see old rows as reviews. An export
   line carries the stored text (`"verdict": "ask"` for an old row), which
   `verify_export` hashes as stored; its `to_event` reads it as `review`.
6. **Wire compatibility.** The SDK's `Verdict` and the core's read `"ask"` from
   any JSON (older SDK callers, logs, fixtures) and write only `"review"`. An older
   binary refuses a version-8 audit database as it refuses any newer schema
   (`SchemaTooNew`), so it never shows a `review` row as something else; an older
   SDK reading newer decision JSON meets an unknown verdict, which its callers must
   already treat as a deny (ADR-046). Exit codes do not change.
7. **History is kept.** Released `CHANGELOG.md` sections and ADR file names keep
   the old word; ADR text names the verdict by its new name. Nothing else that is
   persisted names the verdict: approvals, taint answers, `hosts.json` and the
   policy lock hold no verdict word.

## Consequences

- Renaming public items of `openmoat-core`, `openmoat-hosts` and `openmoat-sdk`
  (`Verdict::Ask`, `Asks`, `HostSpec::asks`, `HookEvent::PreToolUseNoAsk`,
  `Policy::ask`, `Policy::repo_ask`, `RepoPolicy::ask`, `Answer::Ask`,
  `Summary::asked`) is a breaking change of the library API, made without
  deprecated aliases in a 0.x minor release. The JSON outputs change their verdict
  word and the keys that named it; scripts that matched `"ask"` must match
  `"review"` (or both, for old exports).
- A person upgrading runs `openmoat policy upgrade` once; until then nothing
  changes but a lint warning.
- A host protocol that adds its own word for a review needs only a new arm in
  `wire::host_verdict`'s callers, never a change to OpenMoat's names.
