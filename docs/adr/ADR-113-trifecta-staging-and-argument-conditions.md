# ADR-113: The lethal trifecta, staging by default, argument conditions and wider linking

Status: accepted · Date: 2026-11-22 · Builds on ADR-019, ADR-020, ADR-029, ADR-057,
ADR-061 and ADR-063; accepts ADR-061

## Context

Data-flow tracking was the weakest of OpenMoat's deterministic layers:

- **Session taint is coarse.** After a secret read every send needs review
  (`session-taint`), but only reads the `secrets-paths` group names count. An agent's
  own login file, a build tool's credentials, a decoy key or the whole environment
  are denied in the default policy; once a policy reviews them, or a person approves
  one, nothing remembers that the session holds them.
- **Untrusted content and private data are never put together.** Simon Willison's
  "lethal trifecta" (private data, untrusted content, a way to send data out) is the
  combination prompt injection exploits. OpenMoat tracked parts of it separately and
  decided each call alone, so an issue's text, an agent login and a `git push` were
  three ordinary calls.
- **Staging was recorded, not stopped.** ADR-061 folds what a session collected
  outside the project and packed, and marks the send that carries it
  (`@staging-egress`), but no default rule names the atom, and private data copied
  into the project was not tracked at all.
- **Rules cannot look at arguments.** A rule names a tool (`mcp__mail__send_email`)
  or a path, never what a call's arguments hold: "mail only to the team" cannot be
  written. Progent (arXiv 2504.11703) shows that deterministic conditions on tool
  arguments are workable outside the model's planner.
- **Injected input matched exact text.** ADR-057 and ADR-063 §4 link a later call to
  untrusted output by host, path or command, with a few spellings folded. A relative
  path (`../tools/x.sh`) in a page was not kept (worse, the sentence trimming read
  `../x` as `/x`), a command written with its program's directory or `./` was another
  command, and a percent-encoded host (`ev%69l.example`) another host.

## Decision

1. **Trifecta state on the session taint** (`engine/trifecta.rs`; no second store).
   `Taint` gains two facts the fold keeps, first source wins:
   - `private`: the first read of private data that is not secret material. Private
     is a match of `secrets-paths` (its shell patterns: `gh auth token`),
     `agent-credentials`, `build-credentials`, `kerberos-tickets`, `canary` (decoy
     keys), `env-dump` or `env-secrets` in any list, a repository's copy of one, a
     read of a folder that holds such a group's paths (`tar czf k.tgz ~/.ssh`), or a
     read of a path `taint.private_paths` names. Secret material (`taint.secrets`)
     counts as private too.
   - `seen`: the first output the session read that someone else may have written:
     everything `output_source` names (ADR-057: a fetch, a web search, an MCP result,
     an unknown tool, a command reading from a host the policy does not allow, a
     forge's client such as `gh issue view`), except a metadata tool's result (a
     browser's tab list, ADR-057 amendment). `untrusted` counts as well, so a file
     provenance taint (ADR-029) is one.

   With both set, a call that can send data out gets `review` with rule
   `lethal-trifecta`; `taint: { trifecta: deny }` makes it `deny`; no value turns it
   off. A call can send data out when it connects to or fetches from a host off this
   machine, runs a web search (the query leaves), calls an MCP tool that writes,
   names a URL or whose name acts (`send`, `post`, `upload`, …), or publishes (`git
   push`, `gh pr create`, `gh gist create`, `gh api`, `npm publish`, `cargo
   publish`, `twine upload`, `docker push`, …). The reason names the three facts and
   the calls that set them:
   `this session read private data (read /Users/me/.codex/auth.json) and content
   someone else may have written (the output of `gh issue view 7`), and this call can
   send data to git-push: …`. A secret with its own host (a brokered one) going to
   that host alone is no part. A session that never read private data is untouched;
   two parts of three are quiet. Merged strictest-wins after the grant, so a grant
   made before the reads did not approve the send; the person's answer in the agent's
   prompt is the answer.

2. **Staging by default (accepts ADR-061).** The atom becomes `@staging-egress
   <target> <trigger>`; a rule written for ADR-061's shape (`@staging-egress *`,
   `@staging-egress api.github.com`) still matches it, a shell pattern being a prefix.
   - `private`: the session wrote private data into a file: a call that read private
     data also wrote a file (`cp ~/.aws/credentials notes/`, `cat ~/.codex/auth.json >
     x`, `tar czf k.tgz ~/.ssh`); those files are kept (`Staging::private`, at most 64,
     newest kept). Then **any** call that can send data out (the list in 1) carries
     the atom for each place it goes, with or without a body: once the file holds the
     data, a plain `git push` or `GET` can carry it.
   - `staged`: the send names a file the session packed or encoded from outside reads
     (ADR-061 §1–2, unchanged).
   - `collected`: the outside-read and outside-folder thresholds and a send with a
     body (ADR-061 §2, unchanged).

   The default policy's new review group `staging-egress` names `@staging-egress *
   staged $` and `@staging-egress * private $`. **`collected` stays recorded only**:
   its thresholds (25 reads, 2 folders) were set by estimate and ADR-061 §3 asks for
   `openmoat report`'s counts from real sessions before a rule decides it. A person
   can review it now with `shell: ["@staging-egress *"]`. The two triggers that decide
   need no threshold: each requires a specific earlier call (a packer over outside
   reads, a private read that wrote a file), which daily work does not make.

3. **Argument conditions (`when:`).** A `deny` or `review` group may list conditions;
   it then matches a call only when one of its patterns matches one of the call's
   atoms and every condition holds. Each condition is `arg` (optional: one name, a
   list, or `*`; snake case or a dotted path) and exactly one test:
   `under`/`not_under` (path globs, `~` and `${project}` expanded, a value placed
   against the working directory), `host_in`/`host_not_in` (host globs, the value's
   URL host percent-decoded and canonical), `in`/`not_in` (globs, ignoring case, each
   address of a recipient list split at `,` and `;`, `Name <a@b>` read as `a@b`),
   `matches`/`not_matches` (globs over the whole value), and `provenance: untrusted`
   (a host or path in the value is one the session kept from untrusted output,
   ADR-057). A positive test holds when some value passes; a negated one holds unless
   the call has values and every one passes, so a call that names no such value, or
   whose arguments were not read in full, is not shown to stay inside (fail closed).
   Without `arg`, `under` reads the call's file paths and `host_in` its hosts, as the
   engine resolved them; the others read every value.

   The values are the host's arguments of an MCP call, flattened by the CLI (strings,
   numbers and booleans, nesting to depth 8, at most 1024 values of 64 KiB), plus what
   the action names itself (a host tool's `path`, `url`, `command`, `query`; the paths,
   URLs and commands an adapter found). Deterministic: no model, no network.

   **They only narrow.** `policy lint` refuses `when` on an `allow` or `defer` group
   (it could let a call through on what its arguments claim), an exclusion in a list,
   a condition with no test or two. A conditional group never matches an atom on its
   own; `CompiledPolicy::with_arguments` adds its deny or review after the decision,
   strictest wins. Compiled through the IR (ADR-019): an OS layer cannot read
   arguments, so a conditional group's paths and hosts lower as if every condition held
   (a wider deny, recorded as a `Loss`), and `decide_only` lists the group under
   `when`. The JSON schema (`policy-v1.schema.json`) carries the shape.

4. **Wider linking for injected input** (both what is kept and the later call):
   - Hosts are percent-decoded before the ADR-063 canonical form (the URL Standard
     decodes a host before parsing it). Default ports were already dropped with the
     port, and case and the trailing dot folded.
   - A relative path in untrusted output (`./x`, `../x`) is kept, placed against the
     directory the output was read in; sentence punctuation no longer turns `../x`
     into `/x`.
   - A command is compared in one spelling: its program without its directory
     (lowercase where file names ignore case), a leading `./` taken off each word, a
     home, absolute or climbing path placed against the home and working
     directories. Flags and other words stay as written. A row kept before this is
     still matched as written.

## Alternatives considered

- **A separate trifecta store.** The facts are two optional strings beside what taint
  already folds and caches; a second store would need its own cache, fold and audit
  reading. The fold format (`fold-3`) changes so cached rows are refolded once.
- **Deny the trifecta by default.** A person exporting their own notes after reading
  docs is real work; review keeps OpenMoat quiet where a person can judge (ADR-025).
  `taint.trifecta: deny` is there for unattended sessions.
- **Count any network call after private data** (no untrusted part). That is session
  taint for secrets already, and for an agent login or a marked file it would review
  every `git push` of a session that once read one, untrusted content or not.
- **`provenance != untrusted` on allow rules** (Progent's form). An allow that depends
  on arguments the agent chose is a way through; the condition belongs on the review
  or deny side, where `provenance: untrusted` says the same thing.
- **A string condition language** (`"to not in [*@x]"`). Structured YAML gets schema
  checking in editors and a lint error naming the field, and has nothing to parse.
- **Decide `collected` now.** Without measured sessions, the thresholds would either
  never fire or fire on ordinary work; ADR-061 §3 stands for that trigger.

## Consequences

- New review in sessions that read private data and untrusted content and then send;
  in the default policy most private reads are denied, so it fires where a policy
  reviews them, a person approved one, or `taint.private_paths` marks files.
- New review for a send of a packed outside file, and for any send after private data
  was written into a file. Benign: packing the project's own output, a session that
  fetched docs and pushes code, `.env.example` (an exclusion of `secrets-paths`).
- The `staging-egress` rule is a default-policy change: conformance fixtures, the
  rule table (POLICY.md §6) and CHANGELOG; `openmoat policy upgrade` offers it.
- The SDK applies the trifecta and conditions over what an `McpCall` names (it carries
  no raw arguments: a negated condition on one holds). Staging stays the CLI's fold.
- `openmoat run`'s proxy still applies session taint only, not the trifecta: it cannot
  prompt, and refusing every connection after private data and a page would stop
  installs. Recorded as a limit.

## Limits (what still escapes)

- **Paraphrase.** A host, path or command the model rewrites (an IP for a name, a
  subdomain of a word host, `rm -r -f` for `rm -rf`, text it re-encodes or summarises)
  is not linked. The trifecta still holds the send if the session read private data.
- **Indirect flows.** A file written by a `Write` tool with private content the agent
  read in an earlier call is not private staging (the hook does not see the content's
  origin); a script that reads and sends is `session-written-code`'s (ADR-039).
- **Arguments a host does not send.** Conditions read what the host's payload carries;
  an MCP server that takes recipients from its own state, or a tool that resolves a
  contact name to an address, is not seen.
- **Bounds.** ADR-057's caps (256 tokens per output, 4096 per session) still apply,
  so decoys can push a planted token out; arguments past 1024 values make negated
  conditions hold.
- **One session.** Private data read in one session and sent from another is not
  linked, except through file provenance (ADR-029) for untrusted content.

## Implementation

`openmoat-core`: `predicate.rs` (the `when:` model and lint), `arguments.rs` (flattened
values), `engine/arguments.rs` (`with_arguments`), `engine/trifecta.rs`
(`with_trifecta`, private reads, egress targets), `engine/staging.rs` (private
staging, the trigger word), `engine/injection.rs` and `injection.rs` (spellings),
`host/canonical.rs` (percent-decoding), `ir/lower.rs` (losses, `decide_only`).
`openmoat`: `arguments.rs` (flattening the host's JSON), `commands/guard.rs` (order:
decision, injected input, conditions, grant, taint, staging, trifecta),
`taint.rs` (`fold-3`). Fixtures in `tests/conformance/{attacks,review,benign}.yaml`.
