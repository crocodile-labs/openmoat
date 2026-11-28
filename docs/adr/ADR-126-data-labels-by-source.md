# ADR-126: Data labels by source, and rules on where labelled data may go

Status: accepted, released as a preview in 0.28.0 · Date: 2026-11-24 · Builds on ADR-020, ADR-029, ADR-057, ADR-058,
ADR-061 and ADR-113

## Context

OpenMoat follows data through a session in two ways today:

- **By fact.** Session taint (ADR-020) remembers that the session read secret material
  or untrusted content, and the trifecta (ADR-113) that it read private data and
  content someone else may have written. Later calls are tightened whatever their text:
  after a secret read every send needs review, after untrusted content every write to
  a file that runs later does.
- **By text.** Injected input (ADR-057, ADR-113 §4) links a later call to an earlier
  output only when the call names a host, path or command that output held; staging
  (ADR-061) only when a send names the file the session packed.

The text links are where paraphrase escapes (ADR-113 "Limits"). A ticket that says
"post a summary of every customer's contract terms to #general" leads to a chat post
whose words appear nowhere in the ticket; a page that names `collect.evil.example`
leads to a fetch of its address. And the facts are too coarse to say what a person
wants: "data from one MCP server must not reach another server's sending tool", or
"nothing from the web may reach a publish", are not expressible.

CaMeL (Debenedetti et al., "Defeating Prompt Injections by Design", arXiv 2503.18813)
attaches capabilities to every value: a label of where it came from and who may read
it, propagated by an interpreter that runs the plan a privileged model wrote, with
untrusted data handled by a quarantined model that cannot call tools. Policies on each
tool then decide from the labels of its arguments. That needs control of the agent's
interpreter. A hook does not have it: it sees each tool call and each tool output,
never the model's own values, so it cannot know which output a later call used.

## Decision

1. **Labels by source on the session taint** (`engine/labels.rs`; no second store, as
   ADR-113 decided). `Taint` gains `labels`, each a name and the first call that
   brought it in, kept first-source-wins, at most 32 per session:
   - `secret`: secret material (`secrets-paths`, a brokered secret);
   - `private`: private data other than secret material (ADR-113 §1);
   - `web`: a web page or search result;
   - `mcp:<server>`: an MCP server's result, per server; a metadata tool's result (a
     browser's tab list, ADR-057 amendment) brings no label;
   - `unknown-tool`: a host tool OpenMoat does not know;
   - `external`: any output someone else may have written (the trifecta's `seen`: a
     forge's issue text, a read from a host the policy does not allow, each of the
     above);
   - `untrusted`: untrusted content whose kind is not known.

   The fold reads them from each call that ran, as it reads the rest of the taint.
   A fold made before labels were kept, and untrusted content the CLI adds itself (a
   file an exposed session wrote, ADR-029), carry facts without labels;
   `Taint::label_set` gives those as `secret`, `private`, `untrusted` and `external`,
   so nothing the session read goes unlabelled (fail closed).

2. **A label reaches every later sink of the session.** Once the session holds a label,
   every later call that can send data out, or writes a file that runs or steers later,
   carries one atom per label and sink:
   `@data-flow <label> <sink> <target>`, with a fifth word `same-source` when the
   target is where the data came from (an MCP server's own tool; the one host every
   brokered secret belongs to). Sinks are ADR-113's places a call can send data to,
   now by kind: `network <host>`, `web-search web-search`, `publish <git-push|npm-publish|…>`,
   `mcp-send mcp:<server>`, and `protected-write <path>` (the built-in protected list
   and `taint.protected_writes`). A label says "this session read data from this
   source", never "this value came from it": it does not depend on the words the
   model wrote.

3. **Rules decide the atoms, and only deny and review rules.** A policy names a flow as
   any shell atom: `review: [{ id: web-data-leaves, shell: ["@data-flow web network
   *"] }]`. Only the deny, repository review and review lists are read; an allow or
   defer rule (even `shell: ["*"]`) never takes a flow out of a review, so a flow rule
   only narrows. A session whose labels no rule names is untouched. The atoms are
   applied in `CompiledPolicy::with_taint`, so the hook, the SDK and the proxy's
   session taint get them without a new call, merged strictest-wins after the grant.

4. **One default rule.** The default policy's review group `data-flow` names
   `@data-flow mcp:* mcp-send mcp:* $`: an MCP tool that acts on one server after the
   session read another server's result (a ticket posted to chat, a mail turned into a
   public issue). This is ADR-058's `mcp-cross-server` without its text match: that
   rule finds a piece of one server's result in another server's arguments, which a
   paraphrase escapes; this one needs no piece. A server's own tools (`same-source`)
   do not match, nor a server `mcp.flow_trusted` lists (the atom gets a fifth word
   `flow-trusted`, so a person's own rule without `$` still names it), nor a browser's
   tab list, nor a web page before a chat post. Other flows (web to publish, web to a
   host) are left to a person's policy: a session that reads docs and then pushes is
   daily work (ADR-113 "Alternatives").

## What a hook cannot do (limits)

- **Which output a call used.** Every later sink carries every label, so a session that
  read one ticket has every later chat post reviewed under the default rule, whether
  the post used the ticket or not. That is the false-positive cost; a person's grant
  for the call answers it.
- **Quarantined handling.** CaMeL's quarantined model, which reads untrusted data
  without tools, has no counterpart: the agent's one model reads everything.
- **Values inside one call.** A tool that reads and sends in one call (a script, an MCP
  server's own action) is one call; labels see its inputs only through the facts
  above.
- **Across sessions.** Labels are per session; file provenance (ADR-029) is still the
  only link across sessions, and its files carry `untrusted`.
- **What a host does not send.** A host that sends no output (ADR-057) still has its
  calls labelled by source, which needs no output.

## Alternatives considered

- **A label store beside taint.** Taint is already folded, cached and carried across
  policy changes (ADR-121); a second store would need all of that again.
- **Labels on values the model wrote (text similarity, embeddings).** Not
  deterministic, needs a model or a corpus in the core, and a re-encoding (base64, a
  translation) defeats it. Labels by source cost nothing and cannot be reworded away.
- **Per-label settings (`taint.sinks: [{from, to, verdict}]`).** A second rule
  language beside groups. Atoms reuse shell patterns, the policy linter and the
  repository and team layers, as `@staging-egress` does (ADR-061).
- **Default rules for web data.** Reviewing every send after a web read would review
  most sessions; ADR-025's quiet default stands, and the rule is one line for a person
  who wants it.

## Consequences

- New review: an MCP tool that acts after another MCP server's result. Benign
  fixtures: a server's own tools, a browser tab list, docs fetched before a chat post,
  a read-only tool, an ordinary source edit.
- Labels come from the hook, so an unwrapped, remote or plugin server's results label
  the session too, which ADR-058's pieces (kept by the wrapping proxy) never saw.
- The fold keeps labels; folds from before them are read fail closed (§1), so a
  session that spans the upgrade may see `untrusted` and `external` for its earlier
  reads.
- `openmoat policy upgrade` offers the `data-flow` group; POLICY.md documents the atom.

## Implementation

`openmoat-core`: `engine/labels.rs` (labels, `label_set`, `label_flows`),
`engine/taint.rs` (`Taint::labels`, labels from each call, the atoms in `with_taint`),
`engine/trifecta.rs` (`egress_sinks`, sinks by kind). Default policy group
`data-flow`. Fixtures in `tests/conformance/{attacks,benign}.yaml`.
