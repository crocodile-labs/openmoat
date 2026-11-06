# ADR-059: The block message, rule titles, `openmoat watch` and `openmoat why`

Status: accepted · Date: 2026-11-06 · Builds on ADR-004, ADR-025 and ADR-053

## Context

When OpenMoat denies a call or holds it for review, the agent's host shows one line in its
reason field: `moat: deny [secrets-paths] — secret material: read /Users/me/.ssh/id_ed25519`.
The rule id and the engine's reason say what matched, not what was stopped or what the
person can do. The person reads it in the agent's prompt or transcript; the model reads it
too and decides what to do next. A message that only names a rule invites the model to try
the same thing another way; a message that tells it how would help it do so.

People also have no live view of what their agents run (`openmoat show` and `replay` look
back), and no single place that explains one decision: which rules matched, where they are
in the policy, what else (taint, an MCP flow) shaped it and how to change it.

## Decision

1. **Rules have a `title` and a `why`.** A rule group may say `title:` (what it stops, in the
   person's words: "reading or changing your keys and credential files") and `why:` (one
   line). Both are optional, one line each without control characters, at most 80 and 160
   characters (`policy/text.rs`); the policy schema stays version 1, and an older OpenMoat
   rejects a policy that uses them, as it does every new optional field. Every `deny` and
   `review` rule of the default policy has both (a test fails otherwise);
   `openmoat policy upgrade` adds them to a policy made from an earlier default, counted as
   wording updates. `openmoat policy lint` warns once, naming the `deny` and `review` rules
   without a title; the commands that write a policy do not repeat it after each change.

2. **Only the person's own words head a message.** Titles come from the user's policy
   lists and installed policy packs (`Policy::own_group`). A repository policy's `title` and
   `why` are dropped when it is merged: a repository is input the person did not write, and
   its words would reach the model as if they were OpenMoat's. Its `reason` still shows in the
   `rule` line, as before.

3. **The block message.** For a `deny` or `review` whose deciding rule has a title, every
   host's reason field carries at most six lines of plain text:

   ```text
   OpenMoat blocked: reading or changing your keys and credential files
     call   Read ~/.ssh/id_ed25519
     rule   moat: deny [secrets-paths] — secret material: read /Users/me/.ssh/id_ed25519
     why    a key or token that leaves this machine cannot be taken back
     next   if you need this, do it yourself in your own terminal
     more   openmoat why --last · https://openmoat.dev/r/secrets-paths
   ```

   A review the host puts to the person starts `OpenMoat is holding this for you:` and its
   `next` is "approve it in this prompt only if you expected it". A review that reaches a host
   that cannot ask (Codex, goose, Cline, the Continue CLI, a prompt-free mode) as a `deny`
   (ADR-025) keeps that heading, and its `next` says why the host cannot ask and how to
   approve: "Codex hooks cannot prompt, so approve it in your terminal: run `openmoat`, or
   `openmoat allow --last`, then retry".

   - The `rule` line is the line earlier releases sent whole, so a script or test that
     looks for `moat: <verdict> [<rule>]` still finds it. The first rule with a title heads
     the message; every rule id stays in the `rule` line.
   - The `call` is masked as the audit log is (`openmoat_audit` token shapes and the
     brokered secrets' values), shown with `~` for the home directory, on one line, cut in
     the middle past 100 characters; the reasons on the `rule` line are masked the same way
     and cut past 300. Control and invisible characters are shown as `?`.
   - Exactly one `next` step, for the person: do it yourself, answer the prompt, or approve
     it in a terminal. It never suggests another call, a variant, an encoding, a split or a
     retry other than the same call after the person approved it; a test checks the
     wording.
   - No colour: the host renders the text. Each host's reason field takes it as it takes
     the one line now (a JSON string; the hosts tested in `block/tests.rs`).
   - A decision without a titled rule, an `allow`, a `defer`, and every synthetic rule
     (`kernel-integrity`, `kernel-error`, `session-taint`, `default.net`, …) keep the one
     line. `--format json`, the audit log, verdicts, rule matches and exit codes do not
     change.

4. **Presentation only, carried on the decision.** `openmoat_core::Decision` gains
   `notice: Option<Box<Notice>>`, which the engine never sets, no decision reads, and serde
   never writes or reads. The guard fills it after deciding and before answering
   (`notice.rs`): the titles are looked up by rule id in the compiled policy, a few string
   copies per denied call. `openmoat_hosts::reason_line` renders it in every host's format;
   `Host::answer` records on it why a host cannot ask instead of adding that to the
   reasons, so Hermes Agent's approval key (a hash of the rules and reasons) is unchanged.

5. **`openmoat watch`** follows the audit log through a read-only handle: one short read by
   row id twice a second, which in WAL mode neither waits on the guard nor makes it wait,
   and no lock between reads. One line per call (time, agent, a mark, tool, what the call
   names, verdict and rule at the right), a second line under each deny and review with the
   rule's title. Colour only on a terminal without `NO_COLOR`; piped, whole plain lines.
   `--host`, `--only deny|review`, `--session`, `--recent N`, `--no-follow`; Ctrl-C exits 0.

6. **`openmoat why [--last | <event id> | HH:MM[:SS]]`** explains one decision: the call, the
   line the host received, each deciding rule with its title, `why`, reason and where it is
   (`~/.moat/policy.yaml:17`, the approvals file, the repository's policy, a pack, the
   defaults, or a built-in check), how the policy as it is now decides each part of the call
   (after the same lock check as `openmoat policy check`), the session context (taint,
   session-written code, an MCP flow, a changed MCP server), and how a person changes it:
   `openmoat edit` for a deny of their policy (an allow never overrides a deny), `openmoat
   allow --last` for the newest review. `--format json` prints the same as one document.

7. **Rule pages.** `https://openmoat.dev/r/<rule id>` is the fixed address of a rule's page,
   for ids of lowercase letters, digits, `-` and `.`; the pages are a site change.

## Alternatives

- **A new line format only** (`OpenMoat: deny — reading your SSH key`) without the old
  token: breaks every script and test that reads `moat: deny [rule]`, for no gain.
- **Titles built into the code** instead of the policy: two lists of rules to keep in step,
  and a person's own rules could never have one.
- **A field on each host's response** instead of on the decision: every adapter's render
  path would take a second argument; the decision already reaches all of them.
- **Telling the model how to proceed** ("ask the user to run …", "use a project file
  instead"): the text reaches the model, and any hint toward another call helps the attack
  the rule stops.
- **A watcher that holds the database open in a transaction**, or a notification channel
  from the guard: either can slow the guard or add a failure mode to it; polling a WAL
  database from outside adds neither.

## Consequences

- People and models see what was stopped and the one thing a person can do; the old line
  is still there for tools.
- `openmoat_core::Decision` has a new public field and `RuleGroup` two: a breaking change
  of the library API (0.x minor). The SDK's own decision type is unchanged.
- A policy made from an earlier default shows the old line for its rules until `openmoat
  policy upgrade` adds the titles; `openmoat policy lint` says so.

## Limits

- The message is what the host shows; a host that truncates its reason field (none of the
  supported ones is known to) shows less.
- `openmoat why` explains the decision from what the audit log recorded (rules and reasons,
  masked) and decides the call again with the policy as it is now; when the policy changed
  in between, the second part says what would happen now, not what happened then.
- `watch` shows times in UTC, like `show` and `replay`, and reads the terminal's width from
  `COLUMNS`; without it, 100 columns.
