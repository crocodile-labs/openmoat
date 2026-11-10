# ADR-078: Approving a `review` from another device

Status: accepted · Date: 2026-11-10 · Builds on ADR-007, ADR-025, ADR-044, ADR-053 and ADR-071

## Context

A `review` (ADR-053) is answered where the agent runs: the host's own prompt, or, where
the host cannot prompt (Codex, the Continue CLI, a Hermes Agent in YOLO mode, any
headless run), a deny that says how to approve the call with `openmoat allow --last`
at a terminal. A person who left an agent working and walked away has no way to answer
it. A remote answer is useful only if it can never become a way around the check: a
forged, replayed, stale or self-issued approval must be worth nothing, and the agent
must not be able to read or reach whatever issues one.

## Decision 1: what a request is and what an approval is bound to

1. **Only a `review` can be approved remotely.** A `deny`, an `allow` and a `defer` are
   never sent and never changed. The gate runs in `openmoat guard` after every check
   that only tightens (taint, staging, session code, MCP flow, push) and after the host's
   own `defer` handling, so what is approved is the call's last verdict; a deny reached
   later in the pipeline can never be lifted, and a remote approval cannot turn a
   `kernel-self` or `secrets-paths` deny into anything.
2. **A request carries** the host, the host's session id, the working directory, the
   tool, the action as the engine decided it, the SHA-256 of what the call writes or
   sends that the action does not name (a `Write`'s content, an `Edit`'s replacements, a
   patch envelope, MCP arguments), whether the host said it sandboxes the call, and the
   ids of the rules that held it for review. These are hashed, after a domain string,
   into the **request digest**. Two calls with the same digest are the same call in
   every respect OpenMoat decides on.
3. **A request has** a random 128-bit id (the nonce), its digest, when it was made and
   when it expires (default 5 minutes, at most 60, set by the person at `connect`), and an
   HMAC-SHA-256 over all of those under the approval key, after its own domain string.
4. **An answer** (approve or deny) names the request id and digest, the approver's
   channel user id, the channel, when it was given and the request's expiry, and is
   signed under the same key with a third domain string. The guard accepts an answer
   only when its signature verifies, it names the digest of the call now being decided,
   it names the id of the request on file for that digest, the request has not expired,
   and the approver is on the allowlist (Decision 3) as the guard reads it now.
5. **Single use.** An approval is consumed by creating `used/<id>` with create-new
   semantics before the call is allowed: of two guards that race for it, one creates the
   file and allows; the other sees it exists and keeps the `review`. The `used/` folder
   is the replay store. An answer that names a used id is refused even if its files are
   put back. A used marker older than a day is removed, since its request expired long
   before.
6. **A remote deny** holds: the same call is denied (`remote-denied`) until the request
   expires; after that the next try asks again.

## Decision 2: the key and the channel credentials are out of the agent's reach

1. **The approval key** is 256 random bits in `~/.moat/remote/approval.key`, written
   owner-only and read through `key_file::read`, which refuses a key others may read or
   replace (as `proxy.key`, ADR-044). It is not the proxy key: replacing one revokes
   nothing of the other.
2. **The channel credential** (a Telegram bot token) is in
   `~/.moat/remote/telegram.token`, owner-only, read the same way. It is never put in a
   policy file, a command line, an environment variable, the audit log or an error: the
   connector reads it from a file the person names or from the controlling terminal, and
   no message OpenMoat prints contains a request URL (the token is part of Telegram's).
3. **The channel settings** (`~/.moat/remote/channel.json`: which channel, the
   approvers, the expiry) are signed with the approval key, so a file an attacker wrote
   without the key is refused, and with it every remote answer.
4. **`kernel-self`** denies reading `~/.moat/remote/**` (and the same under a moved
   state directory) and every `openmoat approvals` command run by an agent, by either
   name, by path and under the pseudo-terminal wrappers; writes under any `.moat` were
   already denied. Host sandboxes and `openmoat run` get the same read deny from the
   policy, so a sandboxed command cannot read the key or the token either.
5. **No approval through the agent's own tools.** Answers are written only by
   `openmoat approvals listen`, which, as every person-only command, refuses to run
   without a terminal or with an agent or `openmoat run` among its ancestors
   (`terminal::refuse_agent`), and writes an answer only for a reply the channel's
   server delivered from an allowlisted account to a button OpenMoat sent. There is no
   local "approve" command: the local way to approve is the host's prompt or
   `openmoat allow`, which are unchanged.

## Decision 3: who may approve

1. **An allowlist of channel user ids** (`approvers`), changed only by
   `openmoat approvals allow <id>` and `openmoat approvals remove <id>`, person-only
   commands. An empty list approves nothing.
2. **The channel says who answered.** For Telegram the user id is the `from` of the
   callback query, which Telegram's server sets for a button press; it is read over TLS
   from `api.telegram.org` with the bot's token. A reply from anyone else is refused,
   recorded (`remote-refused`), and the sender is told so; its id is printed by
   `listen` so the person can add it on purpose.
3. **Each button is bound to its request.** A button's data is the verdict, the request
   id and the first 64 bits of an HMAC of both and the digest under the key. A button
   whose data does not verify (an edited client, a stale button of a replaced request)
   is refused.

## Decision 4: fail closed

No answer, an expired request, a channel or network error, a missing, unreadable or
tampered key, settings or answer, a full disk: every one leaves the call as it would be
with no channel set, that is a `review` (the host's prompt, or a deny on a host that
cannot prompt). No error path in the gate produces an `allow`. The gate adds one line
to the call's reasons saying the request was sent, or why remote approval is not
available, so the person and the agent see it.

## Decision 5: what is sent, and prompt injection

The text the approver sees is built by OpenMoat, not the agent: the host, the project,
the rules that held the call and what each one is, the request code, the expiry, and the
call itself under a label that says it came from the agent and may try to persuade.
The call is passed through `openmoat_audit::redact` (token shapes and the policy's
brokered values), control and bidirectional characters are shown escaped
(`render::clean`), and it is cut to 1500 characters; a write's content is never sent,
only its size and digest. The message is plain text (no `parse_mode`), with link previews
off, so nothing the agent wrote is rendered as markup or fetched by Telegram. The two
buttons are OpenMoat's. A command that says "approved by the security team" is still
shown as the command it is.

## Decision 6: audit records

- the call's own row: its `review`, with a reason naming the request code (request);
- `listen` writes a row in the request's host and session, tool `approval`, for each
  answer: `remote-approved` (allow), `remote-denied` (deny), `remote-refused` (deny: not
  an approver, a bad button, an answer after expiry) and `remote-expired` (deny, for a
  request nobody answered in time);
- the call's row when an approval is used: `allow`, rule `approved-remote`, with the
  approver and the request code in its reason. A remote deny used by a call records
  `deny`, rule `remote-denied`.

## Decision 7: the code

- `crates/openmoat-cli/src/remote.rs` and `remote/`: the channel-neutral core: request
  and digest, signed settings and answers, the store, the gate the guard calls, the
  listener loop, and the `Channel` trait (`send`, `poll`, `settle`). It does no network
  I/O.
- `remote/telegram.rs`: the only code that talks to a network: Bot API calls over
  rustls with the system roots (the proxy's TLS stack), long polling `getUpdates`
  (no inbound port, no webhook).
- `openmoat approvals connect telegram | allow | remove | status | test | listen |
  disconnect`. `status` is read-only and needs no terminal; every other command is
  person-only.
- Unit tests drive the core with a fake channel; no test uses a real token or network.

## Threat model

| Threat | What stops it | Test |
|---|---|---|
| Spoofed approver: someone else messages the bot or presses a forwarded button | the sender's id from Telegram's server must be on the allowlist the person set | `remote::tests::an_answer_from_someone_not_allowed_is_refused` |
| Forged approval file written by the agent | writes under `.moat` denied; answers signed with a key the agent cannot read | `remote::tests::an_answer_signed_with_another_key_is_refused`, conformance `T9-write-remote-answer` |
| Approval for one call used for another (changed command, content, session, project) | answer bound to the request digest | `remote::tests::an_approval_answers_only_its_own_call` |
| Replay of a used approval, or two guards racing | create-new `used/<id>` before allowing | `remote::tests::an_approval_is_used_once`, `..._restored_answer_is_not_used_again` |
| Stale approval (late answer, old answer file) | request expiry checked by `listen` and again by the guard | `remote::tests::an_expired_request_is_not_approved` |
| Agent reads the bot token or the key | `kernel-self` read deny, sandbox deny, owner-only files with mode check | conformance `T9-read-remote-token`, `T9-cat-remote-key`, `T9-read-moved-remote-token` |
| Agent runs `openmoat approvals allow` or `listen` | `kernel-self` shell deny; ancestry check | conformance `T9-approvals-allow`, `T9-approvals-listen-path`; e2e `approvals_commands_need_a_person` |
| Agent edits the allowlist file | writes denied; settings signed | `remote::tests::tampered_settings_are_refused` |
| Prompt injection in the request text | OpenMoat's own framing, plain text, escaping, redaction, length cap, no previews | `remote::tests::the_prompt_escapes_and_labels_the_agents_text` |
| A remote approval lifting a deny | the gate acts on `review` only | `remote::tests::only_a_review_is_sent`, e2e `a_deny_is_never_sent_for_approval` |
| Channel down, key missing | decision unchanged (`review`) | `remote::tests::without_a_key_the_review_stays` |

Limits, written in `docs/APPROVALS.md` and `docs/LIMITS.md`: an approver's Telegram
account is as trusted as a person at the terminal, so it must not be signed in where an
agent controls a browser or the screen; the request text goes to Telegram's servers; a
host that prompts still shows its prompt, and a remote approval answers the next try of
the same call, not that prompt (the hook cannot wait: `GUARD_BUDGET_S` is 30 s and some
hosts run a call whose hook timed out); `listen` must be running, at a terminal of the
person's own.

## Rejected

- **Waiting in the hook for the answer.** The guard's budget is 30 s, below every hook
  timeout OpenMoat sets, because Claude Code, Codex, the Continue CLI and GitHub Copilot
  CLI run a call whose hook timed out. A person on a phone needs minutes. Waiting longer
  would turn a slow answer into the host running the call unchecked.
- **Sending from the guard.** It would put network calls and a credential read on every
  review, in a process the agent starts.
- **Reusing session grants (`approvals.json`).** A grant lasts 24 hours and covers every
  repeat; a remote answer is one call, minutes long.

## Next steps (not built)

- **Slack**: a Slack app with a bot token (`xoxb-`, `chat:write`) and Socket Mode
  (`connections.open` with an app-level token `xapp-`, `connections:write`) so no inbound
  port is needed; the approver is the interaction payload's `user.id`, and the payload
  arrives over a WebSocket, which needs a WebSocket client this crate does not have.
  It fits the `Channel` trait; it is left out until that client is reviewed.
- **GitHub**: an answer as a PR comment or check run needs a GitHub App or token with
  `issues:write`/`checks:write` and polling of comments; the approver is the comment's
  author login, which must also be checked against the repository's permission. It fits
  the trait as a polling channel; it is left out because a repository's commenters are a
  wider and easier-to-confuse set than one chat, and that needs its own review.
- Telegram from a group chat, and a service unit for `listen` like `openmoat proxy
  install`.

## Vendor facts

From the Telegram Bot API, <https://core.telegram.org/bots/api> (read 2026-11-10):
requests are `https://api.telegram.org/bot<token>/METHOD_NAME`; every response is a JSON
object with a Boolean `ok`, `result` on success and `description` on failure;
`getUpdates` takes `offset` (one more than the highest update id received), `timeout`
(long polling, seconds) and `allowed_updates`, and does not work while a webhook is set;
`CallbackQuery` has `id`, `from`, `message` and `data`; `callback_data` is 1–64 bytes;
`sendMessage` text is 1–4096 characters, `parse_mode` is optional,
`link_preview_options.is_disabled` turns previews off; a callback query must be
answered with `answerCallbackQuery`. Not verified from that page here: that a bot cannot
start a chat with a user who has not messaged it first (the reason `connect` says to
send `/start`); if it can, nothing changes, since the allowlist decides.
