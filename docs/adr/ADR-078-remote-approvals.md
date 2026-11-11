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
   `~/.moat/remote/<channel>/credential` (`telegram/credential`), owner-only, read the
   same way. It is never put in a
   policy file, a command line, an environment variable, the audit log or an error: the
   connector reads it from a file the person names or from the controlling terminal, and
   no message OpenMoat prints contains a request URL (the token is part of Telegram's).
3. **The settings** (`~/.moat/remote/settings.json`: which channel, the approvers, the
   expiry) and each channel's own settings (`~/.moat/remote/<channel>/settings.json`:
   its account and the answers to its `connect` questions) are signed with the approval
   key, so a file an attacker wrote without the key is refused, and with it every remote
   answer.
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

1. **An allowlist of approver ids** (`approvers`, each `<channel>:<user id>`, see
   "Channel architecture"), changed only by
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

The text the approver sees is built by OpenMoat, not the agent: the host, the session,
the folder, the ids of the rules that held the call, the request code, the expiry, and the
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
  listener loop, prompt shaping, and the channel contract (`channel.rs`). It does no
  network I/O.
- `remote/channels/telegram.rs`: the Telegram channel: Bot API calls over the shared
  HTTPS transport (`remote/https.rs`, rustls with the system roots, the proxy's TLS
  stack), long polling `getUpdates` (no inbound port, no webhook).
- `openmoat approvals connect <channel> | allow | remove | status | test | listen |
  disconnect`. `status` is read-only and needs no terminal; every other command is
  person-only.
- The layout is described in "Channel architecture" below.
- Unit tests drive the core with a fake channel; no test uses a real token or network.

## Threat model

| Threat | What stops it | Test |
|---|---|---|
| Spoofed approver: someone else messages the bot or presses a forwarded button | the sender's id from Telegram's server must be on the allowlist the person set | `remote::tests::an_answer_from_someone_not_allowed_is_refused` |
| Forged approval file written by the agent | writes under `.moat` denied; answers signed with a key the agent cannot read | `remote::tests::an_answer_signed_with_another_key_is_refused`, conformance `T9-write-remote-answer` |
| Approval for one call used for another (changed command, content, session, project) | answer bound to the request digest | `remote::tests::an_approval_answers_only_its_own_call` |
| Replay of a used approval, or two guards racing | create-new `used/<id>` before allowing | `remote::tests::an_approval_is_used_once`, `remote::tests::a_restored_answer_is_not_used_again` |
| Stale approval (late answer, old answer file) | request expiry checked by `listen` and again by the guard | `remote::tests::an_expired_request_is_not_approved` |
| Agent reads the bot token or the key | `kernel-self` read deny, sandbox deny, owner-only files with mode check | conformance `T9-read-remote-token`, `T9-cat-remote-key`, `T9-read-moved-remote-token` |
| Agent runs `openmoat approvals allow` or `listen` | `kernel-self` shell deny; ancestry check | conformance `T9-approvals-allow`, `T9-approvals-listen-path`; e2e `approvals_commands_need_a_person` |
| Agent edits the allowlist file | writes denied; settings signed | `remote::tests::tampered_settings_are_refused` |
| Prompt injection in the request text | OpenMoat's own framing, plain text, escaping, redaction, length cap, no previews | `remote::tests::text::the_prompt_escapes_and_labels_the_agents_text` |
| A remote approval lifting a deny | the gate acts on `review` only | `remote::tests::only_a_review_is_sent`, e2e `a_deny_is_never_sent_for_approval` |
| Channel down, key missing | decision unchanged (`review`) | `remote::tests::without_a_key_the_review_stays` |
| An approver of one channel answering as an approver of another (same number on two services) | approver ids qualified by the core with the registered channel name; settings refuse another channel's id; the guard refuses an answer from another channel | `remote::tests::another::ids_of_two_channels_never_collide` |
| A call too long for the channel to show, approved unread | Deny only: the approve code is never sent | `remote::tests::text::a_call_the_channel_cannot_show_whole_can_only_be_denied` |
| Agent reads a channel's credential under the per-channel layout | `kernel-self` read deny on `~/.moat/remote/**` | conformance `T9-read-remote-channel-credential`, `T9-cat-remote-channel-credential-glob`, `T9-read-moved-remote-channel-credential` |

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
  It fits the channel contract (see "Channel architecture"); it is left out until that
  client is reviewed.
- **GitHub**: an answer as a PR comment or check run needs a GitHub App or token with
  `issues:write`/`checks:write` and polling of comments; the approver is the comment's
  author login, which must also be checked against the repository's permission. It fits
  the contract as a polling channel; it is left out because a repository's commenters are a
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

## Amendment 2026-11-11: Channel architecture

More channels will follow Telegram (Slack, GitHub, Discord, Matrix, email, a webhook,
ntfy, Signal, WhatsApp). Adding one must mean a new folder and one registry row, no
edit to the core, and no weaker check. Before fixing the layout we read how five
open-source projects structure their messaging channels, from their source: Hermes
Agent, OpenClaw (its core and its `extensions/`), NanoClaw, Errbot and matterbridge.

### What other projects do

Read 2026-11-11 at hermes-agent `77e16d5`, openclaw `d9094ab`, errbot `af1bb75` and
matterbridge `c4157a4`.

| | Hermes Agent | OpenClaw | Errbot | matterbridge |
|---|---|---|---|---|
| Interface | `BasePlatformAdapter`: `connect`, `disconnect`, `send`, `get_chat_info`; optional `edit_message` answers "not supported" so callers send anew | `ChannelPlugin`: a set of optional sub-adapters (`config`, `outbound`, `gateway`, `security`, `allowlist`, `approvalCapability`, …) | `Backend`: `send_message`, `build_identifier`, `serve_once`/`serve_forever` | `Bridger`: `Send`, `Connect`, `JoinChannel`, `Disconnect`; inbound on a shared Go channel |
| Capabilities | class attributes (`MAX_MESSAGE_LENGTH`, `supports_code_blocks`, …); approval buttons inferred from an overridden method | typed `ChannelCapabilities` (`edit`, `threads`, `reactions`, `polls`, …), `textChunkLimit` | none; a size limit by override, cards fall back to text | almost none; per-account string keys (`MessageLength`, `EditDisable`) |
| Approvals | base class builds the text and the `(label, choice)` rows; one callback form `appr:<id>:<choice>` for all; plain-text `/approve` where a platform has no buttons; Deny only when the card cannot show the whole command | core owns `/approve` and the fallback; a fallback that cannot enforce the reviewer policy is refused; Telegram callbacks versioned and checked against 64 bytes | — | — |
| Config and secrets | `PlatformConfig` with typed token fields and an untyped `extra`; secrets from declared env vars, read through one scoped helper | `channels.<id>` with JSON Schema per plugin; a per-channel secret contract names the secret fields | one untyped `BOT_IDENTITY` dict | one wide TOML struct for every protocol |
| Identity | per-platform allowlists of bare ids; pairing files per platform, 0600 | per-channel `allowFrom`; reviewer ids are qualified, and "an unqualified raw ID cannot satisfy a space-qualified policy" | backend `Identifier` classes; ACLs are not channel-qualified | `UserID` plus `Account`/`Protocol` fields |
| Registry | `PlatformRegistry` of `PlatformEntry(name, factory, check, validate, …)`, plus a legacy factory and about 15 other places a built-in platform is added | loaded plugins, then bundled ones by id, each with a manifest and a lazy entry | `.plug` files and an entry point | a static `map[string]Factory` filled by build-tagged `init()` files |
| Fake channel | `FakePlatformAdapter` with scripted faults; local stand-ins for real APIs | `qa-channel`, a synthetic channel through the same plugin boundary | `TestBackend` with in/out queues | none found |

Sources (files read):
- Hermes Agent: [gateway/platforms/base.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/platforms/base.py),
  [gateway/platforms/ADDING_A_PLATFORM.md](https://github.com/NousResearch/hermes-agent/blob/main/gateway/platforms/ADDING_A_PLATFORM.md),
  [gateway/platform_registry.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/platform_registry.py),
  [gateway/config.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/config.py),
  [gateway/authz_mixin.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/authz_mixin.py),
  [gateway/approval_actor.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/approval_actor.py),
  [gateway/pairing.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/pairing.py),
  [gateway/platforms/webhook.py](https://github.com/NousResearch/hermes-agent/blob/main/gateway/platforms/webhook.py),
  [plugins/platforms/telegram/plugin.yaml](https://github.com/NousResearch/hermes-agent/blob/main/plugins/platforms/telegram/plugin.yaml),
  [tests/e2e/core/delivery/_fake_platform.py](https://github.com/NousResearch/hermes-agent/blob/main/tests/e2e/core/delivery/_fake_platform.py),
  [tests/fakes/platforms/_standin.py](https://github.com/NousResearch/hermes-agent/blob/main/tests/fakes/platforms/_standin.py).
- OpenClaw: [src/channels/plugins/types.plugin.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/types.plugin.ts),
  [types.core.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/types.core.ts),
  [types.adapters.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/types.adapters.ts),
  [types.config.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/types.config.ts),
  [outbound.types.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/outbound.types.ts),
  [approvals.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/approvals.ts),
  [approval-native.types.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/approval-native.types.ts),
  [registry.ts](https://github.com/openclaw/openclaw/blob/main/src/channels/plugins/registry.ts),
  [extensions/telegram/src/approval-callback-data.ts](https://github.com/openclaw/openclaw/blob/main/extensions/telegram/src/approval-callback-data.ts),
  [extensions/telegram/src/secret-contract.ts](https://github.com/openclaw/openclaw/blob/main/extensions/telegram/src/secret-contract.ts),
  [extensions/telegram/src/allow-from.ts](https://github.com/openclaw/openclaw/blob/main/extensions/telegram/src/allow-from.ts),
  [extensions/qa-channel/src/channel-base.ts](https://github.com/openclaw/openclaw/blob/main/extensions/qa-channel/src/channel-base.ts),
  [docs/plugins/sdk-channel-plugins/approvals.md](https://github.com/openclaw/openclaw/blob/main/docs/plugins/sdk-channel-plugins/approvals.md).
- Errbot: [errbot/backends/base.py](https://github.com/errbotio/errbot/blob/master/errbot/backends/base.py),
  [errbot/backends/test.py](https://github.com/errbotio/errbot/blob/master/errbot/backends/test.py),
  [errbot/backends/telegram_messenger.py](https://github.com/errbotio/errbot/blob/master/errbot/backends/telegram_messenger.py),
  [errbot/core.py](https://github.com/errbotio/errbot/blob/master/errbot/core.py),
  [errbot/backend_plugin_manager.py](https://github.com/errbotio/errbot/blob/master/errbot/backend_plugin_manager.py).
- matterbridge: [bridge/bridge.go](https://github.com/42wim/matterbridge/blob/master/bridge/bridge.go),
  [bridge/config/config.go](https://github.com/42wim/matterbridge/blob/master/bridge/config/config.go),
  [bridge/telegram/telegram.go](https://github.com/42wim/matterbridge/blob/master/bridge/telegram/telegram.go),
  [gateway/handlers.go](https://github.com/42wim/matterbridge/blob/master/gateway/handlers.go),
  [gateway/bridgemap/bridgemap.go](https://github.com/42wim/matterbridge/blob/master/gateway/bridgemap/bridgemap.go).

### How a channel is packaged and registered

Read 2026-11-11 at openclaw `83fd655`, nanoclaw `60efd61` and hermes-agent `e2a0b32`.

- **OpenClaw extensions.** Each channel is a folder under `extensions/<id>/` with a
  manifest, `openclaw.plugin.json`: `id`, `name`, `channels`, `activation`, and a
  required `configSchema` (JSON Schema; `additionalProperties: false` in Telegram,
  Slack, Discord and Matrix). More static facts sit under the `openclaw` key of its
  `package.json`: the environment variables that mean "configured", `approvalFlags`,
  `markdownCapable`, and `setup.fields[]`, each `{key, kind, sensitive, cli.flags,
  envVars}`. `index.ts` calls `defineBundledChannelEntry` with lazy specifier and export
  pairs, so setup can load without the runtime. Capabilities (`ChannelCapabilities`) are
  in code, not in the manifest. The loader refuses a manifest without `configSchema`,
  reads it with a size cap, rejects hard links and ids reserved for the core, and
  validates the plugin's configuration against the schema before importing the module.
  Bundled channel ids come from a fixed list and a generated file. Secrets are declared per
  channel by a secret contract that names the secret fields.
  Sources: [extensions/telegram/openclaw.plugin.json](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/extensions/telegram/openclaw.plugin.json),
  [extensions/slack/openclaw.plugin.json](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/extensions/slack/openclaw.plugin.json),
  [extensions/discord/openclaw.plugin.json](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/extensions/discord/openclaw.plugin.json),
  [extensions/matrix/openclaw.plugin.json](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/extensions/matrix/openclaw.plugin.json),
  [extensions/telegram/package.json](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/extensions/telegram/package.json),
  [extensions/telegram/index.ts](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/extensions/telegram/index.ts),
  [src/plugins/manifest.ts](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/src/plugins/manifest.ts),
  [src/plugins/loader-runtime-candidate.ts](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/src/plugins/loader-runtime-candidate.ts),
  [src/channels/plugins/bundled-ids.ts](https://github.com/openclaw/openclaw/blob/83fd655f3facaa19db62b62b0fa262bf3043ed2c/src/channels/plugins/bundled-ids.ts).
- **NanoClaw.** A channel implements `ChannelAdapter` (`name`, `channelType`,
  `supportsThreads`, `setup`, `teardown`, `isConnected`, `deliver`, optional `openDM`
  and others; button presses come back through `onAction`). It registers itself on
  import with `registerChannelAdapter(name, {factory, defaults, …})` into a map; a
  factory returns `null` when its credentials are missing. Main ships only the `cli`
  channel. A skill adds one by copying its adapter, appending an import to
  `src/channels/index.ts` and a pairing step to `setup/index.ts`, so adding a channel
  edits two core files. Credentials are `.env` keys, read without being put in the
  process environment, so child processes do not inherit them. User ids are
  `<channelType>:<handle>`, and `parseUserId` refuses an id with no prefix. No fake
  channel was found.
  Sources: [src/channels/adapter.ts](https://github.com/nanocoai/nanoclaw/blob/60efd61b3c7939fd9910df72a1cb66923ca40dac/src/channels/adapter.ts),
  [src/channels/channel-registry.ts](https://github.com/nanocoai/nanoclaw/blob/60efd61b3c7939fd9910df72a1cb66923ca40dac/src/channels/channel-registry.ts),
  [src/channels/index.ts](https://github.com/nanocoai/nanoclaw/blob/60efd61b3c7939fd9910df72a1cb66923ca40dac/src/channels/index.ts),
  [.claude/skills/add-telegram/SKILL.md](https://github.com/nanocoai/nanoclaw/blob/60efd61b3c7939fd9910df72a1cb66923ca40dac/.claude/skills/add-telegram/SKILL.md),
  [src/env.ts](https://github.com/nanocoai/nanoclaw/blob/60efd61b3c7939fd9910df72a1cb66923ca40dac/src/env.ts),
  [src/modules/permissions/user-dm.ts](https://github.com/nanocoai/nanoclaw/blob/60efd61b3c7939fd9910df72a1cb66923ca40dac/src/modules/permissions/user-dm.ts).
- **Hermes Agent plugins.** Each platform has `plugins/platforms/<name>/plugin.yaml`
  (`name`, `label`, `kind: platform`, `version`, and `requires_env[]`/`optional_env[]`,
  each `{name, description, prompt, url, password}`). The registry records
  `requires_env` as an activation hint before importing anything; `register(ctx)` later
  calls `ctx.register_platform(...)` with the capabilities (`max_message_length`) in
  code. Manifest validation is soft: a bad field is logged and ignored, and a
  `config_schema` mismatch only warns.
  Sources: [plugins/platforms/telegram/plugin.yaml](https://github.com/NousResearch/hermes-agent/blob/e2a0b3292bf4f62ba86d267cd1ae830005cd1005/plugins/platforms/telegram/plugin.yaml),
  [hermes_cli/plugins_manifest.py](https://github.com/NousResearch/hermes-agent/blob/e2a0b3292bf4f62ba86d267cd1ae830005cd1005/hermes_cli/plugins_manifest.py),
  [hermes_cli/plugins.py](https://github.com/NousResearch/hermes-agent/blob/e2a0b3292bf4f62ba86d267cd1ae830005cd1005/hermes_cli/plugins.py).

What we take from these three: every channel's facts are static data that can be read
without building the channel (OpenClaw's manifest, Hermes's deferred `requires_env`,
NanoClaw's `defaults`); here that is the `const SPEC`, which does no I/O. The values
`connect` takes are declared as typed fields, each with a secret flag (OpenClaw's
`setup.fields{sensitive}`, Hermes's `password: true`), so one prompt, one store and one
check serve every channel, and a channel with two secrets (Slack's bot and app tokens)
needs no core change. Settings are strict at load, as OpenClaw checks
`additionalProperties: false` before import, and unlike Hermes's warnings. Ids carry the
channel's prefix and an unprefixed id is never matched (NanoClaw, OpenClaw).

What we leave: a JSON or YAML manifest read at run time, a directory scan or a generated
id list. In a compiled Rust binary the `const SPEC` is the manifest: the compiler checks
its types, and the architecture test checks that the registry lists every channel
folder. We also leave self-registration on import (NanoClaw; in Rust, link-time
registration through `inventory` or `ctor`), because an explicit list is easier to
audit.

What we take from the first comparison: a small trait with typed capabilities, as data, not inferred (OpenClaw);
one place that builds the approval text and one data format for every channel
(Hermes); a fallback that never weakens the check, and Deny only when the call cannot
be shown whole (Hermes, OpenClaw); qualified approver ids (OpenClaw); one registry of
name to factory and facts (Hermes's `PlatformEntry`, without its second list); typed,
per-channel secrets in their own place (OpenClaw's secret contract), not one untyped
dict (Errbot) or one wide struct (matterbridge); a fake channel through the real
boundary (Errbot's `TestBackend`, OpenClaw's `qa-channel`).

What we leave: dynamic plugin loading (a channel is code that handles a credential and
decides who answered; it is compiled in and reviewed, never loaded at run time),
webhooks (they need a listening port; every channel polls or holds an outbound
connection), and edits, threads and reactions (no decision depends on them).

### Decision

1. **A channel is a folder.** `crates/openmoat-cli/src/remote/channels/<name>.rs` with
   its folder `channels/<name>/` (tests, helpers). It defines `pub const SPEC: Spec` and
   a type implementing `Channel`. Nothing outside it names the channel.
2. **One registry.** `remote/channels.rs` declares `mod <name>;` and lists
   `&<name>::SPEC` in `REGISTRY`. `Registry::check` (run on every lookup, and as a unit
   test) refuses a name that is not lowercase letters, digits and `-`, a name the store
   uses (`requests`, `answers`, `used`), a duplicate, or a channel whose messages are
   shorter than 1024 characters.
3. **The contract** (`remote/channel.rs`). `Channel` has `account`, `send`, `notify`,
   `poll` and `settle`; only a channel does network I/O, through the shared transport
   `remote/https.rs`. `Spec`, the channel's manifest as a `const`, carries the name and
   title, typed `Capabilities` (`buttons`, `button_bytes`, `max_text`), the `fields`
   `connect` takes (each `Field { key, ask, secret, valid }`), the user id's shape check,
   `open` (given the checked secrets and settings), the next steps after `connect`, and
   how to revoke the credentials. A secret field is asked at the terminal or read with
   `--credential-file`, never taken from `--set` (other programs can read a command
   line), and never shown in an error.
4. **The core adapts the message** (`remote/prompt.rs`). With buttons that hold
   OpenMoat's 51 bytes, the prompt has Approve and Deny buttons. Without, or when they
   are smaller, the text ends with the two reply codes (the same verdict, id and HMAC
   tag a button carries) and the listener takes a message whose text is exactly one;
   it is checked as a button press is, and only on such a channel. The agent's part is
   cut to fit `max_text`; when the channel cannot show all of the call kept for the
   approver, the prompt offers Deny only and the approve code is never sent.
5. **Approver ids are qualified.** Every allowlist entry and answer is
   `<channel>:<user id>` (`telegram:123`). The core qualifies a sender with the name of
   the registered spec it opened, so a channel cannot claim another channel's id.
   `openmoat approvals allow` takes `telegram:123` or a bare id on the connected
   channel, checks it with the channel's `valid_user`, and refuses another channel's
   id. Signed settings with an approver of another channel are refused at load and
   save, and the guard refuses an answer whose channel is not the connected one.
6. **Per-channel files.** `~/.moat/remote/<channel>/credential` (the secret fields as one
   JSON object, owner-only, read with `key_file::read`, and refused unless it holds
   exactly the spec's secret fields, each valid) and
   `~/.moat/remote/<channel>/settings.json` (the account and the other fields, signed
   under its own domain, bound to the channel's name, and checked against the spec's
   fields on every open). Both settings files are read with `deny_unknown_fields`. The folder name always comes from the registered spec, never from
   a file. The shared files stay where they were: `approval.key`, `settings.json`,
   `requests/`, `answers/`, `used/`. `kernel-self` already denies reading anything
   under `~/.moat/remote/**` and writing under `~/.moat/**`; new conformance fixtures
   cover the per-channel paths, by name, by glob and under a moved state directory.
   No earlier layout was released, so nothing migrates.
7. **Commands come from the registry.** `connect <channel>` takes its values from
   `REGISTRY.names()`; `--credential-file` and `--set KEY=VALUE` are the same for every
   channel. No command has a per-channel branch.
8. **The architecture test** (`crates/openmoat-cli/tests/architecture.rs`): every
   `channels/<name>.rs` has its registry row, its `mod` line and a spec carrying its
   own name, and nothing else lives under `channels/`; no core file (all of `remote/`
   outside the channels and the registry, and the commands and grammar of
   `openmoat approvals`) names a channel, in code or comments, against an allowlist
   that starts empty and only shrinks; nothing outside `remote/` reaches into a
   channel's module; no core file uses the network.
9. **A second channel proves it.** `remote::tests::another` registers a text-only
   "pager" channel with two secret fields and one setting beside the real registry and takes it
   through connect, approver ids, open, reply codes, a stranger refused, an approval
   and the one allowed call, with no core change.

Still one connected channel at a time: qualified ids and per-channel folders make
several possible later (a listener per channel) without a format change.

Every property of Decisions 1 to 6 holds unchanged: the digest binding, the HMACs, single
use, expiry, the allowlist set only by a person, and fail closed.
