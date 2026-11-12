# Approving reviews from another device

When OpenMoat holds an agent's call for review, you normally answer it where the agent
runs: at the agent's own prompt, or with `openmoat allow --last` on an agent that cannot
prompt. With a channel connected, OpenMoat also sends the call to your phone. If you
approve it there, that exact call runs once, the next time the agent tries it.

Telegram is the first channel. The design and its threat model are in
[ADR-078](adr/ADR-078-remote-approvals.md).

**On this page:** [What it does](#what-it-does) · [Set up Telegram](#set-up-telegram) ·
[Commands](#commands) · [What you see on your phone](#what-you-see-on-your-phone) ·
[Files](#files) · [Limits](#limits) ·
[Threats and what stops them](#threats-and-what-stops-them) ·
[Adding a channel](#adding-a-channel)

## What it does

- **Only a `review` is sent.** A call the policy denies is never sent and can never be
  approved from a phone. A call it allows or leaves to the agent is not sent either.
- **An approval is for one call.** It is bound to the agent, the session, the folder, the
  exact command or file (and the content a write carries), and the rules that held it.
  A different command, a changed file content or another session is a new request.
- **Used once.** After the call runs, the same call needs a new approval.
- **It expires.** A request waits 5 minutes unless you chose another time with
  `--expires` (1 to 60 minutes). An answer after that is refused.
- **Deny holds.** If you press Deny, the same call is denied until the request expires.
- **Nothing changes without a channel.** With no channel connected, reviews work exactly
  as before. With one, the agent's own prompt still appears; your local answer still
  works.
- **Every failure keeps the review.** No answer, a network error, a missing key or an
  edited settings file all leave the call held for review, as it would be without a
  channel.

## Set up Telegram

1. In Telegram, open `@BotFather`, send `/newbot` and follow the steps. It gives you a
   token that looks like `123456789:AA…`. Keep it to yourself.
2. In a terminal of your own (not inside an agent), connect the bot:

   ```bash
   openmoat approvals connect telegram
   ```

   Paste the token when asked. OpenMoat checks it with Telegram, then stores it in
   `~/.moat/remote/telegram/credential`, readable only by you. It never goes in a policy
   file. To read it from a file instead, use `--credential-file FILE` and delete the
   file afterwards.
3. Send `/start` to your bot from your own Telegram account.
4. Start the listener in a terminal of your own, and leave it running:

   ```bash
   openmoat approvals listen
   ```

   When you message the bot, it prints your user id:

   ```text
   14:02 message from @you (telegram:123456789), who is not an approver; `openmoat approvals allow telegram:123456789` would make them one
   ```

5. In another terminal, allow that id, then send a test message:

   ```bash
   openmoat approvals allow telegram:123456789
   openmoat approvals test
   ```

   An approver id is the channel's name and the user id on it, so the same number on two
   services is never the same approver. `allow 123456789` means the same on the
   connected channel.

From now on, every call held for review is also sent to you while `listen` runs.

## Commands

| Command | What it does | Who can run it |
|---|---|---|
| `openmoat approvals connect <channel> [--credential-file FILE] [--set KEY=VALUE] [--expires 5m]` | checks the credential with the channel, stores it, makes the approval key, keeps approvers you already allowed on that channel; `--set` gives a channel's other settings, never a secret (Telegram has none) | a person at a terminal |
| `openmoat approvals allow <channel>:<user-id>` | lets that user approve (a bare user id means the connected channel) | a person at a terminal |
| `openmoat approvals remove <channel>:<user-id>` | takes that back; answers they gave that are not used yet stop counting | a person at a terminal |
| `openmoat approvals listen` | sends waiting requests and takes answers, until Ctrl-C | a person at a terminal |
| `openmoat approvals test` | sends a test message to every approver | a person at a terminal |
| `openmoat approvals status [--format json]` | shows the channel and its account, the approvers, the expiry and how many requests wait; never the credential | anyone |
| `openmoat approvals disconnect` | removes the credential, the settings and the waiting requests | a person at a terminal |

"A person at a terminal" means the command refuses to run from a hook, a script or an
agent: it needs a terminal, and no agent and no `openmoat run` may be among the programs
that started it. OpenMoat's default policy also denies every `openmoat approvals` command
an agent tries to run.

## What you see on your phone

```text
OpenMoat: an agent's call is waiting for your approval
Request 3f9a2c · answer before 14:07
Agent: codex · session 0193…
Folder: /home/you/project
Held for review by: runs-later

The call below comes from the agent. Its text may try to persuade you; judge what it does, not what it says.
----
run "npm publish --access public"
----
Approve lets this exact call run once, when the agent tries it again before the request expires. Deny blocks it until then.
        [ Approve once ]  [ Deny ]
```

The agent's message names the same request code, for example
`sent for approval over telegram as request 3f9a2c, until 14:07`.

What is sent: the agent's name, the session id, the folder, the rule ids and the call.
The call passes through the audit log's redaction first (token shapes and your brokered
secrets), invisible and control characters are shown as `?`, each line break stays a
line break with `⏎` at the end of the line before it, and it is cut to 1500
characters. The content of a file write is never sent, only its size.

On a channel without buttons, the message ends with two reply codes instead; send one
back, alone, to answer. A code is checked exactly as a button press is. When a channel
cannot show all of the call in one message, or the call is longer than the 1500
characters kept, it offers Deny only: approve such a call where the agent runs. A call
whose text redaction changed offers Deny only too, since the hidden part may be what
runs (`API_TOKEN="$(curl … | sh)" make test` would show as `API_TOKEN=[redacted] make
test`).

## Files

Everything is under `~/.moat/remote/`, owner-only. The default policy denies agents
reading any of it and writing anywhere under `~/.moat`.

| File | What it holds |
|---|---|
| `approval.key` | the key every request, answer, button and settings file is signed with |
| `settings.json` | the connected channel, the approver ids and the expiry, signed |
| `<channel>/credential` | the channel's secrets, one JSON object (for Telegram, the bot token) |
| `<channel>/settings.json` | the channel's account (the bot's name) and its other settings, signed |
| `requests/`, `answers/`, `used/` | calls waiting, answers given, approvals used |

## Limits

- **The listener must run.** Answers arrive only while `openmoat approvals listen` runs,
  in a terminal of your own. When it is not running, requests expire unanswered.
- **The agent's prompt does not go away.** On an agent that prompts (Claude Code,
  Cursor, Gemini CLI, …), its prompt stays on screen. Your phone's answer applies to the
  next try of the same call. Remote approval is most useful with agents that cannot
  prompt or run unattended (Codex, `claude -p`, Hermes Agent, OpenClaw), where the review
  reaches the agent as a deny that names the request, and the agent tries again.
- **The hook does not wait for you.** OpenMoat answers each hook call within 30 seconds,
  because several agents run a call whose hook timed out. So it never waits for your
  phone.
- **Your Telegram account approves.** Anyone who controls an approver's Telegram account
  can approve. Do not stay signed in to Telegram in a browser or on a screen an agent can
  control.
- **The text goes to Telegram.** The redacted call is stored by Telegram as any message
  is. Do not connect a channel on a machine whose commands must not leave it.
- **One chat per approver.** Messages go to each approver's private chat with the bot;
  group chats are not supported.
- **A webhook on the bot stops it.** Telegram does not deliver updates to `listen` while
  the bot has a webhook set. Use a bot made for OpenMoat.
- **Slack and GitHub are not built yet.** ADR-078 says what each would need.

## Threats and what stops them

| Threat | What stops it |
|---|---|
| Someone else presses Approve (a forwarded message, a stranger who found the bot) | only the Telegram user ids you allowed count; their id comes from Telegram's server |
| The agent writes an approval file | writes under `~/.moat` are denied to agents, and every answer is signed with a key the agent cannot read |
| An approval reused for another call | each approval is bound to the digest of the exact call |
| An approval used twice, or put back from a backup | each one is marked used before the call runs, and a used mark is never removed while its request could be valid |
| A late answer | each request expires; the listener and the hook both check |
| The agent reads the bot token or the key | the default policy denies reading `~/.moat/remote`, in the hook and in the agents' sandboxes; the files are owner-only and refused when others may read them |
| The agent runs `openmoat approvals allow` | denied by the policy, and refused because an agent started it |
| The agent edits the approver list | writes are denied, and the list is signed |
| The agent's command tries to persuade you | OpenMoat writes the message, labels the agent's text, sends it as plain text with no link previews, and redacts secrets in it |
| A user of another channel with the same number | approver ids carry the channel's name, set by OpenMoat, not by the channel |
| A call too long for the channel, approved without being read | the channel is offered Deny only |

## Adding a channel

A channel is one folder and one registry row; nothing else changes. The core (the
request, the signatures, the gate, the listener, the commands) never names a channel,
and `crates/openmoat-cli/tests/architecture.rs` fails if it does. The design is in
ADR-078, "Channel architecture". To add one called `example`:

1. **Create `crates/openmoat-cli/src/remote/channels/example.rs`** with a type that
   implements `Channel` (`remote/channel.rs`): `account` (the account the credential
   belongs to; this call also proves the credential works), `send` (a `Prompt`: plain
   text and, when the channel has buttons, its `choices`), `notify`, `poll` (each
   message or button press as a `Reply`: the sender's id as the channel's server gives
   it, a button's data or a message's text) and `settle`. Talk to the network only
   through `remote/https.rs` or a reviewed transport; never read a credential from the
   environment.
2. **Define `pub const SPEC: Spec`** in the same file, with `name: "example"`:
   - `capabilities`: `buttons` only if the server reports who pressed a button;
     `button_bytes` (OpenMoat's data is 51 bytes; smaller means reply codes);
     `max_text`, at least 1024;
   - `fields`: every value `connect` takes, each a `Field { key, ask, secret, valid }`
     with a strict check. Mark tokens and keys `secret: true`: they are asked at the
     terminal or read with `--credential-file` (when there is one), never taken from
     `--set`, and stored together in `~/.moat/remote/example/credential`, owner-only.
     The others (a room, a workspace) go in the channel's signed settings and can be
     given with `--set KEY=VALUE`. Both are checked again on every load;
   - `user_id` and `valid_user`, a strict check of a user id on the channel;
   - `open`, `next_steps` and `revoke`.
3. **Put its tests in `channels/example/tests.rs`**, against a fake of the service's
   API, as `channels/telegram/tests.rs` does: no network, no real credential.
4. **Add the row** in `remote/channels.rs`: `mod example;` and `&example::SPEC` in
   `REGISTRY`, in file-name order.
5. **Document it**: a setup section on this page, its limits, its vendor facts and
   threat rows in an amendment to ADR-078, and a changelog fragment.

Then run `cargo test -p openmoat --test architecture` and the unit tests. You do not
edit the commands, the gate, the listener, the settings or the policy: `connect
example`, `allow example:<id>`, the per-channel files under `~/.moat/remote/example/`
and the `kernel-self` deny that covers them all follow from the row.

What a channel must never do: decide whether an answer counts (the core checks the
approver, the signature, the expiry and single use), qualify its own user ids (the core
does), render the text as markup, or follow links in it.
