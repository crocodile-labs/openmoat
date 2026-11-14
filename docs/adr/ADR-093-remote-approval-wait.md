# ADR-093: The hook waits a bounded time for a remote answer

Status: accepted · Date: 2026-11-13 · Builds on ADR-078 · Number 092 is held by
another open change, so this decision is 093.

## Context

ADR-078 sends a call held for review to the approvers' phones and lets an approval run
the same call once, on its next try. The guard answers the hook at once with the
`review`, because "the hook never waits": `GUARD_BUDGET_S` is 30 s and Claude Code,
Codex, the Continue CLI, GitHub Copilot CLI and others run a call whose hook timed out.

In use, that order is wrong for agents that prompt (Claude Code, Cursor, Gemini CLI):
the agent's own prompt appears at once, and an approval from the phone applies only to
a retry nobody makes. A person who approved on the phone found the agent still waiting
at its prompt.

The rejection in ADR-078 was of waiting *minutes* for a person. A few seconds, kept
well inside the guard's budget and each host's hook timeout, is a different trade: the
person is usually looking at the phone when the request arrives.

## Decision 1: wait only while a listener runs

1. `openmoat approvals listen` writes `~/.moat/remote/listening.json` after every round
   that reached the channel: the connected channel's name and the time, signed with the
   approval key under its own domain (`openmoat-remote-listening-v1`). It removes the
   file when it returns; after Ctrl-C the beat goes stale.
2. A beat is **live** when its signature verifies with the key, it names the connected
   channel, and it is at most 15 s old (`LIVE_MS`) and at most 2 s ahead of the guard's
   clock. Anything else (no file, another key, another channel, an edited time) is no
   listener.
3. With no live listener the guard does not wait at all: the gate behaves exactly as
   ADR-078 describes.
4. While the wait is on, `listen` polls the channel every 2 s instead of 25 s, so a
   request the guard writes during a poll is sent within about 2 s. With the wait off
   (0) it keeps the 25 s poll.

The beat cannot loosen a decision. It decides only *whether the guard waits*. An
agent cannot write it (`kernel-self` denies writes under `~/.moat`) or sign one (it
cannot read the key). If it could, the guard would wait for nothing, within the limits
below, and then answer `review` as before: delay, never an allow.

## Decision 2: how long, from the host's spec

The wait for one call is the least of:

1. **The person's setting**, `wait_s` in the signed remote settings
   (`~/.moat/remote/settings.json`), set by `openmoat approvals wait <seconds>`, a
   person-only command like `allow`: 0 to 25 s, 20 s when not set, 0 turns the wait off.
   It lives beside the request expiry, not in a policy file, so no repository policy or
   pack can set it. The field is left out of the file while unset, so settings signed
   before it existed still verify, and `connect` keeps it on reconnect.
2. **The guard's budget**: the whole guard run ends `ANSWER_MARGIN` (5 s) before
   `GUARD_BUDGET_S` (30 s), so recording and answering keep 5 s on a loaded machine
   (`MAX_WAIT_S` = 25). The time the guard already spent (taint, lock, compile) comes
   off. Under `openmoat run`, the guard outside the sandbox keeps another
   `RELAY_MARGIN` (5 s): the guard inside, which the host waits for, started earlier and
   counts its own budget from then.
3. **The host's hook timeout**, from its spec's `hook_failure` facts (ADR-079), never a
   list of hosts (`remote::wait::host_limit`):
   - `times_out: Blocks`: the guard run ends `ANSWER_MARGIN` before `timeout_s`
     (Hermes Agent's 30 s callback limit gives 25 s);
   - every other outcome (`Runs`, `NotDocumented`, `BlocksFrom`, whose version is not
     checked per call, `BlocksWhenMissing`): only a quarter of `timeout_s`
     (`FAIL_OPEN_SHARE`), less the margin, so the wait stays far below the point where
     the host would run the call unchecked. A fail-open host with a 20 s timeout gets no
     wait;
   - no `timeout_s`: no wait.

A unit test checks the bound for every host in the registry; today every host gets
25 s (20 s under `openmoat run`), cut to the person's setting.

## Decision 3: what the wait does

1. The gate runs as ADR-078 says. When it leaves the call held on a request (sent now,
   or sent on an earlier try and not answered yet), it waits: it looks for the answer
   file every 100 ms (one `stat`), checks the beat every second, and stops when the
   time is up, the beat goes stale or the request expires. The guard's phase is
   `approval`, so a hang recorded meanwhile says so.
2. **An answer** is checked by the same code as the next try (`gate::answered`):
   signature, digest, request id, expiry, channel, and the approver against the
   settings read again when the answer arrives (an approver removed during the wait no
   longer counts). An approval is used through the same `used/<id>` create-new marker,
   so of a waiting guard and a retry, or of two waiting guards, exactly one allows; the
   other sees the marker and keeps the `review`. A deny denies at once (`remote-denied`).
   A `cut` or `redacted` request still uses no approval.
3. **The audit row** of an approved call is ADR-078's: `allow`, rule `approved-remote`,
   the approver and channel in the reason, plus "answered while the hook waited N s".
4. **No answer in time, or any error** (unreadable settings, a full disk): the `review`
   as before, with a reason saying no answer came within N s and that an approval
   before the expiry still lets the same call run once on the next try. The request
   stays for the listener.
5. The approver's prompt and the listener's reply say the call runs "now if the agent
   is still waiting, or when it tries the call again".

## Consequences

- On agents that prompt, an approval given within the wait runs the call without the
  agent's prompt; the prompt appears only after the wait. Every held call on a machine
  with a live listener takes up to the wait before the prompt shows, so a person at
  the terminal waits too; `openmoat approvals wait 0` turns that off.
- On agents that cannot prompt (Codex, the Continue CLI), the wait turns a deny that
  asks for a retry into an allow when the approver answers in time.
- `listen` makes a request to the channel every 2 s while the wait is on (one
  `getUpdates` long poll each for Telegram), not every 25 s.
- Every limit of ADR-078 holds: the guard still answers within its budget, nothing but
  a `review` is touched, and every failure keeps the `review`.

## Threat model

| Threat | What stops it | Test |
|---|---|---|
| An agent fakes a listener to delay calls | the beat must be signed with the key it cannot read, and writes under `~/.moat` are denied; a fake one only adds a bounded delay | `remote::tests::wait::only_a_fresh_beat_signed_with_the_key_is_a_listener`, `without_a_listener_the_hook_does_not_wait` |
| A forged answer during the wait | the same checks as the next try | `remote::tests::wait::a_forged_answer_during_the_wait_changes_nothing` |
| An approval used twice by a waiting guard and a retry | the create-new `used/<id>` marker | `remote::tests::wait::two_waiting_guards_use_one_approval_once` |
| An approver removed while a guard waits | settings read again when the answer arrives | `remote::tests::wait::an_approver_removed_during_the_wait_no_longer_counts` |
| The wait makes the host time the hook out and run the call | the wait ends inside the guard's budget less a margin, and inside a quarter of a fail-open host's timeout, from the spec | `remote::tests::wait::every_host_s_wait_ends_safely_before_its_hook_times_out` |
| Under `openmoat run` the inner guard gives up first | the relayed guard keeps another 5 s | `remote::tests::wait::the_wait_is_capped_by_the_host_the_budget_and_the_time_already_spent`, e2e `remote_approvals::the_guard_openmoat_run_relays_to_waits_too` |

## Rejected

- **A filesystem watch** (FSEvents, inotify): a new dependency per OS for a wait of
  seconds; a 100 ms `stat` loop costs nothing noticeable.
- **Waiting without a listener**: nothing can answer, so every held call would only be
  slower.
- **The wait in the policy file**: a repository policy or a pack could then set it; it
  is the person's, like the expiry and the approvers.
- **A separate thread in `listen` for the beat**: it would report a listener whose
  channel is stuck; the beat follows rounds that reached the channel.
