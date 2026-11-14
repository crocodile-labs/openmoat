//! What `openmoat guard` does with a `review` while a channel is connected
//! (ADR-078): use a valid answer once, or send the call for one and, while
//! the listener runs, wait a bounded time for it (ADR-093, [`super::wait`]).
//! Every error leaves the `review` as it was (Decision 4); nothing but a
//! `review` is touched (Decision 1.1).

use anyhow::{Result, bail};
use openmoat_audit::KnownSecrets;
use openmoat_core::{Action, Decision, Verdict};
use openmoat_hosts::{HookEvent, HookRequest};

use super::answer::{self, Answer};
use super::refused::Approved;
use super::request::{self, Request};
use super::settings::Settings;
use super::store::Store;
use super::wait::{self, Hold, Waited};
use super::{APPROVED_RULE, DENIED_RULE, hex};
use crate::proxy_session::Key;

/// The most requests that may wait at once; past it a review is not sent, so
/// an agent that keeps trying new calls cannot flood the approver's phone.
pub const MAX_WAITING: usize = 20;

/// [`gate_used`]'s decision alone, as most tests read it.
#[cfg(test)]
pub fn gate(
    store: &Store,
    request: &HookRequest,
    decision: Decision,
    known: &KnownSecrets,
    now_ms: i64,
) -> Decision {
    gate_used(store, request, decision, known, (now_ms, &Hold::NONE)).0
}

/// `decision` for `request` once remote approval has had its say, at
/// `now_ms`, waiting for an answer within `hold`, with the approval this
/// call used, if one was: should the call be refused after all,
/// [`Approved::refused`] tells the approver.
pub fn gate_used(
    store: &Store,
    request: &HookRequest,
    decision: Decision,
    known: &KnownSecrets,
    (now_ms, hold): (i64, &Hold<'_>),
) -> (Decision, Option<Approved>) {
    if decision.verdict != Verdict::Review
        || !matches!(
            request.event,
            HookEvent::PreToolUse | HookEvent::PreToolUseNoPrompt
        )
        || !store.connected()
    {
        return (decision, None);
    }
    let Some(action) = &request.action else {
        return (decision, None);
    };
    match decide(store, request, action, &decision, (known, now_ms)) {
        Ok(Step::Decided(answered, used)) => (answered, used.map(|r| Approved::new(store, r))),
        Ok(Step::Held {
            held,
            open,
            key,
            settings,
        }) => match wait::hold(store, &key, &settings, (&open, &held), hold) {
            Ok(Waited::Not) => (held, None),
            Ok(Waited::NoAnswer(waited)) => {
                let reason = format!(
                    "no answer over {} within {} s; an approval before {} still lets the same \
                     call run once",
                    settings.channel,
                    waited.as_secs(),
                    crate::time::clock(open.expires_ms)
                );
                (with_reason(held, reason), None)
            }
            Ok(Waited::Answered(answered, waited)) => {
                let (answered, used) = *answered;
                let reason = format!("answered while the hook waited {} s", waited.as_secs());
                (
                    with_reason(answered, reason),
                    used.map(|r| Approved::new(store, r)),
                )
            }
            Err(error) => (
                with_reason(held, format!("stopped waiting for an answer: {error:#}")),
                None,
            ),
        },
        Err(error) => (
            with_reason(decision, format!("not sent for remote approval: {error:#}")),
            None,
        ),
    }
}

fn with_reason(mut decision: Decision, reason: String) -> Decision {
    decision.reasons.push(reason);
    decision
}

/// What [`decide`] leaves for [`gate_used`].
enum Step {
    /// The decision, and the request whose approval the call used, if one was.
    Decided(Decision, Option<Request>),
    /// The call is held for review on request `open`, sent now or before and
    /// not answered yet; the gate may wait for its answer.
    Held {
        held: Decision,
        open: Request,
        key: Key,
        settings: Settings,
    },
}

/// The decision a valid answer to `open` on file gives this call, with the
/// request whose approval it used, if one was; `None` while there is no
/// answer an approver of `settings` gave for exactly this request.
pub(super) fn answered(
    store: &Store,
    key: &Key,
    settings: &Settings,
    open: &Request,
    decision: &Decision,
) -> Result<Option<(Decision, Option<Request>)>> {
    let Some(answer) = store.answer(&open.id) else {
        return Ok(None);
    };
    if !answer.answers(key, open)
        || answer.channel != settings.channel
        || !settings.approver(&answer.approver)
    {
        return Ok(None);
    }
    let decided = used(store, open, &answer, decision)?;
    let approved = decided.rules.iter().any(|r| r == APPROVED_RULE);
    Ok(Some((decided, approved.then(|| open.clone()))))
}

/// The decision once remote approval had its say: an approval used, an
/// approver's deny, or the `review` with a reason naming the request sent or
/// waiting. An error keeps the `review` ([`gate_used`] adds why).
fn decide(
    store: &Store,
    request: &HookRequest,
    action: &Action,
    decision: &Decision,
    (known, now_ms): (&KnownSecrets, i64),
) -> Result<Step> {
    let key = Key::load(&store.key_path())?;
    let settings = Settings::load(&store.settings_path(), &key)?;
    let digest = request::digest(request, action, decision)?;
    let mut waiting = 0;
    let mut open = None;
    for found in store.requests()?.into_iter().flatten() {
        if !found.verified(&key) || found.expired(now_ms) {
            continue;
        }
        waiting += 1;
        if found.digest == digest {
            open = Some(found);
        }
    }
    if let Some(open) = open {
        if let Some((decided, used)) = answered(store, &key, &settings, &open, decision)? {
            return Ok(Step::Decided(decided, used));
        }
        let held = with_reason(
            decision.clone(),
            format!(
                "waiting for approval over {} as request {} until {}; once approved, the same \
                 call runs once",
                settings.channel,
                open.code(),
                crate::time::clock(open.expires_ms)
            ),
        );
        return Ok(Step::Held {
            held,
            open,
            key,
            settings,
        });
    }
    if waiting >= MAX_WAITING {
        bail!("{MAX_WAITING} requests are already waiting");
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| anyhow::Error::msg(e.to_string()))?;
    let expiry_ms = i64::try_from(settings.expiry_s.saturating_mul(1000)).unwrap_or(i64::MAX);
    let shown = request::shown(request, action, known);
    let mut new = Request {
        version: request::VERSION,
        id: hex(&id),
        digest,
        host: request.host.id().to_owned(),
        session: request.session_id.clone(),
        cwd: request.cwd.clone(),
        tool: request.tool.clone(),
        rules: decision.rules.clone(),
        shown: shown.text,
        cut: shown.cut,
        redacted: shown.redacted,
        created_ms: now_ms,
        expires_ms: now_ms.saturating_add(expiry_ms),
        mac: String::new(),
    };
    new.sign(&key)?;
    store.put_request(&new)?;
    let held = with_reason(
        decision.clone(),
        format!(
            "sent for approval over {} as request {}, until {}; once approved, the same call \
             runs once",
            settings.channel,
            new.code(),
            crate::time::clock(new.expires_ms)
        ),
    );
    Ok(Step::Held {
        held,
        open: new,
        key,
        settings,
    })
}

/// The decision a valid `answer` to `open` gives this call: an approval used
/// once, or the approver's deny.
fn used(store: &Store, open: &Request, answer: &Answer, decision: &Decision) -> Result<Decision> {
    let by = format!(
        "{} by {} on {} (request {})",
        answer.verdict.word(),
        answer.approver,
        answer.channel,
        open.code()
    );
    match answer.verdict {
        answer::Verdict::Deny => Ok(Decision::single(
            Verdict::Deny,
            DENIED_RULE,
            format!("{by}; the same call is denied until the request expires"),
        )),
        answer::Verdict::Approve => {
            // No prompt offers Approve for such a request; an approval for
            // one anyway is not used.
            if open.deny_only().is_some() {
                return Ok(with_reason(
                    decision.clone(),
                    format!(
                        "request {} hides part of the call from the approver, so it can only \
                         be approved where the agent runs",
                        open.code()
                    ),
                ));
            }
            // The replay store first: a racing guard, or an answer put back
            // after use, finds the marker and keeps the review.
            if store.used(&open.id) || !store.use_once(&open.id)? {
                return Ok(with_reason(
                    decision.clone(),
                    format!("request {} was approved once and is used", open.code()),
                ));
            }
            store.forget(&open.id);
            Ok(Decision::single(
                Verdict::Allow,
                APPROVED_RULE,
                format!("{by}, for this one call"),
            ))
        }
    }
}
