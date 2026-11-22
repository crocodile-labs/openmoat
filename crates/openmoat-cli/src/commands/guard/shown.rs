//! What a person was shown at a review, beside what ran (OWASP ASI09,
//! ADR-110): the held call's row carries the prompt's exact text, and when the
//! host reports that the call ran, a row beside it says whether the action
//! that ran is the one that was shown.
//!
//! Only where the host gives both ends: a prompt (a `review` it shows a person)
//! and a report after the call with the same call id (Claude Code's
//! `PostToolUse`, ADR-057). A host that cannot prompt gets the `review` as a
//! `deny`, so nothing of it runs and nothing is shown to approve.

use anyhow::Result;
use openmoat_audit::{KnownSecrets, NewEvent, RAN_AFTER_REVIEW_TOOL, SHOWN_PREFIX, Store};
use openmoat_core::rule_id::{REVIEW_RAN_AS_SHOWN, REVIEW_RAN_CHANGED};
use openmoat_core::{Action, Decision, Verdict};
use openmoat_hosts::{HookEvent, HookRequest, Host};

/// `recorded` with the text the host's prompt shows for `told` (the decision
/// the host is answered with) when that answer holds the call for review;
/// `None` otherwise. The text is redacted when recorded, as every reason is.
pub(super) fn with_shown(
    host: Host,
    event: &HookEvent,
    told: &Decision,
    recorded: &Decision,
) -> Option<Decision> {
    let answered = host.answer(event, told);
    if answered.verdict != Verdict::Review {
        return None;
    }
    let mut with = recorded.clone();
    with.reasons.push(format!(
        "{SHOWN_PREFIX}{}",
        openmoat_hosts::reason_line(&answered)
    ));
    Some(with)
}

/// After call `request` ran (the host's report, with `ran` its action): when
/// its row held it for review, record beside it whether `ran` is the action
/// held. Nothing for a call without a call id, which no row can be matched by.
/// `known` gives the secret values the guard masks (read only for a held call):
/// the action that ran is compared as the guard recorded the held one.
pub(super) fn ran(
    mut store: Store,
    host: Host,
    request: &HookRequest,
    ran: Option<&Action>,
    known: impl FnOnce() -> Result<KnownSecrets>,
) -> Result<()> {
    let Some(call_id) = request.call_id.as_deref() else {
        return Ok(());
    };
    if store
        .held_for_review(host.id(), &request.session_id, call_id, ran)?
        .is_none()
    {
        return Ok(());
    }
    store.set_secrets(known()?);
    let Some(held) = store.held_for_review(host.id(), &request.session_id, call_id, ran)? else {
        return Ok(());
    };
    let shown = held.shown.as_deref().unwrap_or("(not recorded)");
    let (rule, reason, action) = if held.same_action {
        (
            REVIEW_RAN_AS_SHOWN,
            format!(
                "event {} held this call for review; what ran is the action held there. \
                 {SHOWN_PREFIX}{shown}",
                held.id
            ),
            None,
        )
    } else {
        (
            REVIEW_RAN_CHANGED,
            format!(
                "event {} held this call for review, but the action that ran is not the one \
                 held there: its input changed after it was shown (this row's action is what \
                 ran). {SHOWN_PREFIX}{shown}",
                held.id
            ),
            ran,
        )
    };
    let decision = Decision::single(Verdict::Allow, rule, reason);
    store.record(&NewEvent {
        host: host.id(),
        session_id: &request.session_id,
        call_id: Some(call_id),
        cwd: request.cwd.as_deref(),
        tool: RAN_AFTER_REVIEW_TOOL,
        action,
        decision: &decision,
        latency_us: 0,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
