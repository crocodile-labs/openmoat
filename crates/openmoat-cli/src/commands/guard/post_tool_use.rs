//! A host's report of what a call returned (Claude Code `PostToolUse`,
//! ADR-057): when the call read content an attacker may control, the
//! fingerprints of its distinctive parts are kept for the session, so a later
//! call that acts on one of them needs review (`taint::injected`).
//!
//! Nothing is decided: the call already ran, and its `PreToolUse` row is its
//! record. The one row written here is for a call that row held for review:
//! whether what ran is the action the person was shown (`shown.rs`, ADR-110).
//! The hook then reads on through the
//! session's earlier calls for its taint (`taint::catch_up`), so a long
//! session's next `PreToolUse` does not spend its time budget catching up. The lock is checked first, as for any
//! call, and what cannot be kept fails the hook (exit 2, which the host shows
//! the agent); the call is not undone.

use std::time::Instant;

use anyhow::{Context as _, Result};
use openmoat_core::{CompiledPolicy, Decision, Verdict};
use openmoat_hosts::{HookEvent, HookRequest, Host};

use crate::context;
use crate::exit::Code;
use crate::hangs::{self, Phase};
use crate::home::Home;
use crate::integrity;
use crate::taint;

/// Answer the `PostToolUse` payload `payload` for `event`: empty, exit 0 once
/// its fingerprints are kept; exit 2 with the reason on stderr when they
/// cannot be.
pub(super) fn answer(host: Host, payload: &str, event: &HookEvent) -> Code {
    hangs::enter(Phase::Parse);
    let decision = host
        .parse_request_as(payload, super::entry::event())
        .context("parsing hook payload")
        .and_then(|mut request| match std::mem::take(&mut request.event) {
            HookEvent::PostToolUse { output } => kept(host, request, &output),
            _ => Ok(Decision::new(Verdict::Allow)),
        })
        .unwrap_or_else(|error| super::kernel_error(&error));
    hangs::enter(Phase::Answer);
    super::respond(host, event, &decision)
}

/// Keep the fingerprints of `request`'s output, `output`. The decision the
/// host is answered with: an `allow` it never sees (the response is empty),
/// or the lock check's deny.
fn kept(host: Host, request: HookRequest, output: &str) -> Result<Decision> {
    let started = Instant::now();
    let home = Home::locate()?;
    hangs::enter(Phase::Lock);
    let verified = integrity::check(&home)?;
    if let Some(deny) = verified.checked.deny {
        return Ok(deny);
    }
    // A call with no action has no output to keep (an adapter gives none to
    // a tool whose output is never from outside, ADR-063): once the lock is
    // checked, nothing is placed, compiled or read. The payload was parsed in
    // full before this.
    if request.action.is_none() {
        return Ok(Decision::new(Verdict::Allow));
    }
    let drifted = verified.checked.relaxed;
    let home = verified.home;
    hangs::enter(Phase::Placed);
    let request = super::placed::placed(&home, host, request, &drifted)?;
    let Some(action) = &request.action else {
        return Ok(Decision::new(Verdict::Allow));
    };
    let cwd = request
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolving working directory")?;
    hangs::enter(Phase::Context);
    let ctx = context::eval_context(&home, Some(&cwd), None)?;
    hangs::enter(Phase::Policy);
    let policy = crate::repo::effective_policy(&home, &ctx)?;
    hangs::enter(Phase::Compile);
    let compiled = CompiledPolicy::compile(&policy, &ctx)?;
    hangs::enter(Phase::Audit);
    home.require_exists()?;
    let store = crate::audit_key::open_existing(&home)?;
    hangs::enter(Phase::Record);
    let output = taint::injected::Output {
        host,
        session: &request.session_id,
        action,
        cwd: &ctx.cwd,
        text: output,
    };
    taint::injected::record(&home, &store, &compiled, &output)?;
    // The call ran: read on through the session's history now, so the next
    // call's own fold is short (the cache row is keyed like that call's).
    hangs::enter(Phase::Taint);
    let deadline = started + super::taint_budget(host);
    taint::catch_up(
        &store,
        host,
        &request.session_id,
        &compiled,
        &ctx.cwd,
        deadline,
    );
    // A call a person approved at a review: what ran, beside what they were
    // shown (OWASP ASI09, ADR-110). Last, on this handle: it masks the
    // guard's known secrets from here on.
    super::shown::ran(store, host, &request, Some(action), || {
        let decoys = crate::canary::Record::load(&home)?.decoys();
        crate::secrets::known_with(&policy.secrets, &ctx.home, &decoys.values)
    })?;
    Ok(Decision::new(Verdict::Allow))
}
