//! Writing the guard's decision to the audit log, with what goes along with
//! it: the session cache, file provenance and the link to an `openmoat run`.

use std::time::Instant;

use anyhow::Result;
use openmoat_audit::{EventId, KnownSecrets, NewEvent, NewTicket, Store};
use openmoat_core::{Action, Decision, Verdict};
use openmoat_hosts::{HookRequest, Host};

use super::drift;
use crate::hangs::{self, Phase};
use crate::home::Home;
use crate::integrity::Drift;
use crate::taint;

/// What [`record`] writes.
pub(super) struct Recorded<'a> {
    pub(super) request: Option<&'a HookRequest>,
    pub(super) decision: &'a Decision,
    /// Settings drift the call was decided through; the first call of a
    /// session records it with its row, and the host's answer stays as decided.
    pub(super) drifted: &'a [Drift],
    pub(super) started: Instant,
    pub(super) known: KnownSecrets,
    pub(super) cache: Option<taint::CacheWrite>,
    pub(super) provenance: taint::provenance::Seen,
}

/// Record the decision, after the session cache on the same handle. The cache
/// write never waits for the lock and its result is ignored; it is a separate
/// statement before the record's own transaction, so it cannot touch the
/// hash chain.
pub(super) fn record(host: Host, recorded: Recorded<'_>) -> Result<()> {
    let Recorded {
        request,
        decision,
        drifted,
        started,
        known,
        cache,
        provenance,
    } = recorded;
    hangs::enter(Phase::Record);
    let home = Home::locate()?;
    home.require_exists()?;
    let store = Store::open_existing(&home.audit_path())?;
    if let Some(cache) = cache {
        hangs::enter(Phase::Cache);
        // Before `with_secrets`: the cache is keyed as the unmasked reader reads it.
        cache.write(&store);
        hangs::enter(Phase::Record);
    }
    let store = store.with_secrets(known);
    let noted = match request {
        Some(r) => drift::noted(&store, &r.session_id, decision, drifted)?,
        None => None,
    };
    let decision = noted.as_ref().unwrap_or(decision);
    let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let event = NewEvent {
        host: host.id(),
        session_id: request.map_or("unknown", |r| r.session_id.as_str()),
        call_id: request.and_then(|r| r.call_id.as_deref()),
        cwd: request.and_then(|r| r.cwd.as_deref()),
        tool: request.map_or("unknown", |r| r.tool.as_str()),
        action: request.and_then(|r| r.action.as_ref()),
        decision,
        latency_us,
    };
    let id = store.record(&event)?;
    // A call that may have run wrote and read what it named (ADR-029); like
    // the row, provenance that cannot be written fails the call.
    if let Some(r) = request
        && taint::ran(host, decision.verdict)
    {
        provenance.write(&store, id, host.id(), &r.session_id)?;
    }
    // An MCP call the host may now send: `openmoat mcp proxy` passes on only
    // a call that matches such a decision (ADR-045). Like the row, a decision
    // that cannot be written fails the call.
    if let Some(r) = request {
        mcp_ticket(&store, id, host, r, decision)?;
    }
    // Under `moat run`, the run's proxy applies this session's taint too
    // (ADR-027); a link that cannot be written fails the call like the row.
    let run = std::env::var(taint::run::RUN_SESSION_ENV).ok();
    if let (Some(run), Some(r)) = (taint::run::run_session(run.as_deref()), request) {
        taint::run::link(&store, run, host, &r.session_id)?;
    }
    // A deferred call is the agent's to decide; OpenMoat stays quiet about it.
    if !matches!(decision.verdict, Verdict::Allow | Verdict::Defer) {
        eprintln!("moat: trace {id}  (openmoat show {id})");
    }
    Ok(())
}

/// The decision on MCP call `request`, recorded as `event`, for the proxy to
/// match; nothing for another call, or one the host is told is denied (an
/// `ask` where no person sees it included).
fn mcp_ticket(
    store: &Store,
    event: EventId,
    host: Host,
    request: &HookRequest,
    decision: &Decision,
) -> Result<()> {
    let (Some(Action::McpTool { name, .. }), Some(arguments)) =
        (&request.action, &request.mcp_arguments)
    else {
        return Ok(());
    };
    if host.answer(&request.event, decision).verdict == Verdict::Deny {
        return Ok(());
    }
    store.add_mcp_ticket(&NewTicket {
        event,
        host: host.id(),
        session_id: &request.session_id,
        call_id: request.call_id.as_deref(),
        tool: name,
        arguments_sha256: &crate::integrity::sha256_hex(arguments.as_bytes()),
        verdict: decision.verdict.as_str(),
    })?;
    Ok(())
}
