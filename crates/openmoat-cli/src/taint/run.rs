//! Session taint at `moat run`'s proxy (ADR-027).
//!
//! The proxy records under the run's own audit session (`run-…`). The agent's
//! hooks record under the agent's session, which `moat run` cannot know when it
//! starts. So `moat run` gives the agent [`RUN_SESSION_ENV`], and the guard,
//! started by the agent with its environment, records once per agent session
//! a link row in the run's session: host [`LINK_HOST`], the agent's host id as
//! the tool and its session id as the call id. Link rows are ordinary audit
//! events, in the hash chain like every other row.
//!
//! The proxy's [`RunTaint`] folds every linked session, the same fold the
//! guard uses (`taint.rs`), and keeps where each fold reached, so a request
//! late in a long run reads only the events since the previous request.

use std::sync::{Mutex, PoisonError};

use anyhow::Result;
use openmoat_audit::{EventId, NewEvent, Store};
use openmoat_core::{CompiledPolicy, Decision, Taint, Verdict};
use openmoat_hosts::Host;
use openmoat_proxy::TaintLookup;

use super::{Pass, SessionTaint, fold};
use crate::home::Home;

/// What `moat run` names its audit session in for the agent and its hooks.
pub const RUN_SESSION_ENV: &str = "MOAT_RUN_SESSION";
/// The host of a link row.
pub const LINK_HOST: &str = "moat-run";
/// The rule a link row carries.
const LINK_RULE: &str = "run-session";

/// The run session `value` (of [`RUN_SESSION_ENV`]) names, when it is one:
/// `run-` and then only letters, digits and `-`.
pub fn run_session(value: Option<&str>) -> Option<&str> {
    value.filter(|v| {
        v.strip_prefix("run-").is_some_and(|rest| {
            !rest.is_empty()
                && rest.len() <= 64
                && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    })
}

/// Record, once, that `host`'s session `session` runs under `run`. A link
/// can only add sessions to a run's taint, never take one away.
pub fn link(store: &Store, run: &str, host: Host, session: &str) -> Result<()> {
    if store.session_has(run, LINK_HOST, session)? {
        return Ok(());
    }
    let decision = Decision::single(
        Verdict::Allow,
        LINK_RULE,
        format!(
            "{} session {session} runs under this `openmoat run`; its taint applies to the proxy",
            host.id()
        ),
    );
    store.record(&NewEvent {
        host: LINK_HOST,
        session_id: run,
        call_id: Some(session),
        cwd: None,
        tool: host.id(),
        action: None,
        decision: &decision,
        latency_us: 0,
    })?;
    Ok(())
}

/// The taint of one run session, for its proxy.
pub struct RunTaint<'p> {
    home: Home,
    run: String,
    policy: &'p CompiledPolicy<'p>,
    cwd: String,
    state: Mutex<State>,
}

/// What earlier lookups found: how far the run session was read, and each
/// linked session's fold so far.
struct State {
    store: Option<Store>,
    scanned: EventId,
    linked: Vec<Linked>,
}

struct Linked {
    host: Host,
    session: String,
    upto: EventId,
    taint: SessionTaint,
}

impl<'p> RunTaint<'p> {
    /// The taint of `run`, folded with `policy` (the effective policy of the
    /// project); a call recorded without a directory is taken to have run in
    /// `cwd`.
    pub fn new(home: Home, run: &str, policy: &'p CompiledPolicy<'p>, cwd: &str) -> Self {
        Self {
            home,
            run: run.to_owned(),
            policy,
            cwd: cwd.to_owned(),
            state: Mutex::new(State {
                store: None,
                scanned: EventId(0),
                linked: Vec::new(),
            }),
        }
    }

    fn fold(&self) -> Result<Taint> {
        // A fold interrupted by a panic is only behind; the next lookup folds on.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = &mut *state;
        if state.store.is_none() {
            state.store = Some(self.home.open_audit()?);
        }
        let Some(store) = &state.store else {
            return Ok(Taint::default());
        };
        let rows = store.session_after(&self.run, state.scanned)?;
        if let Some(last) = rows.last() {
            state.scanned = last.id;
        }
        for row in rows.iter().filter(|r| r.host == LINK_HOST) {
            let (Some(session), Ok(host)) = (&row.call_id, row.tool.parse::<Host>()) else {
                continue;
            };
            if !state
                .linked
                .iter()
                .any(|l| l.host == host && l.session == *session)
            {
                state.linked.push(Linked {
                    host,
                    session: session.clone(),
                    upto: EventId(0),
                    taint: SessionTaint::default(),
                });
            }
        }
        let mut out = Taint::default();
        for linked in &mut state.linked {
            let events = store.session_after(&linked.session, linked.upto)?;
            fold(
                &mut linked.taint,
                &events,
                linked.host,
                self.policy,
                &self.cwd,
                &mut Pass::default(),
            )?;
            if let Some(last) = events.last() {
                linked.upto = last.id;
            }
            out.absorb(linked.taint.taint.clone());
        }
        Ok(out)
    }
}

impl TaintLookup for RunTaint<'_> {
    fn taint(&self, session: &str) -> Result<Taint, String> {
        if session != self.run {
            return Err(format!("{session} is not this proxy's session"));
        }
        self.fold().map_err(|e| format!("{e:#}"))
    }

    /// The audit log's newest event id: any new event may be one of this run's.
    fn version(&self) -> Option<i64> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.store.is_none() {
            state.store = self.home.open_audit().ok();
        }
        let id = state.store.as_ref()?.latest_id().ok()?;
        // an empty log is a version too, so the first event changes it
        Some(id.map_or(0, |id| id.0))
    }
}

#[cfg(test)]
mod tests;
