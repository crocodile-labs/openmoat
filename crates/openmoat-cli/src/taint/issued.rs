//! Session taint at the standalone `openmoat proxy` (ADR-044).
//!
//! The proxy records a request under the agent's own session id, the one its
//! issued credential names (`proxy_session.rs`). That session's hook calls are
//! in the same audit session, so its taint is the guard's own fold of them,
//! with the effective policy of the project the session started in: the
//! session-start hook records that directory on the row it records the issue
//! with ([`ISSUED_RULE`]). A session with no such row has no history the
//! proxy can trust, and its requests are refused.
//!
//! Each session's fold is kept between requests, so a request late in a long
//! session reads only the events since the previous one.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{Event, EventId, Store};
use openmoat_core::{CompiledPolicy, EvalContext, Policy, Taint, Verdict};
use openmoat_hosts::Host;
use openmoat_proxy::TaintLookup;

use super::{Pass, SessionTaint, fold};
use crate::context;
use crate::home::Home;

/// The rule of the row the session-start hook records when it issues a
/// session its proxy credential.
pub const ISSUED_RULE: &str = "proxy-credential";

/// How many sessions' folds are kept; the least recently used goes first.
const MAX_SESSIONS: usize = 1024;

/// The taint of the sessions the standalone proxy serves.
pub struct IssuedTaint {
    home: Home,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    store: Option<Store>,
    sessions: HashMap<String, Followed>,
}

/// One session's fold so far, and what it is folded with.
struct Followed {
    host: Host,
    ctx: EvalContext,
    policy: Policy,
    upto: EventId,
    taint: SessionTaint,
    used: Instant,
}

impl IssuedTaint {
    /// The taint of the sessions recorded in `home`'s audit log.
    pub fn new(home: Home) -> Self {
        Self {
            home,
            state: Mutex::new(State::default()),
        }
    }

    fn fold(&self, session: &str) -> Result<Taint> {
        // A fold interrupted by a panic is only behind; the next lookup folds on.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = &mut *state;
        if state.store.is_none() {
            state.store = Some(self.home.open_audit()?);
        }
        let Some(store) = &state.store else {
            bail!("the audit log is not open");
        };
        if !state.sessions.contains_key(session) {
            let events = store.session_after(session, EventId(0))?;
            let followed = self.follow(session, &events)?;
            if state.sessions.len() >= MAX_SESSIONS
                && let Some(oldest) = state
                    .sessions
                    .iter()
                    .min_by_key(|(_, f)| f.used)
                    .map(|(id, _)| id.clone())
            {
                state.sessions.remove(&oldest);
            }
            state.sessions.insert(session.to_owned(), followed);
        }
        let Some(followed) = state.sessions.get_mut(session) else {
            bail!("session {session} is not followed");
        };
        followed.used = Instant::now();
        let events = store.session_after(session, followed.upto)?;
        if let Some(last) = events.last() {
            let compiled = CompiledPolicy::compile(&followed.policy, &followed.ctx)?;
            let cwd = followed.ctx.cwd.clone();
            fold(
                &mut followed.taint,
                &events,
                followed.host,
                &compiled,
                &cwd,
                &mut Pass::default(),
            )?;
            followed.upto = last.id;
        }
        Ok(followed.taint.taint.clone())
    }

    /// A new session to follow, from its first events: the row its credential
    /// was issued with names its host and directory.
    fn follow(&self, session: &str, events: &[Event]) -> Result<Followed> {
        let Some(issued) = events
            .iter()
            .find(|e| e.verdict == Verdict::Allow && e.rules.iter().any(|r| r == ISSUED_RULE))
        else {
            bail!("no proxy credential was issued to session {session}");
        };
        let host: Host = issued
            .host
            .parse()
            .map_err(|_| anyhow::Error::msg(format!("unknown host `{}`", issued.host)))?;
        let cwd = issued
            .cwd
            .as_deref()
            .context("the issue row names no directory")?;
        let ctx = context::eval_context(&self.home, Some(Path::new(cwd)), None)?;
        let policy = crate::repo::effective_policy(&self.home, &ctx)?;
        Ok(Followed {
            host,
            ctx,
            policy,
            upto: EventId(0),
            taint: SessionTaint::default(),
            used: Instant::now(),
        })
    }
}

impl TaintLookup for IssuedTaint {
    fn taint(&self, session: &str) -> Result<Taint, String> {
        self.fold(session).map_err(|e| format!("{e:#}"))
    }

    /// The audit log's newest event id: any new event may be one of a session's.
    fn version(&self) -> Option<i64> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.store.is_none() {
            state.store = self.home.open_audit().ok();
        }
        let id = state.store.as_ref()?.latest_id().ok()?;
        Some(id.map_or(0, |id| id.0))
    }
}

#[cfg(test)]
mod tests;
