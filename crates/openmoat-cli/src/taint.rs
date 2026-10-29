//! Session taint (ADR-020) read from the audit log: the calls of one host
//! session that ran, folded into the [`Taint`] the core tightens the next call
//! with. The log is OpenMoat's, not the agent's, so the agent cannot reset it.
//!
//! A person can answer a taint ask: a grant for that exact call, made with
//! `moat allow` after the session last read untrusted content, stands for it
//! ([`answered`]) until the session reads more. A grant made before that read,
//! or a taint from a secret the session read, still asks.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{Cached, Event, EventId, Store};
use openmoat_core::{Action, CompiledPolicy, Decision, TAINT_RULE, Taint, Verdict};
use openmoat_hosts::{HookEvent, Host};
use serde::{Deserialize, Serialize};

use crate::approvals::{self, Grants};
use crate::context;
use crate::home::Home;
use crate::integrity::sha256_hex;
use crate::realpath::FsPathResolver;

pub mod issued;
pub mod provenance;
pub mod run;

/// What a session was exposed to, and when it last read untrusted content.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTaint {
    pub taint: Taint,
    /// When the latest call that read untrusted content was recorded. A grant
    /// must be newer: one made before a later read did not see that content.
    pub untrusted_last_ms: Option<i64>,
    /// The audit row of that call. Rows only grow, so a grant that records the
    /// newest row it saw is ordered against the read even if the clock stepped
    /// back.
    pub untrusted_last_row: Option<i64>,
}

/// What the earlier calls of `session` on `host` exposed it to. A call
/// recorded without a working directory is taken to have run in `cwd`. A log
/// that cannot be read fails the call: without it the session's history is
/// unknown, and the guard denies.
///
/// A session's fold is cached in the audit database with the event it reached
/// (#570), so a call late in a long session classifies only the events since.
/// The cache applies only under the same OpenMoat version, policy, context and
/// directory it was computed with, and a session keeps a row for each, so
/// calls from two directories each read on from their own; without a row, or
/// when it cannot be read, the session is folded from its first event, as it
/// always was.
///
/// The read is on a read-only handle; the new cache row, when there is one, is
/// returned for the caller to write on the handle it records the call with.
/// A fold that runs long hands what it has reached to `progress.save` every
/// [`CHECKPOINT_EVERY`], and stops at `progress.deadline`, saving what it
/// reached and failing the call (the guard denies, as its budget would): a
/// fold of part of the session is never an answer, since it may lack the
/// event that tainted it, but the next call reads on from where this one got.
///
/// Files the session read that a tainted session wrote ([`provenance`]) taint
/// it too. They are looked up each call, not cached: the cache holds only what
/// the events fold to.
pub fn of_session(
    store: &Store,
    host: Host,
    session: &str,
    policy: &CompiledPolicy<'_>,
    cwd: &str,
    progress: &mut Progress<'_>,
) -> Result<(SessionTaint, Option<CacheWrite>)> {
    let digest = digest(host, policy, cwd)?;
    let (mut out, start) = store
        .session_cache(session, host.id(), &digest)
        .ok()
        .flatten()
        .and_then(|cached| Some((serde_json::from_str(&cached.state).ok()?, cached.upto)))
        .unwrap_or((SessionTaint::default(), EventId(0)));
    let mut upto = start;
    let mut pass = Pass {
        deadline: Some(progress.deadline),
        ..Pass::default()
    };
    let mut saved = Instant::now();
    let write = |out: &SessionTaint, upto: EventId| -> Result<CacheWrite> {
        Ok(CacheWrite {
            session: session.to_owned(),
            host,
            cached: Cached {
                digest: digest.clone(),
                upto,
                state: serde_json::to_string(out)?,
            },
        })
    };
    loop {
        let events = store
            .session_page(session, upto, PAGE_LEN)
            .context("reading this session from the audit log")?;
        let folded = fold(&mut out, &events, host, policy, cwd, &mut pass)?;
        progress.folded = pass.folded;
        if let Some(last) = events.get(..folded).and_then(<[Event]>::last) {
            upto = last.id;
        }
        if folded < events.len() {
            if upto != start {
                (progress.save)(&write(&out, upto)?);
            }
            bail!(
                "this session has more earlier calls than one call has time to read; what was \
                 read is kept, so a later call reads on from there"
            );
        }
        if events.len() < PAGE_LEN {
            break;
        }
        if saved.elapsed() >= CHECKPOINT_EVERY {
            (progress.save)(&write(&out, upto)?);
            saved = Instant::now();
        }
    }
    let write = if upto == start {
        None
    } else {
        Some(write(&out, upto)?)
    };
    if openmoat_core::TaintSettings::provenance_on(policy.policy().taint.as_ref())
        && let Some(exposure) = store
            .exposure(session, host.id())
            .context("reading this session's file provenance from the audit log")?
    {
        out.taint.untrusted.get_or_insert(exposure.source);
        out.untrusted_last_ms = out.untrusted_last_ms.max(Some(exposure.last_ts_ms));
        out.untrusted_last_row = out.untrusted_last_row.max(Some(exposure.last_event.0));
    }
    Ok((out, write))
}

/// How many events [`of_session`] reads from the log at a time.
const PAGE_LEN: usize = 512;

/// How often a long fold hands what it has reached to [`Progress::save`].
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(2);

/// How long [`of_session`] may fold, where what it reached goes meanwhile,
/// and how many events it folded.
pub struct Progress<'a> {
    /// Past this the fold stops, saves what it reached and fails the call.
    pub deadline: Instant,
    /// Stores a fold of part of the session, so a later call reads on from it.
    pub save: &'a mut dyn FnMut(&CacheWrite),
    /// The events of the session classified so far.
    pub folded: usize,
}

/// A session's fold to store in the cache.
pub struct CacheWrite {
    session: String,
    host: Host,
    cached: Cached,
}

impl CacheWrite {
    /// Best effort and without waiting: without the cache the next call folds
    /// more, nothing else. `store` must not mask secrets: the row is keyed by
    /// the session id as [`of_session`] reads it, on a handle that masks none.
    pub fn write(&self, store: &Store) {
        let _ = store.try_set_session_cache(&self.session, self.host.id(), &self.cached);
    }
}

/// What the fold of a session depends on besides its events: this build's
/// classifier, the host, the effective policy and its context, and the
/// directory a call recorded without one is taken to have run in.
fn digest(host: Host, policy: &CompiledPolicy<'_>, cwd: &str) -> Result<String> {
    let mut bytes = Vec::new();
    for part in [
        crate::VERSION.to_owned(),
        host.id().to_owned(),
        serde_json::to_string(policy.policy())?,
        format!("{:?}", policy.context()),
        cwd.to_owned(),
    ] {
        // length-prefixed, so no two different lists of parts hash alike
        bytes.extend_from_slice(&part.len().to_le_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    Ok(sha256_hex(&bytes))
}

/// One fold's state across the pages of events it reads.
#[derive(Default)]
struct Pass {
    /// What each distinct call, in its working directory, exposed the
    /// session to: agents repeat calls (`git status`, the same file reads),
    /// and each is classified once per fold.
    seen: HashMap<(String, String), Taint>,
    /// When the fold stops; `None` folds every event it is given.
    deadline: Option<Instant>,
    /// The events classified so far.
    folded: usize,
}

/// Add what `events` (of the session, oldest first) exposed it to into `out`,
/// until `pass.deadline`. Returns how many of `events` were taken in; fewer
/// than all when the deadline passed first.
fn fold(
    out: &mut SessionTaint,
    events: &[Event],
    host: Host,
    policy: &CompiledPolicy<'_>,
    cwd: &str,
    pass: &mut Pass,
) -> Result<usize> {
    for (taken, event) in events.iter().enumerate() {
        if pass.deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(taken);
        }
        if event.host != host.id() || !ran(host, event.verdict) {
            continue;
        }
        pass.folded += 1;
        if event.action_unreadable {
            bail!("audit event {} of this session cannot be decoded", event.id);
        }
        let Some(action) = &event.action else {
            continue;
        };
        let cwd = event
            .cwd
            .as_deref()
            .map_or_else(|| cwd.to_owned(), |c| context::path_string(Path::new(c)));
        let key = (serde_json::to_string(action)?, cwd);
        let exposure = match pass.seen.entry(key) {
            Entry::Occupied(known) => known.get().clone(),
            Entry::Vacant(slot) => {
                let exposure = policy.exposure(action, &slot.key().1, &FsPathResolver);
                slot.insert(exposure).clone()
            }
        };
        if exposure.untrusted.is_some() {
            out.untrusted_last_ms = out.untrusted_last_ms.max(Some(event.ts_ms));
            out.untrusted_last_row = out.untrusted_last_row.max(Some(event.id.0));
        }
        out.taint.absorb(exposure);
    }
    Ok(events.len())
}

/// Everything `answered` needs about the call being decided.
pub struct Call<'a> {
    pub home: &'a Home,
    pub host: Host,
    pub session: &'a str,
    pub action: &'a Action,
    pub cwd: &'a str,
    pub user_home: &'a str,
}

/// `tainted` is `untainted` tightened by the session's taint. When it is a
/// taint ask a person can answer, and they did: a grant for this exact call,
/// made after the session last read untrusted content, gives `untainted` back.
/// Taint from a secret the session read is never answered this way, and a
/// grant made before the latest untrusted read did not see that content.
///
/// A taint ask that a grant could answer, and has not, says how to give one.
pub fn answered(
    call: &Call<'_>,
    policy: &CompiledPolicy<'_>,
    session: &SessionTaint,
    untainted: Decision,
    tainted: Decision,
    now_ms: i64,
) -> Result<Decision> {
    let Some(last_read) = session.untrusted_last_ms else {
        return Ok(tainted);
    };
    if tainted.verdict != Verdict::Ask || !tainted.rules.iter().any(|r| r == TAINT_RULE) {
        return Ok(tainted);
    }
    // Only untrusted content may be answered: the secrets alone must not make
    // this call ask.
    let secrets_only = Taint {
        secrets: session.taint.secrets.clone(),
        untrusted: None,
    };
    let with_secrets = policy.with_taint(
        untainted.clone(),
        call.action,
        &FsPathResolver,
        &secrets_only,
    );
    if with_secrets.rules.iter().any(|r| r == TAINT_RULE) {
        return Ok(tainted);
    }
    let grants = Grants::load_in(call.home)?;
    let read_row = session.untrusted_last_row;
    let fresh =
        |g: &&approvals::Grant| after_read(g.granted_at_ms, g.audit_row, last_read, read_row);
    // A grant for exactly this call, or one the person gave for every protected
    // write of the session (`moat allow --last`, answer `s`); either only while
    // the session has read nothing untrusted since.
    let project = approvals::project_of(Path::new(call.cwd), Path::new(call.user_home));
    let scope = approvals::Scope {
        host: call.host.id(),
        session_id: call.session,
        project: &project,
    };
    let exact = approvals::approvable(call.action, Some(call.cwd), call.user_home)
        .and_then(|asked| grants.newest(scope, &asked, now_ms).cloned());
    if exact.as_ref().is_some_and(|g| fresh(&g)) {
        let mut decision = untainted;
        decision.reasons.push(
            "approved with `openmoat allow` after the session last read untrusted content"
                .to_owned(),
        );
        return Ok(decision);
    }
    if grants
        .covering_taint(scope, now_ms)
        .is_some_and(|g| fresh(&g))
    {
        let mut decision = untainted;
        decision.reasons.push(
            "the session's protected writes were approved with `openmoat allow` after it last read \
             untrusted content"
                .to_owned(),
        );
        return Ok(decision);
    }
    let mut decision = tainted;
    // Hosts that cannot ask are told how already (`Host::answer`).
    if call.host.spec().asks.allow_last_hint {
        decision.reasons.push(
            "to stop asking for this in this session, run `openmoat allow --last` in a terminal"
                .to_owned(),
        );
    }
    Ok(decision)
}

/// Whether a grant made at `granted_ms`, having seen the audit log up to row
/// `seen_row`, came after the untrusted read recorded at `read_ms` in row
/// `read_row`. By row when both are known: rows only grow, the clock may step
/// back. A grant written by an older build has no row and is ordered by time.
fn after_read(granted_ms: i64, seen_row: Option<i64>, read_ms: i64, read_row: Option<i64>) -> bool {
    match (seen_row, read_row) {
        (Some(seen), Some(read)) => seen >= read,
        _ => granted_ms > read_ms,
    }
}

/// Whether a call decided `verdict` may have run: it was allowed, or it asked
/// a host that can ask (Codex turns an ask into a deny). A person may have
/// declined an ask; that is not recorded, so it counts as run.
pub(crate) fn ran(host: Host, verdict: Verdict) -> bool {
    host.answer(&HookEvent::PreToolUse, &Decision::new(verdict))
        .verdict
        != Verdict::Deny
}

#[cfg(test)]
mod tests;
