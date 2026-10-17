//! Session taint (ADR-020) read from the audit log: the calls of one host
//! session that ran, folded into the [`Taint`] the core tightens the next call
//! with. The log is OpenMoat's, not the agent's, so the agent cannot reset it.
//!
//! A person can answer one taint ask for the rest of the session: a grant for
//! that exact call, made with `moat allow` after the session read untrusted
//! content, stands for it ([`answered`]). A grant made before the taint, or a
//! taint from a secret the session read, still asks.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Action, CompiledPolicy, Decision, Taint, Verdict};
use openmoat_hosts::{HookEvent, Host};

use crate::approvals::{self, Grants};
use crate::context;
use crate::home::Home;
use crate::realpath::FsPathResolver;

/// The rule id the core gives a taint ask.
const TAINT_RULE: &str = "session-taint";

/// What a session was exposed to, and since when it has read untrusted content.
#[derive(Debug, Default)]
pub struct SessionTaint {
    pub taint: Taint,
    /// When the first call that read untrusted content was recorded.
    pub untrusted_since_ms: Option<i64>,
}

/// What the earlier calls of `session` on `host` exposed it to. A call
/// recorded without a working directory is taken to have run in `cwd`. A log
/// that cannot be read fails the call: without it the session's history is
/// unknown, and the guard denies.
pub fn of_session(
    home: &Home,
    host: Host,
    session: &str,
    policy: &CompiledPolicy<'_>,
    cwd: &str,
) -> Result<SessionTaint> {
    let events = home
        .open_audit()?
        .session(session)
        .context("reading this session from the audit log")?;
    let mut out = SessionTaint::default();
    // Every guard call folds the whole session again, so a long session would
    // classify each of its calls once per later call. Agents repeat calls
    // (`git status`, the same file reads); each distinct one, in its working
    // directory, is classified once here.
    let mut seen: HashMap<(String, String), Taint> = HashMap::new();
    for event in events
        .iter()
        .filter(|e| e.host == host.id() && ran(host, e.verdict))
    {
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
        let exposure = match seen.entry(key) {
            Entry::Occupied(known) => known.get().clone(),
            Entry::Vacant(slot) => {
                let exposure = policy.exposure(action, &slot.key().1, &FsPathResolver);
                slot.insert(exposure).clone()
            }
        };
        if out.untrusted_since_ms.is_none() && exposure.untrusted.is_some() {
            out.untrusted_since_ms = Some(event.ts_ms);
        }
        out.taint.absorb(exposure);
    }
    Ok(out)
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
/// made after the session read untrusted content, gives `untainted` back.
/// Taint from a secret the session read is never answered this way, and a
/// grant made before the taint did not see the ask it would answer.
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
    let Some(since) = session.untrusted_since_ms else {
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
    let granted_at = approvals::approvable(call.action, Some(call.cwd), call.user_home)
        .map(|asked| {
            Grants::load(&call.home.grants_path())
                .map(|g| g.granted_at(call.host.id(), call.session, &asked, now_ms))
        })
        .transpose()?
        .flatten();
    if let Some(at) = granted_at
        && at >= since
    {
        let mut decision = untainted;
        decision
            .reasons
            .push("approved with `moat allow` after the session read untrusted content".to_owned());
        return Ok(decision);
    }
    let mut decision = tainted;
    // Hosts that cannot ask are told how already (`Host::answer`).
    if call.host == Host::ClaudeCode {
        decision.reasons.push(
            "to stop asking for this in this session, run `moat allow --last` in a terminal"
                .to_owned(),
        );
    }
    Ok(decision)
}

/// Whether a call decided `verdict` may have run: it was allowed, or it asked
/// a host that can ask (Codex turns an ask into a deny). A person may have
/// declined an ask; that is not recorded, so it counts as run.
fn ran(host: Host, verdict: Verdict) -> bool {
    host.answer(&HookEvent::PreToolUse, &Decision::new(verdict))
        .verdict
        != Verdict::Deny
}
