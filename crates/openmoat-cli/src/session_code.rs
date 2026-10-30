//! Code a session wrote, run where no OS sandbox holds the command (ADR-039).
//!
//! An agent can write a script (`x.py`, `run.sh`) and run it: the hook sees
//! `python3 x.py`, which names no secret, while the script may read
//! `~/.ssh/id_rsa` through a path it builds and send it to an allowed host.
//! Where OpenMoat's OS sandbox runs the agent's commands (Claude Code, Codex and
//! Cursor on macOS and Linux with their sandbox in place, or anything inside
//! `openmoat run`) the sandbox stops that read whatever the script does. Where
//! it does not (the agents with only a hook, and Claude Code and Cursor on
//! native Windows) the hook is the only check, so running a file the same
//! session wrote asks: [`checked`] turns an `allow` or a `defer` into an `ask`
//! with [`RULE`], and a host that cannot ask gets a deny naming `openmoat
//! allow --last`.
//!
//! It only tightens. A file the session did not write (it was there before,
//! another session or a person wrote it) keeps its verdict, and a session grant
//! for the exact call made after the session last wrote the file answers it.

use anyhow::{Context as _, Result};
use openmoat_audit::{SessionWrite, Store, Written};
use openmoat_core::{Action, CompiledPolicy, Decision, Verdict};
use openmoat_hosts::Host;

use crate::approvals::{self, Grants};
use crate::home::Home;
use crate::realpath::FsPathResolver;
use crate::taint::provenance;

/// The rule id of the ask, in audit rows and the reason the agent sees.
pub const RULE: &str = "session-written-code";

/// The call being decided, as the check needs it.
pub struct Call<'a> {
    pub home: &'a Home,
    pub host: Host,
    pub session: &'a str,
    pub action: &'a Action,
    pub cwd: &'a str,
    pub user_home: &'a str,
    /// The files this same call writes before it runs them
    /// (`cat > x.sh <<EOF … EOF; sh x.sh`).
    pub writes: &'a [SessionWrite],
    /// The call came through `openmoat run`, whose sandbox holds the agent.
    pub within_run: bool,
}

/// `decision` for `call`, asking when it allows or defers running a file the
/// same session wrote and no OS sandbox holds the command. `store` is the
/// read handle of the audit log; `sandboxed` says whether the host's OS
/// sandbox is in place ([`crate::protection::os_sandboxed`]), and is asked
/// only when such a file runs.
pub fn checked(
    call: &Call<'_>,
    policy: &CompiledPolicy<'_>,
    store: &Store,
    decision: Decision,
    (now_ms, sandboxed): (i64, &dyn Fn() -> bool),
) -> Result<Decision> {
    if !matches!(decision.verdict, Verdict::Allow | Verdict::Defer) || call.within_run {
        return Ok(decision);
    }
    // A session that wrote nothing, in a call that writes nothing, runs no file
    // it wrote: one index probe instead of classifying the command again.
    if call.writes.is_empty() && !store.session_wrote_any(call.host.id(), call.session)? {
        return Ok(decision);
    }
    let ci = policy.context().case_insensitive_paths;
    let executed: Vec<String> = policy
        .executed(call.action, &FsPathResolver)
        .iter()
        .map(|path| provenance::key(path, ci))
        .collect();
    if executed.is_empty() {
        return Ok(decision);
    }
    let mut written = store
        .session_wrote(call.host.id(), call.session, &executed)
        .context("reading the files this session wrote from the audit log")?;
    // Written by this very call (`cat > x.sh <<EOF … EOF; sh x.sh`): the
    // command shows what it writes, so a grant for exactly it answers it.
    let now = executed
        .iter()
        .filter(|path| call.writes.iter().any(|w| &&w.path == path))
        .map(|path| Written {
            path: path.clone(),
            event_id: openmoat_audit::EventId(0),
            ts_ms: 0,
            sha256: None,
            before: None,
        });
    written.extend(now);
    if written.is_empty() || sandboxed() {
        return Ok(decision);
    }
    if granted_since(call, &written, now_ms)? {
        let mut decision = decision;
        decision.reasons.push(
            "runs code this session wrote, approved with `openmoat allow` after it last wrote it"
                .to_owned(),
        );
        return Ok(decision);
    }
    Ok(ask(call.host, decision, &written))
}

/// Whether a session grant for exactly this call was made after the session
/// last wrote each of `written`: a grant made before a rewrite approved other
/// code. Ordered by audit row where the grant recorded one, else by time.
fn granted_since(call: &Call<'_>, written: &[Written], now_ms: i64) -> Result<bool> {
    let Some(asked) = approvals::approvable(call.action, Some(call.cwd), call.user_home) else {
        return Ok(false);
    };
    let grants = Grants::load_in(call.home)?;
    let project = approvals::project_of(
        std::path::Path::new(call.cwd),
        std::path::Path::new(call.user_home),
    );
    let scope = approvals::Scope {
        host: call.host.id(),
        session_id: call.session,
        project: &project,
    };
    let Some(grant) = grants.newest(scope, &asked, now_ms) else {
        return Ok(false);
    };
    Ok(written.iter().all(|w| match grant.audit_row {
        Some(seen) => seen >= w.event_id.0,
        None => grant.granted_at_ms > w.ts_ms,
    }))
}

/// `decision` tightened to the ask, naming the files.
fn ask(host: Host, decision: Decision, written: &[Written]) -> Decision {
    let mut files: Vec<&str> = written.iter().map(|w| w.path.as_str()).collect();
    files.sort_unstable();
    files.dedup();
    let mut asked = Decision::new(Verdict::Ask);
    asked.rules.push(RULE.to_owned());
    asked.reasons.push(format!(
        "runs code this session wrote, with no OS sandbox below the hook: {}",
        files.join(", ")
    ));
    // Hosts that cannot ask are told how already (`Host::answer`).
    if host.spec().asks.allow_last_hint {
        asked.reasons.push(
            "to run it in this session, run `openmoat allow --last` in a terminal".to_owned(),
        );
    }
    asked.context.extend(decision.reasons);
    asked.context.extend(decision.context);
    asked
}

#[cfg(test)]
mod tests;
