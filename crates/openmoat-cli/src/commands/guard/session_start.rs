//! Claude Code's `SessionStart` hook: the session's own credential for
//! `openmoat proxy` (ADR-044).
//!
//! The policy's `sandbox.proxy_port` sends Claude Code's sandboxed commands to
//! `openmoat proxy`, which refuses a request without a session credential. So
//! at each start, resume, `/clear` and compaction the hook issues the session
//! one (`proxy_session.rs`) and appends `export` lines for the proxy variables
//! to the file `CLAUDE_ENV_FILE` names, which Claude Code runs before each
//! later Bash command of the session. They replace the bare
//! `http://localhost:<port>` Claude Code's sandbox sets, at the same port.
//!
//! The row recorded with the issue names the session's directory, which the
//! proxy folds the session's taint with (`taint/issued.rs`); the file is
//! written only after that row is, so a credential always has its row.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Result;
use openmoat_core::rule_id::{PROXY_CREDENTIAL, SESSION_START};
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{HookRequest, ProxySessions};
use zeroize::Zeroizing;

use crate::home::Home;
use crate::integrity;
use crate::proxy_session::{self, Key};

/// The proxy variables the credential goes in, both cases, as `openmoat run`
/// sets them (ADR-027).
const VARIABLES: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// Lines to append to the session's environment file once the issue is recorded.
pub(super) struct Pending {
    path: PathBuf,
    lines: Zeroizing<String>,
}

impl Pending {
    /// Append the lines; the file is left readable by its owner only.
    pub(super) fn write(&self) -> Result<()> {
        crate::home::append_owner_only(&self.path, self.lines.as_bytes())
    }
}

fn nothing(reason: &str) -> Decision {
    Decision::single(Verdict::Allow, SESSION_START, reason)
}

/// What the session start records, and the lines to write once it is
/// recorded. `env` reads the hook's environment, where the host names the
/// session's environment file ([`ProxySessions::EnvFile`]); `within_run`,
/// whether `openmoat run` relayed it, whose own proxy credential then applies.
pub(super) fn decision(
    home: &Home,
    request: &HookRequest,
    env: &dyn Fn(&str) -> Option<OsString>,
    within_run: bool,
) -> Result<(Decision, Option<Pending>)> {
    // No credential from a tampered installation: its policy may be anyone's.
    let verified = integrity::check(home)?;
    if let Some(deny) = verified.checked.deny {
        return Ok((deny, None));
    }
    let policy = verified.home.load_policy()?;
    let Some(port) = crate::sandbox::proxy_port(&policy) else {
        let why = "the policy sets no `sandbox.proxy_port`, so no host sandbox uses \
                   `openmoat proxy` and no credential is issued";
        return Ok((nothing(why), None));
    };
    if within_run {
        let why = "inside `openmoat run`, whose own proxy credential applies";
        return Ok((nothing(why), None));
    }
    let sessions = request
        .host
        .spec()
        .sandbox
        .as_ref()
        .map(|s| s.proxy_sessions);
    let Some(ProxySessions::EnvFile(variable)) = sessions else {
        let why = format!("{} takes no `openmoat proxy` credential", request.host.id());
        return Ok((nothing(&why), None));
    };
    let refuse = |why: &str| {
        let decision = Decision::single(
            Verdict::Deny,
            PROXY_CREDENTIAL,
            format!(
                "{why}, so this session's sandboxed commands get no credential and \
                 `openmoat proxy` refuses their traffic (407)"
            ),
        );
        Ok((decision, None))
    };
    let name = request.host.display_name();
    let Some(path) = env(variable).map(PathBuf::from).filter(|p| p.is_absolute()) else {
        return refuse(&format!("{name} gave the hook no absolute `{variable}`"));
    };
    if request.cwd.as_deref().is_none_or(str::is_empty) {
        return refuse(&format!("{name} sent no working directory for the session"));
    }
    let key = Key::load_or_create(home)?;
    let now = proxy_session::now_s();
    // Checks the session id, which also names the trust files' folder.
    let untrusted = match proxy_session::issue(&key, request.host, &request.session_id, now, false)
    {
        Ok(issued) => issued,
        Err(error) => return refuse(&format!("{error:#}")),
    };
    let (trust, trust_note) = session_trust(home, &policy, &request.session_id);
    let issued = match &trust {
        Some(_) => proxy_session::issue(&key, request.host, &request.session_id, now, true)?,
        None => untrusted,
    };
    let url = issued.proxy_url(port);
    let mut lines = Zeroizing::new(String::with_capacity(
        VARIABLES.len() * (url.len() + 24) + 80,
    ));
    if let Some(exports) = &trust {
        lines.push_str(exports);
    }
    lines.push_str("# openmoat: this session's openmoat proxy credential (ADR-044)\n");
    for variable in VARIABLES {
        lines.push_str("export ");
        lines.push_str(variable);
        lines.push('=');
        lines.push_str(&url);
        lines.push('\n');
    }
    let mut decision = Decision::single(
        Verdict::Allow,
        PROXY_CREDENTIAL,
        format!(
            "the session's sandboxed commands get their own `openmoat proxy` credential, \
             accepted until {} (Unix time)",
            issued.expires
        ),
    );
    decision.reasons.extend(trust_note);
    Ok((decision, Some(Pending { path, lines })))
}

/// The session's trust files (ADR-062 §2), when the policy has `requests:`
/// hosts the proxy holds and a pinned CA exists: the `export` lines that
/// point the session's TLS clients at them, and what the row says. Only the
/// certificate is written, never the key. `None` lines leave the session
/// untrusted, so the proxy never terminates its tunnels.
fn session_trust(
    home: &Home,
    policy: &openmoat_core::Policy,
    session: &str,
) -> (Option<String>, Option<String>) {
    let hosts = crate::proxy_ca::request_hosts(policy);
    if hosts.is_empty() {
        return (None, None);
    }
    let Some(cert) = crate::proxy_ca::pinned_cert(home) else {
        let why = format!(
            "{} have request rules, but there is no pinned proxy CA, so the session gets no \
             trust files and `openmoat proxy` cannot read its HTTPS there",
            hosts.join(", ")
        );
        return (None, Some(why));
    };
    let trust = match crate::proxy_ca::Trust::write_for_session(&cert, session) {
        Ok(trust) => trust,
        Err(error) => {
            let why = format!("the session's trust files were not written: {error:#}");
            return (None, Some(why));
        }
    };
    let mut lines =
        String::from("# openmoat: the proxy CA this session's commands trust (ADR-062)\n");
    for (variable, file) in trust.env() {
        let file = file.to_string_lossy();
        if file.contains('\'') {
            return (
                None,
                Some(format!("the trust file path {file} holds a quote")),
            );
        }
        for part in ["export ", variable, "='", &file, "'\n"] {
            lines.push_str(part);
        }
    }
    let why = format!(
        "its TLS clients trust the proxy CA through {}, so `openmoat proxy` reads its HTTPS to {}",
        trust.dir().display(),
        hosts.join(", ")
    );
    (Some(lines), Some(why))
}
