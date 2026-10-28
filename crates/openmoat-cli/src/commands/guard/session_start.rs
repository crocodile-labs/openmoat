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
use openmoat_core::{Decision, Verdict};
use openmoat_hosts::{HookRequest, ProxySessions};
use zeroize::Zeroizing;

use crate::home::Home;
use crate::integrity;
use crate::proxy_session::{self, Key};
use crate::taint::issued::ISSUED_RULE;

/// The rule of a session start that issues nothing.
const NOTHING_RULE: &str = "session-start";

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
    Decision::single(Verdict::Allow, NOTHING_RULE, reason)
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
            ISSUED_RULE,
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
    let issued = match proxy_session::issue(
        &key,
        request.host,
        &request.session_id,
        proxy_session::now_s(),
    ) {
        Ok(issued) => issued,
        Err(error) => return refuse(&format!("{error:#}")),
    };
    let url = issued.proxy_url(port);
    let mut lines = Zeroizing::new(String::with_capacity(
        VARIABLES.len() * (url.len() + 24) + 80,
    ));
    lines.push_str("# openmoat: this session's openmoat proxy credential (ADR-044)\n");
    for variable in VARIABLES {
        lines.push_str("export ");
        lines.push_str(variable);
        lines.push('=');
        lines.push_str(&url);
        lines.push('\n');
    }
    let decision = Decision::single(
        Verdict::Allow,
        ISSUED_RULE,
        format!(
            "the session's sandboxed commands get their own `openmoat proxy` credential, \
             accepted until {} (Unix time)",
            issued.expires
        ),
    );
    Ok((decision, Some(Pending { path, lines })))
}
