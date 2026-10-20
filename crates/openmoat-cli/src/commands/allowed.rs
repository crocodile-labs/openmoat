//! `moat allowed`: what a person allowed, in one place, each with the command
//! that takes it back. Read-only, so it needs no terminal: tools that show it
//! (the `MoatBar` app) run it with `--format json`.
//!
//! - permanent rules `moat allow --always`, `--site` and `--dir` wrote to
//!   `~/.moat/policy.d/approved.yaml`;
//! - session grants from `moat allow --last` that have not expired;
//! - repositories whose policy `moat trust` lets allow.

use std::io::Write as _;

use anyhow::Result;
use openmoat_core::{Action, Kind, RuleGroup};
use serde::Serialize;

use crate::approvals::{self, GRANT_TTL_MS, Grants, Overlay};
use crate::cli::{AllowedArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::render::{self, Deferred};
use crate::time;
use crate::trust::Trust;

#[derive(Serialize)]
struct Allowed<'a> {
    /// Rules in `approved.yaml`, as the policy spells them.
    rules: &'a [RuleGroup],
    session_grants: Vec<SessionGrant<'a>>,
    trusted_repos: Vec<TrustedRepo<'a>>,
}

#[derive(Serialize)]
struct SessionGrant<'a> {
    host: &'a str,
    session_id: &'a str,
    /// One line a person can read: `run "npm install"`, `write ~/p/Makefile`.
    what: String,
    action: &'a Action,
    granted_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Serialize)]
struct TrustedRepo<'a> {
    root: &'a str,
    /// SHA-256 of the `.moat/policy.yaml` that was trusted; a change ends the trust.
    sha256: &'a str,
}

pub fn run(args: &AllowedArgs) -> Result<Code> {
    let home = Home::locate()?;
    let overlay = Overlay::load(&home.overlay_path())?;
    let grants = Grants::load(&home.grants_path())?;
    let trust = Trust::load(&home.trust_path())?;
    let now = time::now_ms();
    let allowed = Allowed {
        rules: &overlay.allow,
        session_grants: grants
            .active(now)
            .map(|g| SessionGrant {
                host: &g.host,
                session_id: &g.session_id,
                what: approvals::describe(&g.action),
                action: &g.action,
                granted_at_ms: g.granted_at_ms,
                expires_at_ms: g.granted_at_ms.saturating_add(GRANT_TTL_MS),
            })
            .collect(),
        trusted_repos: trust
            .repos
            .iter()
            .map(|(root, sha256)| TrustedRepo { root, sha256 })
            .collect(),
    };
    if args.format == Format::Json {
        render::json(&allowed)?;
        return Ok(Code::Ok);
    }
    text(&allowed, now)
}

fn text(allowed: &Allowed<'_>, now: i64) -> Result<Code> {
    let mut out = Deferred::default();
    writeln!(out, "Permanent rules (~/.moat/policy.d/approved.yaml)")?;
    if allowed.rules.is_empty() {
        writeln!(out, "  none")?;
    }
    for rule in allowed.rules {
        writeln!(out, "  {:<14} {}", rule.id, patterns(rule))?;
        writeln!(
            out,
            "  {:<14} remove: openmoat allow --remove {}",
            "", rule.id
        )?;
    }
    writeln!(
        out,
        "Session grants (each ends {} after it was given)",
        time::duration(GRANT_TTL_MS)
    )?;
    if allowed.session_grants.is_empty() {
        writeln!(out, "  none")?;
    }
    for grant in &allowed.session_grants {
        writeln!(
            out,
            "  {} session {}: {} (ends in {})",
            grant.host,
            grant.session_id,
            grant.what,
            time::duration(grant.expires_at_ms.saturating_sub(now))
        )?;
    }
    writeln!(out, "Trusted repositories (openmoat trust)")?;
    if allowed.trusted_repos.is_empty() {
        writeln!(out, "  none")?;
    }
    for repo in &allowed.trusted_repos {
        writeln!(out, "  {}  sha256:{}", repo.root, repo.sha256)?;
        writeln!(out, "  revoke: openmoat trust --revoke {}", repo.root)?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// `shell: npm install; net: docs.rs`, as `moat trust` prints a rule.
fn patterns(group: &RuleGroup) -> String {
    Kind::ALL
        .into_iter()
        .filter(|k| !group.patterns(*k).is_empty())
        .map(|k| format!("{}: {}", k.as_str(), group.patterns(k).join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}
