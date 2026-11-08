//! `moat allowed`: what a person allowed, in one place, each with the command
//! that takes it back. Read-only, so it needs no terminal: tools that show it
//! (the `MoatBar` app) run it with `--format json`.
//!
//! - standing rules `moat allow --always` and `--site` wrote to
//!   `~/.moat/policy.d/approved.yaml`, and the directories `--dir` allowed there,
//!   each with when it ends if `--for` gave it an end (shown as expired after);
//! - session grants from `moat allow --last` that have not expired;
//! - repositories whose policy `moat trust` lets allow.

use std::collections::BTreeMap;
use std::io::Write as _;

use anyhow::Result;
use openmoat_core::{Action, Kind, RuleGroup};
use serde::Serialize;

use crate::approvals::{self, DirGrant, GRANT_TTL_MS, Grants, Overlay, State, Window};
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
    /// Directories `openmoat allow --dir` allowed, as chosen; each leaves out
    /// what the policy holds for review in it.
    directories: &'a [DirGrant],
    /// For each rule or directory `--for` gave an end, by id: when it ends,
    /// and whether it is in force now. An id not here lasts until removed.
    expires: BTreeMap<&'a str, Ends<'a>>,
    session_grants: Vec<SessionGrant<'a>>,
    trusted_repos: Vec<TrustedRepo<'a>>,
}

#[derive(Serialize)]
struct Ends<'a> {
    /// As written in `approved.yaml` (RFC 3339 UTC).
    until: &'a str,
    /// `None` when it cannot be read, which counts as ended.
    until_ms: Option<i64>,
    /// `false` once ended, when unreadable, and while the clock reads earlier
    /// than when it was granted: the policy leaves it out.
    in_force: bool,
}

impl<'a> Ends<'a> {
    fn of(window: &'a Window, now: i64) -> Self {
        Self {
            until: &window.until,
            until_ms: time::parse_rfc3339(&window.until),
            in_force: window.holds(now),
        }
    }
}

/// How `allowed` says when an entry ends, after what it allows.
fn ends_text(window: Option<&Window>, now: i64) -> String {
    match window.map(|w| w.state(now)) {
        None => String::new(),
        Some(State::Holds { until_ms }) => format!(
            " (ends {}, in {})",
            time::timestamp(until_ms),
            time::duration(until_ms.saturating_sub(now))
        ),
        Some(State::Ended { until_ms }) => {
            format!(" (EXPIRED {}, not in force)", time::timestamp(until_ms))
        }
        Some(State::Early) => {
            " (granted later than the clock now reads, so not in force)".to_owned()
        }
        Some(State::Unreadable) => " (its end cannot be read, so it counts as expired)".to_owned(),
    }
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
    /// The project it applies in; `None` for a file grant, which needs none,
    /// and for one an earlier release wrote.
    project: Option<&'a str>,
    /// `false` for a grant an earlier release wrote without the project it
    /// needs: it applies nowhere until approved again.
    applies: bool,
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
        directories: &overlay.dirs,
        expires: overlay
            .expires
            .iter()
            .map(|(id, w)| (id.as_str(), Ends::of(w, now)))
            .collect(),
        session_grants: grants
            .active(now)
            .map(|g| SessionGrant {
                host: &g.host,
                session_id: &g.session_id,
                what: approvals::describe(&g.action),
                action: &g.action,
                granted_at_ms: g.granted_at_ms,
                expires_at_ms: g.granted_at_ms.saturating_add(GRANT_TTL_MS),
                project: g.project.as_deref(),
                applies: !g.unbound(),
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
    text(&allowed, &overlay, now)
}

fn text(allowed: &Allowed<'_>, overlay: &Overlay, now: i64) -> Result<Code> {
    let mut out = Deferred::default();
    writeln!(out, "Standing rules (~/.moat/policy.d/approved.yaml)")?;
    if allowed.rules.is_empty() && allowed.directories.is_empty() {
        writeln!(out, "  none")?;
    }
    let dirs = allowed.directories.iter().map(|g| {
        let what = format!(
            "read and write in {} (what the policy holds for review stays held)",
            g.dir.join(", ")
        );
        (&g.id, what)
    });
    for (id, what) in allowed
        .rules
        .iter()
        .map(|r| (&r.id, patterns(r)))
        .chain(dirs)
    {
        let ends = ends_text(overlay.expires.get(id.as_str()), now);
        writeln!(out, "  {id:<14} {what}{ends}")?;
        writeln!(out, "  {:<14} remove: openmoat allow --remove {id}", "")?;
    }
    if overlay.ids().any(|id| !overlay.holds(id, now)) {
        writeln!(
            out,
            "  `openmoat allow --prune` removes the ones not in force"
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
        let place = match (grant.applies, grant.project) {
            (false, _) => " (names no project, so it applies nowhere: approve it again)".to_owned(),
            (true, Some(project)) if matches!(grant.action, Action::Shell { .. }) => {
                format!(" in {project}")
            }
            (true, _) => String::new(),
        };
        render::line(
            &mut out,
            &format!(
                "  {} session {}: {}{place} (ends in {})",
                grant.host,
                grant.session_id,
                grant.what,
                time::duration(grant.expires_at_ms.saturating_sub(now))
            ),
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
