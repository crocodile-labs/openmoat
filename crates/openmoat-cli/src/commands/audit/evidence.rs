//! `openmoat audit evidence`: for a time window, what the audit log records per
//! framework control of the compliance map (`compliance.rs`, ADR-051), with
//! the policy, lock and protections in force when the report is made.
//!
//! The events are read with [`Store::export`](openmoat_audit::Store::export),
//! the reader `openmoat audit export` uses, so the evidence covers exactly the
//! events an export of the window would hold and verify.

use std::collections::BTreeSet;
use std::fs;

use anyhow::{Result, bail};
use openmoat_audit::{Event, ExportFilter, ExportedEvent, Store};
use openmoat_core::{DEFAULT_POLICY, Policy};
use openmoat_hosts::Host;
use serde::Serialize;

use crate::cli::{EvidenceArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::Lock;
use crate::protection::{self, Level, Protection};
use crate::{render, time};

mod build;
#[cfg(test)]
mod tests;
mod text;

use build::{Counts, Inputs, STATEMENT, build};

/// Version of the JSON document, its `format` field.
const FORMAT: &str = "openmoat-evidence-v1";

#[derive(Debug, Serialize)]
struct Window {
    since: String,
    until: String,
    host: Option<&'static str>,
}

/// The policy file in force when the report is made.
#[derive(Debug, Default, Serialize)]
struct PolicyState {
    path: String,
    sha256: Option<String>,
    /// Byte for byte the default policy this build ships.
    same_as_shipped_default: bool,
    /// `deny`, `allow` and `review` rule groups, after `openmoat allow` rules and packs.
    rules: Option<[usize; 3]>,
    error: Option<String>,
}

/// The policy lock when the report is made.
#[derive(Debug, Default, Serialize)]
struct LockState {
    present: bool,
    pinned_at: Option<String>,
    /// The lock was last re-pinned at or after the window's start: the policy
    /// and hook files in force during the window may differ from those shown.
    pinned_since_window_start: bool,
    files_pinned: usize,
    drift: Vec<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Evidence {
    format: &'static str,
    statement: &'static str,
    generated_at: String,
    window: Window,
    totals: Counts,
    log: build::Log,
    policy: PolicyState,
    lock: LockState,
    protections: Vec<Protection>,
    controls: Vec<build::ControlEvidence>,
    groups: Vec<build::GroupEvidence>,
    unmapped_rules: Vec<build::UnmappedRule>,
}

pub fn run(args: &EvidenceArgs) -> Result<Code> {
    let now = time::now_ms();
    let since_ms = time::parse_since(&args.since, now)?;
    let until_ms = match &args.until {
        Some(until) => time::parse_since(until, now)?,
        None => now,
    };
    if until_ms <= since_ms {
        bail!("--until must be later than --since");
    }
    let home = Home::locate()?;
    let store = home.open_audit()?;
    let host = args.host.map(Host::id);
    let events = window(&store, since_ms, until_ms, host)?;
    let chain = store.verify_chain()?;
    let in_force = home.load_policy();
    let in_force_ids = in_force.as_ref().ok().map(rule_ids);
    let default_ids = default_rule_ids()?;
    let built = build(
        &events,
        Inputs {
            chain,
            in_force: in_force_ids.as_ref(),
            default_ids: &default_ids,
            samples: usize::from(args.samples),
        },
    );
    let binary = crate::install::hook_binary()?;
    let evidence = Evidence {
        format: FORMAT,
        statement: STATEMENT,
        generated_at: time::rfc3339(now),
        window: Window {
            since: time::rfc3339(since_ms),
            until: time::rfc3339(until_ms),
            host,
        },
        totals: built.totals,
        log: built.log,
        policy: policy_state(&home, in_force.as_ref()),
        lock: lock_state(&home, since_ms),
        protections: protection::report(&home, &binary)?
            .into_iter()
            .filter(|p| p.level != Level::NotFound)
            .collect(),
        controls: built.controls,
        groups: built.groups,
        unmapped_rules: built.unmapped_rules,
    };
    match args.format {
        Format::Json => render::json(&evidence)?,
        Format::Text => text::write(&evidence)?,
    }
    Ok(Code::Ok)
}

/// The chained events from `since_ms` up to, not including, `until_ms`, oldest
/// first: what `openmoat audit export --since` writes, cut at the window's end.
fn window(store: &Store, since_ms: i64, until_ms: i64, host: Option<&str>) -> Result<Vec<Event>> {
    let exported = store.export(&ExportFilter {
        since_ms,
        host,
        session_id: None,
    })?;
    Ok(exported
        .iter()
        .filter(|e| e.ts_ms < until_ms)
        .map(ExportedEvent::to_event)
        .collect::<Result<_, _>>()?)
}

/// Every rule group id of `policy`.
fn rule_ids(policy: &Policy) -> BTreeSet<String> {
    [&policy.deny, &policy.allow, &policy.review, &policy.defer]
        .into_iter()
        .flatten()
        .map(|g| g.id.clone())
        .collect()
}

/// The `deny` and `review` rule ids of the shipped default policy: the ones the
/// compliance map names by policy id.
pub fn default_rule_ids() -> Result<BTreeSet<String>> {
    let policy = Policy::parse(DEFAULT_POLICY)?;
    Ok(policy
        .deny
        .iter()
        .chain(&policy.review)
        .map(|g| g.id.clone())
        .collect())
}

fn policy_state(home: &Home, in_force: Result<&Policy, &anyhow::Error>) -> PolicyState {
    let path = home.policy_path();
    let mut state = PolicyState {
        path: path.display().to_string(),
        ..PolicyState::default()
    };
    match fs::read(&path) {
        Ok(bytes) => {
            state.sha256 = Some(crate::integrity::sha256_hex(&bytes));
            state.same_as_shipped_default = bytes == DEFAULT_POLICY.as_bytes();
        }
        Err(error) => state.error = Some(format!("reading {}: {error}", path.display())),
    }
    match in_force {
        Ok(policy) => {
            let (deny, allow, review) = policy.rule_count();
            state.rules = Some([deny, allow, review]);
        }
        Err(error) => state.error = Some(format!("{error:#}")),
    }
    state
}

fn lock_state(home: &Home, since_ms: i64) -> LockState {
    let path = home.lock_path();
    if !path.exists() {
        return LockState::default();
    }
    match Lock::load(&path) {
        Ok(lock) => LockState {
            present: true,
            pinned_at: Some(time::rfc3339(lock.pinned_at_ms)),
            pinned_since_window_start: lock.pinned_at_ms >= since_ms,
            files_pinned: lock.entries.len(),
            drift: lock.verify().iter().map(ToString::to_string).collect(),
            error: None,
        },
        Err(error) => LockState {
            present: true,
            error: Some(format!("{error:#}")),
            ..LockState::default()
        },
    }
}
